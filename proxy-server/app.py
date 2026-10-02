import asyncio
import json
import os
import re
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from google.protobuf.struct_pb2 import Struct
from pydantic import BaseModel, Field
from sqlalchemy import text
import grpc
import common.anonymizer.anonymizer_pb2 as an_pb2
import common.anonymizer.anonymizer_pb2_grpc as an_pb2_grpc

ROOT = Path(__file__).resolve().parents[1]
PROXY_DIR = Path(__file__).resolve().parent
CONSUMER_DIR = ROOT / "consumer_analyzer" / "consumer"
PII_ANALYSER_DIR = ROOT / "consumer_analyzer" / "pii_analyser"
COMMON_DIR = ROOT / "common"
for path in (str(ROOT), str(PROXY_DIR), str(CONSUMER_DIR), str(PII_ANALYSER_DIR), str(COMMON_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from config import AN_SVC_URL, DEFAULT_USER, SQLITE_PATH, STORAGE_ROOT  # noqa: E402
from sqlite_db import SqliteModel  # noqa: E402
from kafka_consumer import LocalUploadTrigger  # noqa: E402


class S3Object(BaseModel):
    bucketName: str = Field(..., description="Name of the bucket")
    objectKey: str = Field(..., description="Key of the object")
    objectData: bytes = Field(..., description="Data of the object")
    policy_map: list = Field(..., description="List of policies for anonymization")


app = FastAPI()

# --- Frontend UI -------------------------------------------------------------
# Registered BEFORE the catch-all proxy route below so /ui/ is never treated as
# an S3 bucket path.
UI_DIR = ROOT / "ui"


@app.get("/ui", include_in_schema=False)
async def ui_redirect():
    return RedirectResponse(url="/ui/")


app.mount("/ui", StaticFiles(directory=str(UI_DIR), html=True), name="ui")
# -----------------------------------------------------------------------------
engine = SqliteModel.create_engine(SQLITE_PATH)
storage_root = Path(os.environ.get("STORAGE_ROOT", STORAGE_ROOT))
storage_root.mkdir(parents=True, exist_ok=True)
anonymizer_url = os.environ.get("AN_SVC_URL", AN_SVC_URL)
_upload_trigger: LocalUploadTrigger | None = None


def get_upload_trigger() -> LocalUploadTrigger:
    global _upload_trigger
    if _upload_trigger is None:
        _upload_trigger = LocalUploadTrigger()
    return _upload_trigger


def _safe_storage_path(bucket: str, key: str = "") -> Path:
    dest = (storage_root / bucket / key).resolve() if key else (storage_root / bucket).resolve()
    if not str(dest).startswith(str(storage_root.resolve())):
        raise ValueError("Invalid object path")
    return dest


def _split_bucket_key(path: str) -> tuple[str, str]:
    parts = path.split("/")
    return parts[0], "/".join(parts[1:])


def _requesting_user(request: Request) -> str:
    header_user = request.headers.get("x-user")
    if header_user:
        return header_user
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("AWS") or "Credential=" in authorization:
        try:
            return authorization.split(" ")[1].split("=")[1].split("/")[0]
        except (IndexError, ValueError):
            pass
    return os.environ.get("DEFAULT_USER", DEFAULT_USER)


def _policy_messages(policy_rows: list) -> list:
    messages = []
    for row in policy_rows:
        policy = row if isinstance(row, dict) else json.loads(row)
        params = Struct()
        operator_params = policy.get("operator_params") or {}
        if operator_params:
            params.update(operator_params)
        messages.append(
            an_pb2.Policy(
                entityType=policy["entity_type"],
                operatorName=policy["operator_name"],
                operatorParams=params,
            )
        )
    return messages


async def read_local_object(path: str) -> Response:
    bucket, key = _split_bucket_key(path)
    if not key:
        bucket_dir = _safe_storage_path(bucket)
        if not bucket_dir.exists():
            return Response(content=b"Bucket not found", status_code=404)
        objects = sorted(
            str(p.relative_to(bucket_dir))
            for p in bucket_dir.rglob("*")
            if p.is_file()
        )
        return Response(content=json.dumps(objects).encode("utf-8"), media_type="application/json")

    file_path = _safe_storage_path(bucket, key)
    if not file_path.is_file():
        return Response(content=b"Object not found", status_code=404)
    return Response(content=file_path.read_bytes(), status_code=200)


async def write_local_object(path: str, body: bytes) -> Response:
    bucket, key = _split_bucket_key(path)
    if not key:
        _safe_storage_path(bucket).mkdir(parents=True, exist_ok=True)
        return Response(status_code=200)
    file_path = _safe_storage_path(bucket, key)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(body)
    return Response(status_code=200)


async def delete_local_object(path: str) -> Response:
    bucket, key = _split_bucket_key(path)
    target = _safe_storage_path(bucket, key) if key else _safe_storage_path(bucket)
    if not target.exists():
        return Response(content=b"Not found", status_code=404)
    if target.is_file():
        target.unlink()
        async with engine.connect() as connection:
            await connection.execute(
                text("DELETE FROM pii_objects WHERE bucket_name=:bucket AND object_key=:key"),
                {"bucket": bucket, "key": key},
            )
            await connection.commit()
    return Response(status_code=204)


async def run_pii_analysis(bucket: str, key: str) -> None:
    await asyncio.to_thread(get_upload_trigger().on_put, bucket, key)


async def post_process_get_response(path: str, request: Request, response: Response) -> Response:
    access_key = _requesting_user(request)
    query = text(
        """
        SELECT p.policy FROM users u
        JOIN policies p ON u.policy_name = p.policy_name
        WHERE u.user_name = :access_key
        """
    )
    async with engine.connect() as connection:
        query_result = await connection.execute(query, {"access_key": access_key})
        rows = query_result.fetchall()
        if len(rows) == 0:
            print(f"No policy found for user {access_key}, skipping anonymization")
            return response

        policy_map = []
        for row in rows:
            policy = row.policy
            policy_map.append(json.loads(policy) if isinstance(policy, str) else policy)
        print(f"Policy found for user {access_key}: {policy_map}, proceeding with anonymization")

        bucket, key = _split_bucket_key(path)
        async with grpc.aio.insecure_channel(anonymizer_url) as ch:
            stub = an_pb2_grpc.PIIAnonymizerServiceStub(ch)
            try:
                grpc_response = await stub.AnonymizeObject(
                    an_pb2.AnonymizeObjectRequest(
                        bucketName=bucket,
                        objectKey=key,
                        objectData=response.body,
                        policy_map=_policy_messages(policy_map),
                    )
                )
                updated = grpc_response.updatedObjectData

                headers = dict(response.headers)

                # Remove the old Content-Length because the anonymized
                # response has a different size.
                headers.pop("content-length", None)
                headers.pop("Content-Length", None)

                headers["objectLength"] = str(grpc_response.objectLength)

                return Response(
                    content=updated,
                    status_code=response.status_code,
                    headers=headers
                )
            except grpc.aio.AioRpcError as e:
                error = {"code": e.code().name, "details": e.details()}
                print(f"gRPC error details: {error}")
                return response


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy_handler(request: Request, path: str, tagging: str | None = None):
    if request.method in ("PUT", "POST") and path:
        body = await request.body()
        resp = await write_local_object(path, body)
        bucket, key = _split_bucket_key(path)
        if key:
            await run_pii_analysis(bucket, key)
        return resp

    if request.method == "DELETE" and path:
        return await delete_local_object(path)

    if request.method == "GET" and re.match(r"^[^/]+/.+", path) and tagging is None:
        resp = await read_local_object(path)
        if resp.status_code == 200:
            return await post_process_get_response(path, request, resp)
        return resp

    if request.method == "GET":
        return await read_local_object(path)

    if request.method == "HEAD":
        bucket, key = _split_bucket_key(path)
        target = _safe_storage_path(bucket, key) if key else _safe_storage_path(bucket)
        return Response(status_code=200 if target.exists() else 404)

    return Response(status_code=405)


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8080, reload=False)
