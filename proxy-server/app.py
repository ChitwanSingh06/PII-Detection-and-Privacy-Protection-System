# import asyncio
import os
from sqlalchemy import text
import uvicorn
from fastapi import FastAPI, Request, Response
# from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
import httpx
import grpc
import common.anonymizer.anonymizer_pb2 as an_pb2
import common.anonymizer.anonymizer_pb2_grpc as an_pb2_grpc
from postgres import PostgresModel
from google.protobuf.json_format import MessageToDict

import re


class S3Object(BaseModel):
    bucketName: str = Field(..., description="Name of the S3 bucket")
    objectKey: str = Field(..., description="Key of the S3 object")
    objectData: bytes = Field(..., description="Data of the S3 object")
    policy_map: list = Field(..., description="List of policies for anonymization")

# boto3.client()
AN_SVC_URL = "http://"+os.environ.get("ANNON_POD_URL", "cxo-s3-cluster52.lab.nimblestorage.com:80")  
S3_ENDPOINT = "http://"+os.environ.get("S3_ENDPOINT", "cxo-s3-cluster52.lab.nimblestorage.com:80")
POSTGRES_URL = os.environ.get("POSTGRES_URL", "localhost")
POSTGRES_USER = os.environ.get("POSTGRES_USER", "user")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "password")
POSTGRES_DB = os.environ.get("POSTGRES_DB", "pii_db")

# os.environ['no_proxy'] = f""
app = FastAPI()
engine = PostgresModel.create_engine(POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_URL, POSTGRES_DB)
# analyzer = AnalyzerEngine()
# anonymizer = AnonymizerEngine()
# POD_A_URL = "http://cxo-s3-cluster52.lab.nimblestorage.com:80"  # All except get-object
# POD_B_URL = "http://cxo-s3-cluster52.lab.nimblestorage.com:80"  # get-object
temp = {}

async def s3_forward(request, target_url: str) -> Response:
    async with httpx.AsyncClient() as client:
        # Prepare request details
        # method = request.method
        url = f"{target_url}{request.url.path}"
        headers = dict(request.headers)
        # print()
        # Preserve query string
        if request.url.query:
            url += "?" + request.url.query
        print("GET request to Pod B:", url)
        # body = await request.body()
        print(headers)
        # Forward request
        resp = await client.request(request.method, url, headers=request.headers, content=await request.body())
        
        print(resp.headers)
        # Stream response back to client
        # async for chunk in resp.aiter_bytes(1000):
        #     yield chunk
        # print(resp.headers)
        return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))

async def post_process_get_response(path: str, request: Request, response: Response) -> Response:
    grpc_response, error = None, None
    accessKey = request.headers['authorization'].split(" ")[1].split("=")[1].split("/")[0]
    query = text("""SELECT p.policy FROM users u JOIN policies p ON u.policy_name = p.policy_name WHERE u.user_name = :access_key""")
    async with engine.connect() as connection:
        query_result = await connection.execute(query, {"access_key": accessKey})
        rows = await query_result.fetchall()
        if len(rows) == 0:
            print(f"No policy found for user {accessKey}, skipping anonymization")
            return response

        policy_map = [row.policy for row in rows]
        print(f"Policy found for user {accessKey}: {policy_map}, proceeding with anonymization")
        # print(policy_map)       

        async with grpc.aio.insecure_channel(f"{AN_SVC_URL}") as ch:
            stub = an_pb2_grpc.PIIAnonymizerServiceStub(ch)
            # s3object = S3Object()
            try:
                grpc_response = await stub.AnonymizeObject(an_pb2.AnonymizeObjectRequest(bucketName=path.split('/')[0], objectKey='/'.join(path.split('/')[1:]), objectData=response.body, policy_map=policy_map))
                grpc_response = MessageToDict(grpc_response, preserving_proto_field_name=True)
            except grpc.aio.AioRpcError as e:
                print(f"received grpc.aio.AioRpcError: {e}")
                error = {"code": e.code().name, "details": e.details()}
                print(f"gRPC error details: {error}")
                grpc_response = None
        if grpc_response:
            print("Anonymization successful, returning modified object")
            response.headers["objectLength"] = str(grpc_response["objectLength"])
            return Response(content=grpc_response["updatedObjectData"], status_code=response.status_code, headers=dict(response.headers))
        return response

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy_handler(request: Request, path: str, tagging:str|None=None):
    # print(type(tagging))
    if request.method == "GET" and re.match(r"^[^/]+/.+", path) and tagging is None:
        resp = await s3_forward(request, S3_ENDPOINT)
        if resp.status_code == 200:
            # pass
            return await post_process_get_response(path, request, resp)
        return resp
    return await s3_forward(request, S3_ENDPOINT)

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8080, reload=True)