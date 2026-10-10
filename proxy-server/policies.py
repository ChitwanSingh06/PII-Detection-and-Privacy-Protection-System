"""Policy management API (admin only).

Works directly on the EXISTING SQLite tables; no new schema:
  policies(policy_name, policy)  -> one row per rule, `policy` is the rule JSON
                                    {"entity_type", "operator_name", "operator_params"}
  users(user_name, policy_name, ...) -> the policy assigned to a user ('' = no policy)

The GET path and the LLM endpoint already read these tables on every request, so a change
made here applies to the very next request (no cache to invalidate).
"""
import json
import re

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import text

from auth import AuthUser, get_current_user, require_role
from config import SQLITE_PATH
from sqlite_db import SqliteModel

router = APIRouter(tags=["policies"])

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ENTITY_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")  # Presidio entity names, e.g. EMAIL_ADDRESS


def _admin(user: AuthUser = Depends(get_current_user)) -> AuthUser:
    return require_role(user, "admin")


def _engine():
    return SqliteModel.create_engine(SQLITE_PATH)  # same shared engine app.py uses


# --- Rule validation: only what the anonymizer/Presidio can actually apply -----
class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: str
    operator_name: str
    operator_params: dict = Field(default_factory=dict)

    @field_validator("entity_type")
    @classmethod
    def _entity(cls, v: str) -> str:
        if not _ENTITY_RE.match(v):
            raise ValueError("entity_type must look like EMAIL_ADDRESS (A-Z, 0-9, _)")
        return v

    @model_validator(mode="after")
    def _params(self):
        op, params = self.operator_name, dict(self.operator_params)

        def only(*allowed):
            extra = set(params) - set(allowed)
            if extra:
                raise ValueError(f"unknown parameter(s) for '{op}': {sorted(extra)}")

        if op == "redact":
            only()
        elif op == "replace":
            only("new_value")
            if "new_value" in params and (not isinstance(params["new_value"], str) or len(params["new_value"]) > 200):
                raise ValueError("new_value must be a string of at most 200 characters")
        elif op == "hash":
            only("hash_type")
            if "hash_type" in params and params["hash_type"] not in ("sha256", "sha512"):
                raise ValueError("hash_type must be sha256 or sha512")
        elif op == "mask":
            only("masking_char", "chars_to_mask", "from_end")
            n = params.get("chars_to_mask")
            if isinstance(n, bool) or not isinstance(n, int) or not 0 <= n <= 1000:
                raise ValueError("mask requires chars_to_mask as an integer between 0 and 1000")
            char = params.get("masking_char", "*")
            if not isinstance(char, str) or len(char) != 1:
                raise ValueError("masking_char must be a single character")
            end = params.get("from_end", False)
            if not isinstance(end, bool):
                raise ValueError("from_end must be true or false")
            # Presidio's mask needs all three, so always store all three (as init_db seeds them).
            params = {"masking_char": char, "chars_to_mask": n, "from_end": end}
        else:
            raise ValueError("operator_name must be one of: mask, redact, replace, hash")
        self.operator_params = params
        return self


def _validate_rules(rules: list[Rule]) -> list[Rule]:
    if not rules:
        raise ValueError("a policy needs at least one rule")
    types = [r.entity_type for r in rules]
    dupes = sorted({t for t in types if types.count(t) > 1})
    if dupes:  # the anonymizer only applies one rule per entity type
        raise ValueError(f"only one rule per entity_type is allowed (duplicated: {dupes})")
    return rules


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rules: list[Rule] = Field(..., max_length=50)

    @field_validator("rules")
    @classmethod
    def _rules_ok(cls, v: list[Rule]) -> list[Rule]:
        return _validate_rules(v)


class PolicyCreate(PolicyUpdate):
    policy_name: str

    @field_validator("policy_name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not _NAME_RE.match(v):
            raise ValueError("policy_name must be 1-64 characters: letters, digits, '_', '.', '-'")
        return v


class Assignment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_name: str | None = None  # null / "" removes the user's policy


# --- DB helpers ----------------------------------------------------------------
def _rule_json(rule: Rule) -> str:
    return json.dumps(rule.model_dump())  # same shape init_db stores


async def _rules_of(conn, name: str) -> list[dict]:
    rows = (await conn.execute(
        text("SELECT policy FROM policies WHERE policy_name = :n ORDER BY rowid"), {"n": name}
    )).fetchall()
    return [json.loads(r.policy) if isinstance(r.policy, str) else r.policy for r in rows]


async def _users_of(conn, name: str) -> list[str]:
    rows = (await conn.execute(
        text("SELECT user_name FROM users WHERE policy_name = :n ORDER BY user_name"), {"n": name}
    )).fetchall()
    return [r.user_name for r in rows]


async def _describe(conn, name: str) -> dict:
    return {"policy_name": name, "rules": await _rules_of(conn, name), "assigned_users": await _users_of(conn, name)}


async def _insert_rules(conn, name: str, rules: list[Rule]) -> None:
    for rule in rules:
        await conn.execute(
            text("INSERT INTO policies (policy_name, policy) VALUES (:n, :p)"),
            {"n": name, "p": _rule_json(rule)},
        )


def _not_found(name: str) -> HTTPException:
    return HTTPException(status_code=404, detail=f"Policy '{name}' not found")


# --- Policy CRUD ---------------------------------------------------------------
@router.get("/api/policies")
async def list_policies(_: AuthUser = Depends(_admin)):
    async with _engine().connect() as conn:
        names = [r.policy_name for r in (await conn.execute(
            text("SELECT DISTINCT policy_name FROM policies ORDER BY policy_name"))).fetchall()]
        return [await _describe(conn, n) for n in names]


@router.get("/api/policies/{policy_name}")
async def get_policy(policy_name: str, _: AuthUser = Depends(_admin)):
    async with _engine().connect() as conn:
        result = await _describe(conn, policy_name)
    if not result["rules"]:
        raise _not_found(policy_name)
    return result


@router.post("/api/policies", status_code=201)
async def create_policy(body: PolicyCreate, _: AuthUser = Depends(_admin)):
    async with _engine().begin() as conn:
        if await _rules_of(conn, body.policy_name):
            raise HTTPException(status_code=409, detail=f"Policy '{body.policy_name}' already exists")
        await _insert_rules(conn, body.policy_name, body.rules)
    async with _engine().connect() as conn:
        return await _describe(conn, body.policy_name)


@router.put("/api/policies/{policy_name}")
async def update_policy(policy_name: str, body: PolicyUpdate, _: AuthUser = Depends(_admin)):
    """Replace ALL rules of the policy. Users assigned to it keep it and see the new rules at once."""
    async with _engine().begin() as conn:
        if not await _rules_of(conn, policy_name):
            raise _not_found(policy_name)
        await conn.execute(text("DELETE FROM policies WHERE policy_name = :n"), {"n": policy_name})
        await _insert_rules(conn, policy_name, body.rules)
    async with _engine().connect() as conn:
        return await _describe(conn, policy_name)


@router.delete("/api/policies/{policy_name}", status_code=204)
async def delete_policy(policy_name: str, _: AuthUser = Depends(_admin)):
    async with _engine().begin() as conn:
        if not await _rules_of(conn, policy_name):
            raise _not_found(policy_name)
        users = await _users_of(conn, policy_name)
        if users:
            raise HTTPException(
                status_code=409,
                detail=f"Policy '{policy_name}' is assigned to {', '.join(users)}. Unassign or reassign them first.",
            )
        await conn.execute(text("DELETE FROM policies WHERE policy_name = :n"), {"n": policy_name})
    return Response(status_code=204)


# --- Assignment ----------------------------------------------------------------
@router.get("/api/users")
async def list_users(_: AuthUser = Depends(_admin)):
    """Users with their role and assigned policy ('' = none). Password hashes are never returned."""
    async with _engine().connect() as conn:
        rows = (await conn.execute(
            text("SELECT user_name, role, policy_name FROM users ORDER BY user_name, rowid"))).fetchall()
    return [{"user_name": r.user_name, "role": r.role, "policy_name": r.policy_name or None} for r in rows]


@router.put("/api/users/{user_name}/policy")
async def assign_policy(user_name: str, body: Assignment, _: AuthUser = Depends(_admin)):
    """Assign (or change) the policy used for this user's GETs and LLM prompts."""
    new_policy = body.policy_name or ""
    async with _engine().begin() as conn:
        ids = [r.rid for r in (await conn.execute(
            text("SELECT rowid AS rid FROM users WHERE user_name = :u ORDER BY rowid"), {"u": user_name})).fetchall()]
        if not ids:
            raise HTTPException(status_code=404, detail=f"User '{user_name}' not found")
        if new_policy and not await _rules_of(conn, new_policy):
            raise _not_found(new_policy)
        # users' primary key is (user_name, policy_name): keep one row per user, then update it.
        await conn.execute(
            text("DELETE FROM users WHERE user_name = :u AND rowid != :keep"), {"u": user_name, "keep": ids[0]})
        await conn.execute(
            text("UPDATE users SET policy_name = :p WHERE rowid = :keep"), {"p": new_policy, "keep": ids[0]})
    return {"user_name": user_name, "policy_name": new_policy or None}
