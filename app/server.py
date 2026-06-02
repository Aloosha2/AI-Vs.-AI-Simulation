"""FastAPI toy communication server.

This is intentionally small and partially vulnerable by default. The simulation
agents use it through FastAPI's in-process TestClient, and it can also be run on
localhost for manual class demos.
"""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app import security


app = FastAPI(title="Local AI vs AI Cybersecurity Simulation")

USERS = {
    "alice": "wonderland",
    "bob": "builder",
    "admin": "root-local-demo",
    "guest": "guest",
}

USER_ROLES = {
    "alice": "user",
    "bob": "user",
    "admin": "admin",
    "guest": "guest",
}

TOKENS: dict[str, str] = {}
MESSAGES: list[dict[str, Any]] = []


class LoginRequest(BaseModel):
    username: str
    password: str


class MessageRequest(BaseModel):
    token: str
    recipient: str
    content: str
    visibility: str = "private"


def reset_app_state(clear_log: bool = False) -> None:
    """Reset in-memory app and security state for tests and judge rounds."""

    TOKENS.clear()
    MESSAGES.clear()
    security.reset_security_state(clear_log=clear_log)


def _client_id(request: Request) -> str:
    return request.client.host if request.client else "local-testclient"


def _enforce_rate_limit(request: Request, endpoint: str) -> None:
    client_id = _client_id(request)
    if security.check_rate_limit(client_id, endpoint, time.time()):
        raise HTTPException(
            status_code=429,
            detail=security.public_error(
                f"rate limit exceeded for client {client_id} on {endpoint}",
                "Too many requests.",
            ),
        )


def _username_for_token(token: str) -> str:
    username = TOKENS.get(token)
    if not username:
        raise HTTPException(
            status_code=401,
            detail=security.public_error(
                f"token {token!r} is not present in in-memory TOKENS",
                "Invalid credentials.",
            ),
        )
    return username


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    security.log_event(
        "malformed_request",
        client_id=_client_id(request),
        path=str(request.url.path),
        error_count=len(exc.errors()),
    )
    content = {
        "error": security.public_error(str(exc), "Invalid request."),
    }
    if not security.config.safer_errors_enabled:
        content["details"] = jsonable_encoder(exc.errors())
    return JSONResponse(status_code=422, content=content)


@app.get("/health")
def health(request: Request) -> dict[str, Any]:
    _enforce_rate_limit(request, "/health")
    security.log_event("health_check", client_id=_client_id(request))
    return {
        "status": "ok",
        "defenses": security.config_snapshot(),
        "users": [{"username": username, "role": role} for username, role in USER_ROLES.items()],
        "message_queue_size": len(MESSAGES),
    }


@app.post("/login")
def login(payload: LoginRequest, request: Request) -> dict[str, str]:
    _enforce_rate_limit(request, "/login")
    client_id = _client_id(request)
    security.log_event("login_attempt", username=payload.username, client_id=client_id)

    if security.is_locked(payload.username):
        raise HTTPException(
            status_code=423,
            detail=security.public_error(
                f"account {payload.username!r} locked after repeated failures",
                "Account temporarily locked.",
            ),
        )

    expected_password = USERS.get(payload.username)
    if expected_password is None or expected_password != payload.password:
        security.record_failed_login(payload.username, client_id)
        raise HTTPException(
            status_code=401,
            detail=security.public_error(
                f"login failed for username={payload.username!r}; expected a demo password",
                "Invalid credentials.",
            ),
        )

    security.clear_failed_logins(payload.username)
    token = f"local-{payload.username}-{uuid4().hex}"
    TOKENS[token] = payload.username
    security.log_event("login_success", username=payload.username, client_id=client_id)
    return {"token": token}


@app.post("/send_message")
def send_message(payload: MessageRequest, request: Request) -> dict[str, Any]:
    _enforce_rate_limit(request, "/send_message")
    sender = _username_for_token(payload.token)

    is_valid, reason = security.validate_message_content(payload.content)
    if not is_valid:
        security.log_event(
            "payload_rejected",
            sender=sender,
            recipient=payload.recipient,
            reason=reason,
            size=len(payload.content),
        )
        raise HTTPException(status_code=413, detail=security.public_error(reason, "Payload rejected."))

    message = {
        "id": len(MESSAGES) + 1,
        "sender": sender,
        "recipient": payload.recipient,
        "content": payload.content,
        "size": len(payload.content),
        "visibility": payload.visibility if payload.visibility in {"public", "private"} else "private",
    }
    MESSAGES.append(message)
    security.log_event(
        "message_sent",
        sender=sender,
        recipient=payload.recipient,
        size=len(payload.content),
    )
    return {"accepted": True, "message_id": message["id"]}


@app.get("/messages")
def messages(token: str, request: Request) -> dict[str, Any]:
    _enforce_rate_limit(request, "/messages")
    username = _username_for_token(token)
    visible = [
        message
        for message in MESSAGES
        if (
            message["visibility"] == "public"
            or message["sender"] == username
            or message["recipient"] == username
            or USER_ROLES.get(username) == "admin"
        )
    ]
    security.log_event("messages_read", username=username, count=len(visible))
    return {"messages": visible}


@app.middleware("http")
async def log_probes(request: Request, call_next):
    response = await call_next(request)
    if response.status_code == 404:
        security.log_event(
            "endpoint_probe",
            client_id=_client_id(request),
            path=str(request.url.path),
        )
    return response
