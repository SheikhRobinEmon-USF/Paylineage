"""Executor HTTP process. Reachable only from the API on the data network (I6)."""

from __future__ import annotations

import hmac

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from paylineage.db.base import transaction
from paylineage.domain.clock import SystemClock
from paylineage.domain.context import Ctx, DomainError
from paylineage.executor.service import execute
from paylineage.policy.engine import get_engine
from paylineage.settings import get_settings


class HttpBank:
    def __init__(self, url: str, token: str, client: httpx.Client | None = None) -> None:
        self._url = url.rstrip("/")
        self._token = token
        self._client = client or httpx.Client(timeout=5.0)

    def transfer(
        self,
        *,
        idempotency_key: str,
        amount_minor: int,
        currency: str,
        beneficiary_token: str,
        reference: str,
    ) -> str:
        r = self._client.post(
            f"{self._url}/transfers",
            json={
                "idempotency_key": idempotency_key,
                "amount_minor": amount_minor,
                "currency": currency,
                "beneficiary_token": beneficiary_token,
                "reference": reference,
            },
            headers={"Authorization": f"Bearer {self._token}"},
        )
        r.raise_for_status()
        return str(r.json()["bank_reference"])


class ExecuteIn(BaseModel):
    permit_id: str = Field(min_length=36, max_length=36)
    request_id: str = Field(min_length=8, max_length=64)


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title="PayLineage executor", docs_url=None, redoc_url=None)
    token = s.executor_token.get_secret_value() if s.executor_token else None
    bank_token = s.mockbank_token.get_secret_value() if s.mockbank_token else None

    def auth(authorization: str = Header(default="")) -> None:
        if not token or not hmac.compare_digest(
            authorization.removeprefix("Bearer ").encode(), token.encode()
        ):
            raise HTTPException(401, "unauthorized")

    @app.post("/execute", dependencies=[Depends(auth)])
    def run_execute(body: ExecuteIn) -> dict[str, object]:
        if not bank_token:
            raise HTTPException(503, "executor has no bank credentials")
        bank = HttpBank(s.mockbank_url, bank_token)
        try:
            with transaction() as session:
                out = execute(
                    Ctx(session, SystemClock(), get_engine()), body.permit_id, body.request_id, bank
                )
        except DomainError as exc:
            raise HTTPException(exc.status, {"code": exc.code, "message": exc.message}) from exc
        return {
            "executed": out.executed,
            "decision": out.decision.as_dict(),
            "bank_reference": out.bank_reference,
        }

    return app


def run() -> None:
    import uvicorn

    uvicorn.run(create_app(), host="0.0.0.0", port=8100)  # noqa: S104 (container internal network)
