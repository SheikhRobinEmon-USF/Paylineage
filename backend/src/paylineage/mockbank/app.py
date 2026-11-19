"""SIMULATED bank rails. No real money, accounts or networks (CLAUDE.md rule 9).

Separate process on an internal network only the executor joins (I6). Requires
the executor's bearer token. Transfers are idempotent on the permit id.
"""

from __future__ import annotations

import hmac
import secrets
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from paylineage.settings import get_settings


class TransferIn(BaseModel):
    idempotency_key: str = Field(min_length=8, max_length=64)
    amount_minor: int = Field(gt=0, le=9_007_199_254_740_991)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    beneficiary_token: str = Field(pattern=r"^acct_[0-9a-f]{32}$")
    reference: str = Field(max_length=64)


class TransferOut(BaseModel):
    bank_reference: str
    status: str
    simulated: bool = True
    replayed: bool = False


@dataclass
class Ledger:
    transfers: dict[str, TransferOut] = field(default_factory=dict)
    payloads: dict[str, TransferIn] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def transfer(self, t: TransferIn) -> TransferOut:
        with self.lock:
            prior = self.transfers.get(t.idempotency_key)
            if prior is not None:
                if self.payloads[t.idempotency_key] != t:
                    raise HTTPException(409, "idempotency key reused with a different payload")
                return prior.model_copy(update={"replayed": True})
            out = TransferOut(bank_reference="SIM-" + secrets.token_hex(6).upper(), status="settled")
            self.transfers[t.idempotency_key] = out
            self.payloads[t.idempotency_key] = t
            return out

    def count(self) -> int:
        with self.lock:
            return len(self.transfers)


def create_app(token: str | None = None) -> FastAPI:
    configured = get_settings().mockbank_token
    expected = token or (configured.get_secret_value() if configured is not None else None)
    app = FastAPI(title="PayLineage mock bank (SIMULATED)", docs_url=None, redoc_url=None)
    ledger = Ledger()
    app.state.ledger = ledger

    def auth(authorization: str = Header(default="")) -> None:
        if not expected:
            raise HTTPException(503, "mock bank token not configured")
        given = authorization.removeprefix("Bearer ")
        if not hmac.compare_digest(given.encode(), expected.encode()):
            raise HTTPException(401, "unauthorized")

    @app.post("/transfers", dependencies=[Depends(auth)])
    def transfer(t: TransferIn) -> TransferOut:
        return ledger.transfer(t)

    @app.get("/health")
    def health() -> dict[str, object]:
        return {"ok": True, "simulated": True, "at": datetime.now(UTC).isoformat()}

    return app


def run() -> None:
    import uvicorn

    uvicorn.run(create_app(), host="0.0.0.0", port=8200)  # noqa: S104 (container internal network)
