"""PayLineage API. Agents sign requests (RFC 9421); people use passkey sessions.

The browser never sends trust levels, digests or decisions; every request is
re-derived from the store (rule 4). The API process holds no bank credentials;
execution goes through the executor process over its private network (I6).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any, Literal, Protocol

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from paylineage.agents.signing import SignatureError, verify_request
from paylineage.api import views
from paylineage.api.deps import (
    LIMITER,
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    Me,
    check_origin,
    current_user,
    get_clock,
    get_ctx,
    require_role,
    serializer,
    session_user_id,
)
from paylineage.approvals import service as approvals
from paylineage.approvals import webauthn
from paylineage.audit.chain import ChainProblem, load_events, verify_events
from paylineage.audit.checkpoint import Checkpoint, CheckpointStore, checkpoint_now, load_or_create_key
from paylineage.audit.checkpoint import verify as checkpoint_verify
from paylineage.canonical import digest as canonical_digest
from paylineage.db.models import (
    ExtractedField,
    IdempotencyKey,
    Invoice,
    Mandate,
    OnboardingRequest,
    Payment,
    Permit,
    Supplier,
    User,
    WebAuthnChallenge,
)
from paylineage.domain.context import Actor, Ctx, DomainError
from paylineage.domain.enums import OldAccountOutcome
from paylineage.explain import explain
from paylineage.extraction.extractors import DeterministicExtractor, Extractor, OllamaExtractor
from paylineage.ingestion.parse import IngestionError
from paylineage.ingestion.pipeline import ingest_email
from paylineage.onboarding import service as onb
from paylineage.payments import service as payments
from paylineage.permits.service import issue_permit
from paylineage.policy.engine import get_engine
from paylineage.settings import get_settings

log = logging.getLogger("paylineage.api")
_KEYID_RE = re.compile(r'keyid="([A-Za-z0-9._:-]{1,128})"')


# ---------------- executor client (I6) ----------------


class ExecutorClient(Protocol):
    def execute(self, permit_id: str, request_id: str) -> dict[str, Any]: ...


class HttpExecutorClient:
    def __init__(self, url: str, token: str | None) -> None:
        self._url, self._token = url.rstrip("/"), token

    def execute(self, permit_id: str, request_id: str) -> dict[str, Any]:
        if not self._token:
            raise HTTPException(
                503, {"code": "EXECUTOR_UNAVAILABLE", "message": "executor token not configured"}
            )
        try:
            r = httpx.post(
                f"{self._url}/execute",
                json={"permit_id": permit_id, "request_id": request_id},
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=10.0,
            )
        except httpx.HTTPError as exc:
            raise HTTPException(503, {"code": "EXECUTOR_UNAVAILABLE", "message": type(exc).__name__}) from exc
        if r.status_code >= 400:
            raise HTTPException(r.status_code, r.json().get("detail", {"code": "EXECUTION_REFUSED"}))
        return dict(r.json())


# ---------------- request models ----------------


class Strict(BaseModel):
    """Unknown fields are an error: a client cannot smuggle in trust levels or digests (I9)."""

    model_config = ConfigDict(extra="forbid")


class DevLogin(Strict):
    handle: str = Field(pattern=r"^[a-z0-9]{2,12}$")


class CredentialIn(Strict):
    challenge_id: str = Field(min_length=36, max_length=36)
    credential: dict[str, Any]


class ProposalIn(Strict):
    invoice_id: str = Field(min_length=36, max_length=36)
    supplier_id: str | None = Field(default=None, max_length=36)
    amount_minor: int = Field(gt=0, le=9_007_199_254_740_991)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    beneficiary_account: str = Field(min_length=4, max_length=40)
    operation: Literal[
        "propose_payment",
        "change_bank_details",
        "approve",
        "execute",
        "edit_mandate",
        "create_supplier",
        "verify_supplier",
    ] = "propose_payment"
    tool_descriptions: list[str] = Field(default_factory=list, max_length=10)
    explanation: str = Field(default="", max_length=2000)


class ClearIn(Strict):
    code: str = Field(pattern=r"^[A-Z_]{3,40}$")
    note: str = Field(min_length=3, max_length=1000)


class ReasonIn(Strict):
    reason: str = Field(min_length=3, max_length=500)


class EditIn(Strict):
    amount_minor: int | None = Field(default=None, gt=0, le=9_007_199_254_740_991)
    beneficiary_account: str | None = Field(default=None, min_length=4, max_length=40)


class NewSupplierIn(Strict):
    legal_name: str = Field(min_length=3, max_length=200)
    domains: list[str] = Field(default_factory=list, max_length=5)
    registry_id: str | None = Field(default=None, max_length=64)
    contact_phone: str | None = Field(default=None, max_length=40)
    bank_account: str = Field(min_length=6, max_length=40)
    bank_name: str = Field(min_length=2, max_length=120)


class BankChangeIn(Strict):
    new_account: str = Field(min_length=6, max_length=40)
    bank_name: str = Field(min_length=2, max_length=120)
    channel: Literal["email", "invoice", "phone_inbound", "portal", "user_entered"] = "email"
    old_account_outcome: OldAccountOutcome = OldAccountOutcome.STILL_VALID


class AssignIn(Strict):
    verifier_id: str = Field(min_length=36, max_length=36)


class VerifyIn(Strict):
    method: Literal["callback_on_file", "simulated_validation_service"]
    callback_confirmed: bool = False
    note: str = Field(default="", max_length=500)


class MandateIn(Strict):
    per_proposal_ceiling_minor: int = Field(ge=0, le=9_007_199_254_740_991)
    daily_ceiling_minor: int = Field(ge=0, le=9_007_199_254_740_991)
    supplier_scope: list[str] = Field(min_length=1, max_length=200)
    second_approver_above_minor: int = Field(ge=0, le=9_007_199_254_740_991)
    expires_in_days: int = Field(ge=1, le=365)


# ---------------- helpers ----------------


def _fail(exc: DomainError) -> HTTPException:
    return HTTPException(exc.status, {"code": exc.code, "message": exc.message, "detail": exc.detail})


def _idempotent(ctx: Ctx, scope: str, key: str | None, body: Any) -> dict[str, Any] | None:
    if not key:
        return None
    row = ctx.session.get(IdempotencyKey, (scope, key))
    if row is None:
        return None
    if row.request_digest != canonical_digest(json.loads(json.dumps(body, default=str))):
        raise HTTPException(409, {"code": "IDEMPOTENCY_KEY_REUSED", "message": "same key, different request"})
    return row.response


def _remember(ctx: Ctx, scope: str, key: str | None, body: Any, response: dict[str, Any]) -> dict[str, Any]:
    if key:
        ctx.session.add(
            IdempotencyKey(
                scope=scope,
                key=key[:128],
                request_digest=canonical_digest(json.loads(json.dumps(body, default=str))),
                response=json.loads(json.dumps(response, default=str)),
                created_at=ctx.now(),
            )
        )
    return response


def _payment(ctx: Ctx, pid: str) -> Payment:
    p = ctx.session.get(Payment, pid)
    if p is None:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": "payment not found"})
    return p


def _extractor() -> Extractor:
    s = get_settings()
    if s.extractor == "ollama":
        return OllamaExtractor(s.ollama_url, s.ollama_model)
    return DeterministicExtractor()


# ---------------- app ----------------


def _checkpoint_key() -> Ed25519PrivateKey | None:
    s = get_settings()
    if s.audit_checkpoint_key_path is None:
        return None
    try:
        return load_or_create_key(s.audit_checkpoint_key_path, allow_create=s.paylineage_env != "prod")
    except (OSError, ValueError):
        log.exception("checkpoint key unavailable")
        return None


def _write_checkpoint() -> Checkpoint | None:
    """Sign the committed audit head into the external store (I11). Safe to call any time."""
    key = _checkpoint_key()
    if key is None:
        return None
    with _ctx() as ctx:
        return checkpoint_now(
            ctx.session, key, CheckpointStore(get_settings().audit_checkpoint_dir), ctx.now()
        )


def _with_checkpoints(ctx: Ctx, problems: list[ChainProblem]) -> tuple[list[ChainProblem], int, str]:
    """Add checkpoint checks. A configured key that cannot be read is a problem, never a pass."""
    s = get_settings()
    if s.audit_checkpoint_key_path is None:
        return problems, 0, "No checkpoint key configured: chain verified, checkpoints not."
    key = _checkpoint_key()
    if key is None:
        missing = ChainProblem(0, "checkpoint_key_unavailable", "checkpoint key configured but unreadable")
        return [*problems, missing], 0, "Checkpoint key unreadable: checkpoints could not be verified."
    store = CheckpointStore(s.audit_checkpoint_dir)
    n = len(store.all())
    return (
        list(checkpoint_verify(ctx.session, key.public_key(), store)),
        n,
        f"Verified against {n} Ed25519 checkpoints held outside the database.",
    )


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    async def loop() -> None:
        while True:
            await asyncio.sleep(CHECKPOINT_EVERY_S)
            try:
                await run_in_threadpool(_write_checkpoint)
            except Exception:
                log.exception("audit checkpoint failed")

    task = asyncio.create_task(loop()) if get_settings().audit_checkpoint_key_path else None
    try:
        yield
    finally:
        if task is not None:
            task.cancel()


CHECKPOINT_EVERY_S = 60


def create_app(executor: ExecutorClient | None = None) -> FastAPI:
    s = get_settings()
    app = FastAPI(
        lifespan=_lifespan,
        title="PayLineage API",
        version="1.0.0",
        docs_url="/v1/docs" if s.paylineage_env == "dev" else None,
        openapi_url="/v1/openapi.json",
    )
    app.state.executor = executor or HttpExecutorClient(
        s.executor_url, s.executor_token.get_secret_value() if s.executor_token else None
    )

    @app.exception_handler(DomainError)
    def domain_error(_r: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse(
            {"detail": {"code": exc.code, "message": exc.message, "detail": exc.detail}}, exc.status
        )

    @app.middleware("http")
    async def headers_and_limits(request: Request, call_next: Any) -> Response:
        try:
            check_origin(request)
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, exc.status_code)
        # Bucket by client address plus the claimed agent key id. A client can vary
        # headers and cookies at will, so they never form the bucket on their own.
        host = request.client.host if request.client else "anon"
        m = _KEYID_RE.search(request.headers.get("signature-input", ""))
        key = f"{host}|{m.group(1) if m else 'human'}"
        if request.method != "GET" and not LIMITER.allow(key):
            return JSONResponse({"detail": {"code": "RATE_LIMITED", "message": "slow down"}}, 429)
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-PayLineage-Simulation"] = "simulated rails and verification"
        return response

    r = APIRouter(prefix="/v1")

    # ---- health and policy ----

    @r.get("/health")
    def health() -> dict[str, Any]:
        e = get_engine()
        return {
            "ok": e.runtime != "unavailable",
            "policy_runtime": e.runtime,
            "policy_sha256": e.sha256,
            "simulation": True,
        }

    @r.get("/policy")
    def policy_info() -> dict[str, Any]:
        e = get_engine()
        reg = json.loads((s.policy_dir / "schema" / "reason_codes.v1.json").read_text())
        return {
            "runtime": e.runtime,
            "sha256": e.sha256,
            "reason_codes": reg["codes"],
            "fallback_active": e.runtime == "opa-server",
        }

    @r.get("/policy/policy.wasm")
    def policy_wasm() -> Response:
        """The exact bytes the backend evaluates. The browser checks the SHA-256 before use (rule 10)."""
        data = s.policy_wasm_path.read_bytes()
        return Response(
            data, media_type="application/wasm", headers={"X-Policy-SHA256": hashlib.sha256(data).hexdigest()}
        )

    # ---- sessions ----

    def _set_session(resp: Response, uid: str) -> None:
        resp.set_cookie(
            SESSION_COOKIE,
            serializer().dumps({"uid": uid, "n": secrets.token_hex(4)}),
            max_age=SESSION_MAX_AGE,
            httponly=True,
            samesite="strict",
            secure=s.paylineage_env != "dev",
            path="/",
        )

    @r.post("/auth/dev-login")
    def dev_login(body: DevLogin, response: Response, ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
        """Persona switch for local development only. Approvals still need the persona's passkey."""
        if s.paylineage_env != "dev":
            raise HTTPException(404)
        u = ctx.session.execute(
            select(User).where(User.email == f"{body.handle}@example.test")
        ).scalar_one_or_none()
        if u is None:
            raise HTTPException(404, {"code": "NOT_FOUND", "message": "no such persona"})
        _set_session(response, u.id)
        return {"id": u.id, "name": u.display_name, "roles": u.roles, "simulated_sign_in": True}

    @r.get("/auth/personas")
    def personas(ctx: Ctx = Depends(get_ctx)) -> list[dict[str, Any]]:
        if s.paylineage_env != "dev":
            raise HTTPException(404)
        return [
            {"handle": u.email.split("@")[0], "name": u.display_name, "roles": u.roles}
            for u in ctx.session.execute(select(User).order_by(User.email)).scalars()
        ]

    @r.post("/auth/logout")
    def logout(response: Response) -> dict[str, bool]:
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"ok": True}

    @r.get("/me")
    def me(m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
        from paylineage.db.models import WebAuthnCredential

        n = len(
            ctx.session.execute(
                select(WebAuthnCredential.id).where(
                    WebAuthnCredential.user_id == m.user.id, WebAuthnCredential.revoked_at.is_(None)
                )
            ).all()
        )
        return {"id": m.user.id, "name": m.user.display_name, "roles": m.user.roles, "passkeys": n}

    @r.post("/auth/passkey/register/begin")
    def reg_begin(m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
        issued = webauthn.begin_registration(ctx, m.user)
        return {"challenge_id": issued.challenge_id, "options": json.loads(issued.options_json)}

    @r.post("/auth/passkey/register/finish")
    def reg_finish(
        body: CredentialIn, m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)
    ) -> dict[str, Any]:
        try:
            cred = webauthn.finish_registration(ctx, body.challenge_id, body.credential)
        except DomainError as exc:
            raise _fail(exc) from exc
        if cred.user_id != m.user.id:
            raise HTTPException(403, {"code": "WEBAUTHN_INVALID", "message": "challenge for another user"})
        return {"ok": True, "credential_id": cred.id[:16]}

    @r.post("/auth/passkey/login/begin")
    def login_begin(ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
        issued = webauthn.begin_assertion(
            ctx, purpose="login", challenge=secrets.token_bytes(32), user_id=None, nonce=secrets.token_hex(8)
        )
        return {"challenge_id": issued.challenge_id, "options": json.loads(issued.options_json)}

    @r.post("/auth/passkey/login/finish")
    def login_finish(body: CredentialIn, response: Response) -> dict[str, Any]:
        failure: DomainError | None = None
        uid = ""
        out: dict[str, Any] = {}
        with _ctx() as ctx:
            try:
                v = webauthn.finish_assertion(ctx, body.challenge_id, "login", body.credential)
                uid = v.user.id
                out = {"id": v.user.id, "name": v.user.display_name, "roles": v.user.roles}
            except DomainError as exc:
                failure = exc  # a failed assertion still burns its challenge (commit below)
        if failure is not None:
            raise _fail(failure)
        _set_session(response, uid)
        return out

    @r.get("/session")
    def session_probe(request: Request, ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
        """Signed in user or null. Lets the browser check without a 401 in the console."""
        uid = session_user_id(request)
        u = ctx.session.get(User, uid) if uid else None
        if u is None or not u.active:
            return {"user": None}
        from paylineage.db.models import WebAuthnCredential

        n = len(
            ctx.session.execute(
                select(WebAuthnCredential.id).where(
                    WebAuthnCredential.user_id == u.id, WebAuthnCredential.revoked_at.is_(None)
                )
            ).all()
        )
        return {"user": {"id": u.id, "name": u.display_name, "roles": u.roles, "passkeys": n}}

    # ---- inbound email (mail gateway) and agent endpoints ----

    @r.post("/inbound/email")
    async def inbound(request: Request, x_ingest_token: str = Header(default="")) -> dict[str, Any]:
        expected = s.ingest_token.get_secret_value() if s.ingest_token else None
        if s.paylineage_env != "dev" and (
            not expected or not secrets.compare_digest(x_ingest_token.encode(), expected.encode())
        ):
            raise HTTPException(401)
        raw = await request.body()

        def work() -> dict[str, Any]:
            try:
                with _ctx() as ctx:
                    res = ingest_email(ctx, raw, _extractor())
            except IngestionError as exc:
                raise HTTPException(422, {"code": "INGESTION_REFUSED", "message": str(exc)}) from exc
            return {
                "invoice_id": res.invoice_id,
                "supplier_id": res.supplier_id,
                "signals": [g.code for g in res.signals],
            }

        return await run_in_threadpool(work)

    def _verify_agent(ctx: Ctx, request: Request, body: bytes) -> str:
        try:
            va = verify_request(
                ctx.session,
                method=request.method,
                target_uri=str(request.url),
                body=body,
                headers=dict(request.headers),
                now=ctx.now(),
            )
        except SignatureError as exc:
            raise HTTPException(401, {"code": "AGENT_SIGNATURE_INVALID", "message": str(exc)}) from exc
        return va.agent_id

    def _agent_invoice_view(ctx: Ctx, inv: Invoice) -> dict[str, Any]:
        fields = ctx.session.execute(
            select(ExtractedField).where(ExtractedField.invoice_id == inv.id)
        ).scalars()
        return {
            "invoice_id": inv.id,
            "supplier_id": inv.supplier_id,
            "fields": {f.field_name: f.display_value for f in fields},
            "note": "Values are untrusted_external. Account numbers are masked.",
        }

    @r.get("/agent/invoices")
    async def agent_invoices(request: Request) -> dict[str, Any]:
        """Invoices with no payment proposed yet. Typed fields only, never document text."""
        body = await request.body()

        def work() -> dict[str, Any]:
            with _ctx() as ctx:
                _verify_agent(ctx, request, body)
                proposed = select(Payment.invoice_id)
                rows = (
                    ctx.session.execute(
                        select(Invoice)
                        .where(Invoice.id.notin_(proposed))
                        .order_by(Invoice.created_at)
                        .limit(20)
                    )
                    .scalars()
                    .all()
                )
                return {"invoices": [_agent_invoice_view(ctx, i) for i in rows]}

        return await run_in_threadpool(work)

    @r.get("/agent/invoices/{invoice_id}")
    async def agent_invoice(invoice_id: str, request: Request) -> dict[str, Any]:
        """Typed fields only. The planner never receives raw document text (ARCHITECTURE)."""
        body = await request.body()

        def work() -> dict[str, Any]:
            with _ctx() as ctx:
                _verify_agent(ctx, request, body)
                inv = ctx.session.get(Invoice, invoice_id)
                if inv is None:
                    raise HTTPException(404)
                return _agent_invoice_view(ctx, inv)

        return await run_in_threadpool(work)

    @r.post("/agent/proposals")
    async def agent_propose(
        request: Request, idempotency_key: str = Header(min_length=8, max_length=128)
    ) -> Any:
        raw = await request.body()

        def work() -> Any:
            with _ctx() as ctx:
                agent_id = _verify_agent(ctx, request, raw)
                try:
                    body = ProposalIn.model_validate_json(raw)
                except ValueError as exc:
                    raise HTTPException(422, {"code": "INPUT_INVALID", "message": "bad proposal"}) from exc
                payments.idempotency_lock(ctx.session, f"agent:{agent_id}", idempotency_key)
                cached = _idempotent(ctx, f"agent:{agent_id}", idempotency_key, body.model_dump())
                if cached is not None:
                    return cached
                try:
                    res = payments.propose(
                        ctx,
                        Actor(agent_id, "agent", frozenset({"agent"})),
                        payments.Proposal(
                            invoice_id=body.invoice_id,
                            supplier_id=body.supplier_id,
                            amount_minor=body.amount_minor,
                            currency=body.currency,
                            beneficiary_account=body.beneficiary_account,
                            idempotency_key=idempotency_key,
                            operation=body.operation,
                            tool_descriptions=tuple(body.tool_descriptions),
                        ),
                        signature_valid=True,
                    )
                except DomainError as exc:
                    raise _fail(exc) from exc
                out = {"payment_id": res.payment.id, "state": res.payment.state, **res.decision.as_dict()}
                return _remember(ctx, f"agent:{agent_id}", idempotency_key, body.model_dump(), out)

        return await run_in_threadpool(work)

    # ---- payment control ----

    @r.get("/queue")
    def get_queue(
        state: str | None = None, _m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)
    ) -> dict[str, Any]:
        items = views.queue(ctx.session, state)
        exposure = sum(
            i["exposure_minor"] for i in items if i["state"] in ("held", "awaiting_approval", "evaluated")
        )
        e = get_engine()
        return {
            "items": items,
            "exposure_minor": exposure,
            "policy_runtime": e.runtime,
            "policy_sha256": e.sha256,
        }

    @r.get("/payments/{pid}")
    def get_payment(pid: str, _m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
        return views.payment_detail(ctx.session, _payment(ctx, pid))

    @r.post("/payments/{pid}/explain")
    def explain_payment(
        pid: str, _m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)
    ) -> dict[str, Any]:
        e = explain(views.payment_detail(ctx.session, _payment(ctx, pid)))
        return {"text": e.text, "source": e.source, "label": e.label}

    def _act(fn: Any) -> Any:
        try:
            return fn()
        except DomainError as exc:
            raise _fail(exc) from exc

    @r.post("/payments/{pid}/clear-hold")
    def clear(
        pid: str, body: ClearIn, m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)
    ) -> dict[str, Any]:
        res = _act(lambda: payments.clear_hold(ctx, pid, m.actor, body.code, body.note))
        return {"state": res.payment.state, **res.decision.as_dict()}

    @r.post("/payments/{pid}/recheck")
    def recheck(pid: str, m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
        require_role(m, "analyst", "steward", "ap_specialist")
        res = _act(lambda: payments.recheck(ctx, pid, m.actor))
        return {"state": res.payment.state, **res.decision.as_dict()}

    @r.post("/payments/{pid}/deny")
    def deny(
        pid: str, body: ReasonIn, m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)
    ) -> dict[str, Any]:
        p = _act(lambda: payments.deny_held(ctx, pid, m.actor, body.reason))
        return {"state": p.state}

    @r.post("/payments/{pid}/edit")
    def edit(
        pid: str, body: EditIn, m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)
    ) -> dict[str, Any]:
        res = _act(
            lambda: payments.material_change(
                ctx,
                pid,
                m.actor,
                payments.MaterialChange(
                    amount_minor=body.amount_minor, beneficiary_account=body.beneficiary_account
                ),
            )
        )
        return {"state": res.payment.state, "version": res.payment.version, **res.decision.as_dict()}

    @r.post("/payments/{pid}/approval/begin")
    def approval_begin(
        pid: str, m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)
    ) -> dict[str, Any]:
        require_role(m, "finance_approver")
        issued = _act(lambda: approvals.begin_approval(ctx, pid, m.user))
        p = _payment(ctx, pid)
        detail = views.payment_detail(ctx.session, p)
        return {
            "challenge_id": issued.challenge_id,
            "options": json.loads(issued.options_json),
            "record": detail["record"],
            "digest": detail["digest"],
            "supplier": detail["supplier"],
            "proposed_account": detail["proposed_account"],
        }

    @r.post("/payments/{pid}/approval/finish")
    def approval_finish(pid: str, body: CredentialIn, _m: Me = Depends(current_user)) -> dict[str, Any]:
        # Its own transaction so a refusal (and the spent challenge) is committed before we answer.
        failure: DomainError | None = None
        with _ctx() as ctx:
            owner = ctx.session.execute(
                select(WebAuthnChallenge.user_id, WebAuthnChallenge.payment_id).where(
                    WebAuthnChallenge.id == body.challenge_id
                )
            ).first()
            if owner is None or owner[0] != _m.user.id or owner[1] != pid:
                raise HTTPException(
                    403,
                    {"code": "CHALLENGE_INVALID", "message": "challenge not issued to you for this payment"},
                )
            try:
                out = approvals.finish_approval(ctx, body.challenge_id, body.credential)
            except DomainError as exc:
                # The challenge stays spent: leave the block normally so its consumption commits.
                failure = exc
        if failure is not None:
            raise _fail(failure)
        result = {
            "approved": out.approval is not None,
            "state": out.payment.state,
            "receipt": None
            if out.approval is None
            else {
                "approval_id": out.approval.id,
                "digest": out.approval.digest,
                "version": out.approval.payment_version,
                "signed_at": out.approval.signed_at.isoformat(),
                "expires_at": out.approval.expires_at.isoformat(),
            },
            **out.decision.as_dict(),
        }
        if out.approval is None:
            raise HTTPException(
                403,
                {
                    "code": out.decision.reasons[0] if out.decision.reasons else "POLICY_UNDEFINED",
                    "message": "approval refused",
                    "detail": result,
                },
            )
        return result

    @r.post("/payments/{pid}/permit")
    def permit(pid: str, m: Me = Depends(current_user)) -> dict[str, Any]:
        require_role(m, "finance_approver", "ap_specialist")
        with _ctx() as ctx:
            out = _act(lambda: issue_permit(ctx, pid, m.actor))
            result = {"permit_id": out.permit.id if out.permit else None, **out.decision.as_dict()}
        if out.permit is None:
            raise HTTPException(
                403, {"code": out.decision.reasons[0], "message": "permit refused", "detail": result}
            )
        return result

    @r.post("/payments/{pid}/execute")
    def execute(pid: str, request: Request, m: Me = Depends(current_user)) -> dict[str, Any]:
        require_role(m, "finance_approver", "ap_specialist")
        with _ctx() as ctx:
            p = _payment(ctx, pid)
            permit_row = (
                ctx.session.execute(
                    select(Permit)
                    .where(Permit.payment_id == p.id, Permit.consumed_at.is_(None))
                    .order_by(Permit.issued_at.desc())
                )
                .scalars()
                .first()
            )
            if permit_row is None:
                raise HTTPException(409, {"code": "PERMIT_MISSING", "message": "issue a permit first"})
            permit_id = permit_row.id
        rid = request.headers.get("idempotency-key") or secrets.token_hex(12)
        out: dict[str, Any] = request.app.state.executor.execute(permit_id, rid)
        return out

    # ---- suppliers and onboarding ----

    @r.get("/suppliers")
    def suppliers(_m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)) -> list[dict[str, Any]]:
        return [
            views.supplier_detail(ctx.session, x)
            for x in ctx.session.execute(select(Supplier).order_by(Supplier.legal_name)).scalars()
        ]

    @r.get("/suppliers/{sid}")
    def supplier(sid: str, _m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
        sup = ctx.session.get(Supplier, sid)
        if sup is None:
            raise HTTPException(404)
        return views.supplier_detail(ctx.session, sup)

    @r.get("/onboarding")
    def onboarding_queue(_m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)) -> list[dict[str, Any]]:
        rows = ctx.session.execute(
            select(OnboardingRequest)
            .where(OnboardingRequest.closed_at.is_(None))
            .order_by(OnboardingRequest.created_at)
        ).scalars()
        out = []
        for q in rows:
            sup = ctx.session.get(Supplier, q.supplier_id)
            out.append(
                {
                    "id": q.id,
                    "kind": q.kind,
                    "state": q.state,
                    "supplier": sup.legal_name if sup else None,
                    "supplier_id": q.supplier_id,
                    "channel": q.channel,
                    "risk_tier": q.risk_tier,
                    "requester": views.user_name(ctx.session, q.requester_id),
                    "verifier": views.user_name(ctx.session, q.verifier_id),
                    "created_at": q.created_at.isoformat(),
                }
            )
        return out

    @r.post("/suppliers")
    def new_supplier(
        body: NewSupplierIn, m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)
    ) -> dict[str, Any]:
        req = _act(
            lambda: onb.request_new_supplier(
                ctx,
                m.actor,
                onb.NewSupplier(
                    body.legal_name,
                    body.domains,
                    body.registry_id,
                    {"phone": body.contact_phone} if body.contact_phone else None,
                    body.bank_account,
                    body.bank_name,
                ),
            )
        )
        return {"request_id": req.id, "supplier_id": req.supplier_id, "state": req.state}

    @r.post("/suppliers/{sid}/bank-changes")
    def bank_change(
        sid: str, body: BankChangeIn, m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)
    ) -> dict[str, Any]:
        req = _act(
            lambda: onb.record_bank_change(
                ctx,
                m.actor,
                supplier_id=sid,
                new_account_raw=body.new_account,
                bank_name=body.bank_name,
                channel=body.channel,
                old_account_outcome=body.old_account_outcome,
            )
        )
        return {"request_id": req.id, "state": req.state}

    def _user_actor(ctx: Ctx, uid: str) -> Actor:
        u = ctx.session.get(User, uid)
        if u is None:
            raise HTTPException(404)
        return Actor(u.id, "user", frozenset(u.roles), u.active)

    @r.post("/onboarding/{rid}/assign")
    def assign(
        rid: str, body: AssignIn, m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)
    ) -> dict[str, str]:
        req = _act(lambda: onb.assign_verifier(ctx, m.actor, rid, _user_actor(ctx, body.verifier_id)))
        return {"state": req.state}

    @r.post("/onboarding/{rid}/verify")
    def verify(
        rid: str, body: VerifyIn, m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)
    ) -> dict[str, Any]:
        with _ctx() as tx:
            try:
                req = onb.record_verification(
                    tx, m.actor, rid, onb.VerificationClaim(body.method, body.callback_confirmed, body.note)
                )
                return {"state": req.state, "verification": req.verification}
            except DomainError as exc:
                err = exc
        raise _fail(err)

    @r.post("/onboarding/{rid}/approve")
    def steward_ok(rid: str, m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)) -> dict[str, str]:
        req = _act(lambda: onb.steward_approve(ctx, m.actor, rid))
        return {"state": req.state}

    @r.post("/onboarding/{rid}/reject")
    def steward_no(
        rid: str, body: ReasonIn, m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)
    ) -> dict[str, str]:
        req = _act(lambda: onb.reject(ctx, m.actor, rid, body.reason))
        return {"state": req.state}

    # ---- agents and mandates ----

    @r.get("/agents")
    def agents(_m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)) -> list[dict[str, Any]]:
        return views.agents_view(ctx.session)

    @r.post("/agents/{aid}/mandates")
    def new_mandate(
        aid: str, body: MandateIn, m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)
    ) -> dict[str, Any]:
        require_role(m, "platform_engineer", "admin")
        cur = ctx.session.execute(
            select(Mandate).where(Mandate.agent_id == aid).order_by(Mandate.version.desc()).limit(1)
        ).scalar_one_or_none()
        if cur is None:
            raise HTTPException(404)
        now = ctx.now()
        new = Mandate(
            agent_id=aid,
            version=cur.version + 1,
            principal_org=cur.principal_org,
            permitted_operations=cur.permitted_operations,
            forbidden_operations=cur.forbidden_operations,
            supplier_scope=body.supplier_scope,
            per_proposal_ceiling_minor=body.per_proposal_ceiling_minor,
            daily_ceiling_minor=body.daily_ceiling_minor,
            approver_role=cur.approver_role,
            second_approver_above_minor=body.second_approver_above_minor,
            not_before=now,
            expires_at=now + timedelta(days=body.expires_in_days),
            created_by=m.user.id,
        )
        ctx.session.add(new)
        from paylineage.audit.chain import append

        append(
            ctx.session,
            actor=m.user.id,
            kind="mandate.version_created",
            subject_id=new.id,
            payload={"agent_id": aid, "version": new.version, "ceiling": body.per_proposal_ceiling_minor},
            now=now,
        )
        return {"version": new.version}

    @r.post("/agents/{aid}/mandates/revoke")
    def revoke(
        aid: str, body: ReasonIn, m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)
    ) -> dict[str, Any]:
        require_role(m, "platform_engineer", "admin")
        cur = ctx.session.execute(
            select(Mandate).where(Mandate.agent_id == aid).order_by(Mandate.version.desc()).limit(1)
        ).scalar_one_or_none()
        if cur is None:
            raise HTTPException(404)
        cur.revoked_at = ctx.now()
        from paylineage.audit.chain import append

        append(
            ctx.session,
            actor=m.user.id,
            kind="mandate.revoked",
            subject_id=cur.id,
            payload={"agent_id": aid, "version": cur.version, "reason": body.reason},
            now=ctx.now(),
        )
        return {"revoked_version": cur.version}

    # ---- audit ----

    @r.post("/audit/checkpoint")
    def audit_checkpoint_now(m: Me = Depends(current_user)) -> dict[str, Any]:
        require_role(m, "admin", "analyst")
        cp = _write_checkpoint()
        return {"seq": cp.seq if cp else None, "written": cp is not None}

    @r.get("/audit/events")
    def audit_events(_m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
        events = load_events(ctx.session)
        problems, _last, head = verify_events(events)
        problems, checkpoints, note = _with_checkpoints(ctx, problems)
        return {
            "events": [
                {
                    "seq": e.seq,
                    "kind": e.kind,
                    "actor": views.user_name(ctx.session, e.actor) or e.actor,
                    "at": e.created_at.isoformat(),
                    "hash": e.hash[:12],
                }
                for e in events[-500:]
            ],
            "verified": not problems,
            "problems": [p.__dict__ for p in problems],
            "head": head,
            "checkpoints": checkpoints,
            "note": note,
        }

    @r.get("/audit/verify")
    def audit_verify(_m: Me = Depends(current_user), ctx: Ctx = Depends(get_ctx)) -> dict[str, Any]:
        events = load_events(ctx.session)
        problems, last, head = verify_events(events)
        problems, _n, _note = _with_checkpoints(ctx, problems)
        return {
            "events": len(events),
            "last_seq": last,
            "head": head,
            "problems": [p.__dict__ for p in problems],
            "note": "Tamper evident relative to signed checkpoints, not tamper proof.",
        }

    app.include_router(r)
    return app


def _ctx() -> Any:
    """A standalone transaction (commits on exit) for handlers that must commit before replying."""
    from contextlib import contextmanager

    from paylineage.db.base import get_sessionmaker

    @contextmanager
    def cm() -> Any:
        session = get_sessionmaker()()
        try:
            with session.begin():
                yield Ctx(session, get_clock(), get_engine())
        finally:
            session.close()

    return cm()


def run() -> None:
    import uvicorn

    uvicorn.run(create_app(), host=get_settings().bind_host, port=8000)
