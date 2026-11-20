"""Runtime settings. Secrets only come from the environment (never from code or the DB)."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The checkout root. Installed (non editable) packages live in site-packages, so
# containers set PAYLINEAGE_ROOT explicitly.
REPO_ROOT = Path(os.environ.get("PAYLINEAGE_ROOT") or Path(__file__).resolve().parents[3])

DEV_SESSION_SECRET = "dev-only-session-secret-change-me"  # noqa: S105 (dev default, refused in prod)
DEV_VAULT_PEPPER = "dev-only-vault-pepper-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", env_file=".env", extra="ignore")

    paylineage_env: Literal["dev", "test", "prod"] = "dev"
    database_url: str = "postgresql+psycopg://paylineage:paylineage_dev@localhost:5432/paylineage"

    policy_dir: Path = REPO_ROOT / "policy"
    # Optional pin. When set, the loaded policy.wasm must hash to exactly this value.
    policy_sha256: str | None = None
    # "wasm" is the only silent-free default. "opa-server" needs an explicit opt in,
    # a matching POLICY_SHA256 and a passing parity run (I8).
    policy_runtime: Literal["wasm", "opa-server"] = "wasm"
    opa_server_url: str | None = None
    policy_fuel: int = Field(default=20_000_000, ge=100_000)

    session_secret: SecretStr = SecretStr(DEV_SESSION_SECRET)
    # Keyed hash for account tokens. Separate from the session secret so rotating
    # sessions never changes tokens. Changing it requires re-tokenizing the vault.
    vault_pepper: SecretStr = SecretStr(DEV_VAULT_PEPPER)
    # Shared secret for the mail gateway posting to /v1/inbound/email.
    ingest_token: SecretStr | None = None
    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "PayLineage (simulation)"
    webauthn_origin: str = "http://localhost:3000"

    # Executor and mock bank. The agent-facing API never needs MOCKBANK_TOKEN (I6).
    executor_url: str = "http://localhost:8100"
    executor_token: SecretStr | None = None
    mockbank_url: str = "http://localhost:8200"
    mockbank_token: SecretStr | None = None

    audit_checkpoint_dir: Path = REPO_ROOT / "var" / "checkpoints"
    audit_checkpoint_key_path: Path | None = None
    audit_checkpoint_every: int = 50

    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3.5:4b"
    extractor: Literal["deterministic", "ollama", "adversarial_stub"] = "deterministic"
    prompt_guard: Literal["off", "heuristic", "model"] = "heuristic"

    @model_validator(mode="after")
    def _no_dev_secrets_in_prod(self) -> Settings:
        if self.paylineage_env == "prod":
            problems = []
            if self.session_secret.get_secret_value() == DEV_SESSION_SECRET:
                problems.append("SESSION_SECRET")
            if self.vault_pepper.get_secret_value() == DEV_VAULT_PEPPER:
                problems.append("VAULT_PEPPER")
            if self.executor_token is None:
                problems.append("EXECUTOR_TOKEN")
            if problems:
                raise ValueError(f"production refuses development defaults for: {', '.join(problems)}")
        return self

    @property
    def policy_wasm_path(self) -> Path:
        return self.policy_dir / "dist" / "policy.wasm"

    @property
    def policy_sha256_path(self) -> Path:
        return self.policy_dir / "dist" / "policy.sha256"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
