"""Runtime settings. Secrets only come from the environment (never from code or the DB)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]


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

    session_secret: SecretStr = SecretStr("dev-only-session-secret-change-me")
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

    @property
    def policy_wasm_path(self) -> Path:
        return self.policy_dir / "dist" / "policy.wasm"

    @property
    def policy_sha256_path(self) -> Path:
        return self.policy_dir / "dist" / "policy.sha256"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
