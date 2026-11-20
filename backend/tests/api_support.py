"""Point the API at the test database and inject the test clock and executor."""

from __future__ import annotations

import os
from typing import Any

from fastapi.testclient import TestClient

from paylineage.eval.world import World
from paylineage.executor import service as executor_service


class InProcessExecutor:
    """Stands in for the executor process in tests; same service code, simulated bank."""

    def __init__(self, world: World) -> None:
        self.world = world

    def execute(self, permit_id: str, request_id: str) -> dict[str, Any]:
        with self.world.tx() as ctx:
            out = executor_service.execute(ctx, permit_id, request_id, self.world.bank)
        return {
            "executed": out.executed,
            "decision": out.decision.as_dict(),
            "bank_reference": out.bank_reference,
        }


def client_for(world: World, test_db: str) -> TestClient:
    from paylineage.api import deps
    from paylineage.api.main import create_app
    from paylineage.db import base
    from paylineage.settings import get_settings

    os.environ["DATABASE_URL"] = test_db
    os.environ["PAYLINEAGE_ENV"] = "dev"
    get_settings.cache_clear()
    base.get_engine.cache_clear()
    base.get_sessionmaker.cache_clear()
    deps.set_clock(world.clock)
    deps.LIMITER._state.clear()
    return TestClient(
        create_app(executor=InProcessExecutor(world)),
        base_url="http://localhost:8000",
        headers={"Origin": "http://localhost:3000"},
    )
