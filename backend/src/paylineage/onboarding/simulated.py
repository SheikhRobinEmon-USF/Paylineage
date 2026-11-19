"""SIMULATED verification services. Fictional data only (CLAUDE.md rule 9).

PayLineage enforces verification decisions; it does not prove real bank account
ownership. These stand in for a business registry and a bank account validation
service so the workflow can be exercised end to end.
"""

from __future__ import annotations

from dataclasses import dataclass

# Fictional business registry: registry id -> legal name.
REGISTRY: dict[str, str] = {
    "REG-ACME-0001": "Acme Industrial Supply Co. (fictional)",
    "REG-NORTH-0002": "Northwind Components LLC (fictional)",
    "REG-BLUE-0003": "Bluebird Packaging Inc. (fictional)",
    "REG-ORBIT-0004": "Orbit Fasteners Ltd. (fictional)",
    "REG-CEDAR-0005": "Cedar Logistics Group (fictional)",
    "REG-HARBOR-0006": "Harbor Chemicals Corp. (fictional)",
    # S13 residual risk: a forged entry an attacker managed to plant.
    "REG-FAKE-0666": "Acme Industrial Supplies Co. (fictional)",
}

# Fictional bank validation directory: normalized account -> holder legal name.
BANK_DIRECTORY: dict[str, str] = {}


def register_account_holder(normalized_account: str, holder: str) -> None:
    BANK_DIRECTORY[normalized_account] = holder


@dataclass(frozen=True)
class RegistryResult:
    found: bool
    name_matches: bool


def registry_lookup(registry_id: str | None, legal_name: str) -> RegistryResult:
    if registry_id is None or registry_id not in REGISTRY:
        return RegistryResult(found=False, name_matches=False)
    return RegistryResult(found=True, name_matches=REGISTRY[registry_id].casefold() == legal_name.casefold())


def validation_service(normalized_account: str, legal_name: str) -> bool:
    """Simulated account validation, like a confirmation of payee check."""
    holder = BANK_DIRECTORY.get(normalized_account)
    return holder is not None and holder.casefold() == legal_name.casefold()
