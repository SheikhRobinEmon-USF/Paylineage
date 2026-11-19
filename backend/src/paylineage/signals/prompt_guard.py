"""Optional Llama Prompt Guard 2 (86M) second opinion. Off unless PROMPT_GUARD=model.

The model is gated on Hugging Face: the owner accepts the licence and sets
HF_TOKEN. `transformers` and `torch` are not dependencies of the app; if they
are missing the heuristic alone runs. The model output can only add a signal
(a hold), never remove one or allow anything.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

log = logging.getLogger("paylineage.signals")
MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"


@lru_cache(maxsize=1)
def _pipeline() -> Any:
    try:
        from transformers import pipeline  # type: ignore[import-not-found]
    except ImportError:
        log.warning("PROMPT_GUARD=model but transformers is not installed; heuristic only")
        return None
    try:
        return pipeline("text-classification", model=MODEL_ID, device=-1, truncation=True, max_length=512)
    except Exception as exc:  # noqa: BLE001 - optional detector; heuristic still runs
        log.warning("Prompt Guard unavailable: %s", type(exc).__name__)
        return None


def malicious_probability(text: str) -> float | None:
    pipe = _pipeline()
    if pipe is None or not text.strip():
        return None
    chunks = [text[i : i + 1500] for i in range(0, min(len(text), 15000), 1500)]
    best = 0.0
    for out in pipe(chunks):
        label = str(out.get("label", "")).upper()
        score = float(out.get("score", 0.0))
        p = score if ("MALICIOUS" in label or label.endswith("1")) else 1.0 - score
        best = max(best, p)
    return best
