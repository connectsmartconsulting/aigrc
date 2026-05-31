"""Core abstractions: Check, Target, CheckResult, PayloadResult."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel


class Outcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


class FrameworkRef(BaseModel):
    """A single regulatory framework control reference."""
    framework: str
    control_id: str
    title: str


class PayloadResult(BaseModel):
    """Result of a single payload execution against a target."""
    payload_id: str
    label: str
    technique: str
    outcome: Outcome
    evidence: str
    target_response: str = ""
    elapsed_ms: int = 0
    agcp_layer: str = ""


class CheckResult(BaseModel):
    """Aggregate result of a single check run."""
    check_id: str
    check_version: str
    target: str
    model_hint: str = ""
    started_at: str
    finished_at: str
    frameworks: list[FrameworkRef]
    payloads: list[PayloadResult]
    pass_rate: float
    summary: str
    offline: bool = False

    # AGCP Phase 1 conformance fields
    evidence_id: str = ""
    evidence_hash: str = ""
    source_system: str = "aigrc"
    evaluation_timestamp: str = ""
    provenance_chain: list[dict] = []
    agcp_conformance_levels: list[str] = []

    @property
    def passed(self) -> int:
        return sum(1 for p in self.payloads if p.outcome == Outcome.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for p in self.payloads if p.outcome == Outcome.FAIL)

    @property
    def errored(self) -> int:
        return sum(1 for p in self.payloads if p.outcome == Outcome.ERROR)


@dataclass
class Payload:
    """A single adversarial test payload."""
    payload_id: str
    label: str
    technique: str
    prompt: str
    canary: str = ""
    evaluator: str = "canary_leak"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
