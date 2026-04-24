"""Core abstractions for aigrc."""

from aigrc.core.models import (
    CheckResult,
    FrameworkRef,
    Outcome,
    Payload,
    PayloadResult,
    now_iso,
)
from aigrc.core.registry import Registry, get_registry
from aigrc.core.target import Target, build_target
from aigrc.core.reporter import Reporter

__all__ = [
    "CheckResult",
    "FrameworkRef",
    "Outcome",
    "Payload",
    "PayloadResult",
    "Registry",
    "Reporter",
    "Target",
    "build_target",
    "get_registry",
    "now_iso",
]
