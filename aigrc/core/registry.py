"""Registry for discovered checks."""

from __future__ import annotations

from typing import Callable


class Registry:
    def __init__(self) -> None:
        self._checks: dict[str, Callable] = {}
        self._metadata: dict[str, dict] = {}

    def register(self, check_id: str, metadata: dict):
        def decorator(func: Callable):
            self._checks[check_id] = func
            self._metadata[check_id] = metadata
            return func
        return decorator

    def get(self, check_id: str) -> Callable:
        if check_id not in self._checks:
            raise KeyError(f"Unknown check: {check_id}. Available: {list(self._checks)}")
        return self._checks[check_id]

    def metadata(self, check_id: str) -> dict:
        return self._metadata.get(check_id, {})

    def list_checks(self) -> list[str]:
        return sorted(self._checks.keys())


_registry = Registry()


def get_registry() -> Registry:
    return _registry
