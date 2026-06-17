"""Tests for AGCP evidence hash integrity and determinism.

The evidence_hash must (a) be deterministic for identical evidence and
(b) be independently recomputable from the published "payloads" field, so a
third party can verify the evidence has not been altered.
"""

import hashlib
import json

from aigrc.checks import prompt_injection_basic  # noqa: F401
from aigrc.cli import _agcp_fields
from aigrc.core import build_target, get_registry


def _run():
    target = build_target("mock://moderate", model="mock", offline=True)
    fn = get_registry().get("prompt-injection")
    return fn(target, offline=True)


def test_evidence_hash_is_deterministic():
    fields_a = _agcp_fields(_run())
    fields_b = _agcp_fields(_run())
    assert fields_a["evidence_hash"] == fields_b["evidence_hash"]
    assert len(fields_a["evidence_hash"]) == 64  # sha256 hex


def test_evidence_hash_matches_published_payloads():
    """A verifier re-hashing the shipped 'payloads' field must reproduce
    evidence_hash. This is the property that was previously broken (hash was
    taken over untagged payloads while tagged payloads shipped)."""
    fields = _agcp_fields(_run())
    recomputed = hashlib.sha256(
        json.dumps(
            [p.model_dump() for p in fields["payloads"]],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert recomputed == fields["evidence_hash"]


def test_evidence_hash_changes_if_payload_changes():
    """Sanity: altering a shipped payload must change the recomputed hash,
    proving the hash actually covers the evidence content."""
    fields = _agcp_fields(_run())
    tampered = [p.model_dump() for p in fields["payloads"]]
    tampered[0]["agcp_layer"] = "TAMPERED"
    recomputed = hashlib.sha256(
        json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert recomputed != fields["evidence_hash"]


def test_provenance_chain_hash_matches():
    fields = _agcp_fields(_run())
    assert fields["provenance_chain"][0]["evidence_hash"] == fields["evidence_hash"]
