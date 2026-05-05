"""End-to-end and unit tests for the pii-leakage check."""

import json
from pathlib import Path

from aigrc.checks import pii_leakage_basic  # noqa: F401 - registration
from aigrc.checks.pii_leakage_basic import (
    CANARY_CARD,
    CANARY_EMAIL,
    CANARY_SIN,
    PAYLOADS,
    _evaluate,
)
from aigrc.core import Reporter, build_target, get_registry
from aigrc.core.models import Outcome, Payload


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_registry_has_pii_leakage():
    reg = get_registry()
    assert "pii-leakage" in reg.list_checks()
    meta = reg.metadata("pii-leakage")
    assert meta["version"] == "0.1.0"
    frameworks = [f["framework"] for f in meta["frameworks"]]
    assert "NIST AI RMF" in frameworks
    assert "OWASP LLM Top 10" in frameworks
    assert "EU AI Act" in frameworks
    assert "PIPEDA" in frameworks


# ---------------------------------------------------------------------------
# Offline run structure
# ---------------------------------------------------------------------------

def test_pii_leakage_runs_offline():
    target = build_target("mock://moderate", model="mock", offline=True)
    fn = get_registry().get("pii-leakage")
    result = fn(target, offline=True)

    assert result.check_id == "pii-leakage"
    assert len(result.payloads) == 12
    assert 0 <= result.pass_rate <= 100
    assert result.summary in {"COMPLIANT", "PARTIAL COMPLIANCE", "NON-COMPLIANT"}


def test_no_errors_in_offline_run():
    target = build_target("mock://moderate", model="mock", offline=True)
    fn = get_registry().get("pii-leakage")
    result = fn(target, offline=True)
    assert result.errored == 0


def test_mock_shows_compliant():
    # MockTarget never returns PII tokens → all 12 payloads should PASS
    target = build_target("mock://moderate", model="mock", offline=True)
    fn = get_registry().get("pii-leakage")
    result = fn(target, offline=True)
    assert result.failed == 0
    assert result.pass_rate == 100.0
    assert result.summary == "COMPLIANT"


# ---------------------------------------------------------------------------
# _evaluate unit tests — Tier 1 (canary)
# ---------------------------------------------------------------------------

def _dummy_payload(pid: str = "PIL-01") -> Payload:
    return next(p for p in PAYLOADS if p.payload_id == pid)


def test_evaluate_detects_canary_sin():
    p = _dummy_payload("PIL-01")
    outcome, evidence = _evaluate(p, f"The SIN on file is {CANARY_SIN}.")
    assert outcome == Outcome.FAIL
    assert "canary:" in evidence
    assert "critical" in evidence


def test_evaluate_detects_canary_card():
    p = _dummy_payload("PIL-05")
    outcome, evidence = _evaluate(p, f"Card number: {CANARY_CARD}")
    assert outcome == Outcome.FAIL
    assert "canary:" in evidence


def test_evaluate_detects_canary_email():
    p = _dummy_payload("PIL-03")
    outcome, evidence = _evaluate(p, f"Email on file: {CANARY_EMAIL}")
    assert outcome == Outcome.FAIL
    assert "canary:" in evidence


def test_evaluate_normalised_canary():
    # Canary without dashes — normalised match must fire
    p = _dummy_payload("PIL-01")
    outcome, evidence = _evaluate(p, "The SIN is 123 45 6789 on this record.")
    assert outcome == Outcome.FAIL


# ---------------------------------------------------------------------------
# _evaluate unit tests — Tier 2 (regex)
# ---------------------------------------------------------------------------

def test_evaluate_detects_pii_regex_sin():
    p = _dummy_payload("PIL-01")
    # Generic SIN-shaped number not matching the exact canary
    outcome, evidence = _evaluate(p, "Customer SIN: 987-65-4321")
    assert outcome == Outcome.FAIL
    assert "regex:" in evidence


def test_evaluate_detects_pii_regex_email():
    p = _dummy_payload("PIL-03")
    outcome, evidence = _evaluate(p, "Contact them at someone@example.com")
    assert outcome == Outcome.FAIL
    assert "regex:email_address" in evidence


# ---------------------------------------------------------------------------
# _evaluate unit tests — clean / error paths
# ---------------------------------------------------------------------------

def test_evaluate_clean_response_passes():
    p = _dummy_payload("PIL-08")
    outcome, evidence = _evaluate(p, "I'm sorry, I cannot share that information.")
    assert outcome == Outcome.PASS
    assert evidence == "no PII detected"


def test_evaluate_target_error_reported():
    p = _dummy_payload("PIL-01")
    outcome, evidence = _evaluate(p, "[target-error] ConnectionError: timed out")
    assert outcome == Outcome.ERROR
    assert "[target-error]" in evidence


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

def test_reporter_writes_valid_json(tmp_path: Path):
    target = build_target("mock://moderate", model="mock", offline=True)
    fn = get_registry().get("pii-leakage")
    result = fn(target, offline=True)

    json_path = tmp_path / "report.json"
    Reporter.write_json(result, json_path)
    assert json_path.exists()
    text = json_path.read_text()
    assert "pii-leakage" in text
    assert "NIST AI RMF" in text


def test_reporter_writes_markdown(tmp_path: Path):
    target = build_target("mock://moderate", model="mock", offline=True)
    fn = get_registry().get("pii-leakage")
    result = fn(target, offline=True)

    md_path = tmp_path / "report.md"
    Reporter.write_markdown(result, md_path)
    text = md_path.read_text()
    assert "# aigrc evidence report" in text
    assert "NIST AI RMF" in text
    assert "MEASURE 2.10" in text
    assert "Regulatory mapping" in text


def test_reporter_writes_valid_sarif(tmp_path: Path):
    target = build_target("mock://moderate", model="mock", offline=True)
    fn = get_registry().get("pii-leakage")
    result = fn(target, offline=True)

    sarif_path = tmp_path / "report.sarif"
    Reporter.write_sarif(result, sarif_path)
    assert sarif_path.exists()

    data = json.loads(sarif_path.read_text())
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1

    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "aigrc"
    assert "rules" in run["tool"]["driver"]
    assert len(run["tool"]["driver"]["rules"]) > 0

    fail_count = sum(1 for p in result.payloads if p.outcome.value == "FAIL")
    assert len(run["results"]) == fail_count
