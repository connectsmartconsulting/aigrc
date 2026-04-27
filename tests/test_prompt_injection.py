"""End-to-end tests using the offline mock target."""

from pathlib import Path

from aigrc.checks import prompt_injection_basic  # noqa: F401
from aigrc.core import Reporter, build_target, get_registry
from aigrc.core.models import Outcome


def test_registry_has_prompt_injection():
    reg = get_registry()
    assert "prompt-injection" in reg.list_checks()
    meta = reg.metadata("prompt-injection")
    assert meta["version"] == "0.1.0"
    frameworks = [f["framework"] for f in meta["frameworks"]]
    assert "NIST AI RMF" in frameworks
    assert "OWASP LLM Top 10" in frameworks
    assert "EU AI Act" in frameworks


def test_prompt_injection_runs_offline():
    target = build_target("mock://moderate", model="mock", offline=True)
    fn = get_registry().get("prompt-injection")
    result = fn(target, offline=True)

    assert result.check_id == "prompt-injection"
    assert len(result.payloads) == 18
    assert result.passed > 0
    assert result.failed > 0
    assert 0 <= result.pass_rate <= 100
    assert result.summary in {"COMPLIANT", "PARTIAL COMPLIANCE", "NON-COMPLIANT"}


def test_no_errors_in_offline_run():
    target = build_target("mock://moderate", model="mock", offline=True)
    fn = get_registry().get("prompt-injection")
    result = fn(target, offline=True)
    assert result.errored == 0


def test_reporter_writes_valid_json(tmp_path: Path):
    target = build_target("mock://moderate", model="mock", offline=True)
    fn = get_registry().get("prompt-injection")
    result = fn(target, offline=True)

    json_path = tmp_path / "report.json"
    Reporter.write_json(result, json_path)
    assert json_path.exists()
    text = json_path.read_text()
    assert "prompt-injection" in text
    assert "NIST AI RMF" in text


def test_reporter_writes_markdown_with_framework_table(tmp_path: Path):
    target = build_target("mock://moderate", model="mock", offline=True)
    fn = get_registry().get("prompt-injection")
    result = fn(target, offline=True)

    md_path = tmp_path / "report.md"
    Reporter.write_markdown(result, md_path)
    text = md_path.read_text()
    assert "# aigrc evidence report" in text
    assert "NIST AI RMF" in text
    assert "MEASURE 2.7" in text
    assert "Regulatory mapping" in text


def test_canary_detection():
    """Payload 001 (direct override) is expected to leak canary against moderate mock."""
    target = build_target("mock://moderate", model="mock", offline=True)
    fn = get_registry().get("prompt-injection")
    result = fn(target, offline=True)

    # Base64 and delimiter injection payloads should fail against moderate policy
    fails = [p for p in result.payloads if p.outcome == Outcome.FAIL]
    assert any("base64" in p.label.lower() or "Delimiter" in p.label for p in fails)


def test_reporter_writes_valid_sarif(tmp_path: Path):
    """SARIF v2.1.0 output should be valid JSON with the required top-level keys
    and should round-trip cleanly through json.loads."""
    import json as _json

    target = build_target("mock://moderate", model="mock", offline=True)
    fn = get_registry().get("prompt-injection")
    result = fn(target, offline=True)

    sarif_path = tmp_path / "report.sarif"
    Reporter.write_sarif(result, sarif_path)
    assert sarif_path.exists()

    data = _json.loads(sarif_path.read_text())
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1

    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "aigrc"
    assert "rules" in run["tool"]["driver"]
    assert len(run["tool"]["driver"]["rules"]) > 0

    # Each FAIL payload should appear as a SARIF result
    fail_count = sum(1 for p in result.payloads if p.outcome.value == "FAIL")
    assert len(run["results"]) == fail_count

    # Results must reference rules by id and carry framework metadata
    for r in run["results"]:
        assert r["ruleId"]
        assert r["level"] in {"error", "warning", "note", "none"}
        assert "frameworks" in r["properties"]
        assert any("NIST" in fw for fw in r["properties"]["frameworks"])
