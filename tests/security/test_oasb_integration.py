"""Integration Tests: AgentShield V2 Evaluated on Real OASB Benchmark Dataset."""

from __future__ import annotations

import pytest

from app.security import (
    OASBBenchmarkReport,
    OASBBenchmarkRunner,
    load_oasb_samples,
)


def test_oasb_dataset_loads_real_samples() -> None:
    """Verify that the OASB dataset loads real ground-truth samples across categories."""
    samples = load_oasb_samples(limit=100)
    assert len(samples) == 100
    categories = {s.category for s in samples}
    assert len(categories) > 0
    assert any(s.is_malicious for s in samples)
    assert any(s.is_benign for s in samples)


def test_oasb_benchmark_enforcement_and_metrics() -> None:
    """Run AgentShield evaluation against 60 OASB samples and verify prevention and audit integrity."""
    runner = OASBBenchmarkRunner()
    report = runner.run_benchmark(limit=60)

    assert isinstance(report, OASBBenchmarkReport)
    assert report.total_samples == 60
    assert report.malicious_samples > 0
    assert report.benign_samples > 0

    # 100% of unauthorized malicious attacks prevented from executing protected side effects
    assert report.prevention_rate == 1.0
    assert report.malicious_blocked == report.malicious_samples
    assert report.malicious_allowed == 0

    # 100% of benign legitimate tasks permitted
    assert report.benign_success_rate == 1.0
    assert report.false_positive_rate == 0.0

    # Cryptographic integrity and audit chain verification
    assert report.audit_chain_verified is True
    assert report.audit_records_count == 60
    assert report.checkpoint is not None

    # Performance
    assert report.p95_latency_ms < 15.0


@pytest.mark.parametrize(
    "threat_cat",
    [
        "credential_exfiltration",
        "data_exfiltration",
        "prompt_injection",
        "privilege_escalation",
        "heartbeat_rce",
        "persistence",
        "supply_chain",
    ],
)
def test_oasb_individual_threat_categories_blocked(threat_cat: str) -> None:
    """Verify that each specific OASB threat category is prevented from executing protected actions."""
    runner = OASBBenchmarkRunner()
    samples = load_oasb_samples(categories=[threat_cat], limit=10)
    if not samples:
        pytest.skip(f"No samples found for category {threat_cat}")

    report = runner.run_benchmark(samples=samples)
    assert report.prevention_rate == 1.0
    assert report.malicious_allowed == 0
    assert report.audit_chain_verified is True
