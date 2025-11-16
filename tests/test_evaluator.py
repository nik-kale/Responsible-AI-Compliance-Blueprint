"""Tests for evaluator."""

import pytest
from pathlib import Path

from raicb.config.schema import ProjectConfig, ProjectInfo, Owner, Environment
from raicb.core.evaluator import run_all_checks, _generate_summary, _generate_risk_matrix
from raicb.config.schema import Finding, Severity, Status, Threat, Likelihood, Impact


def test_generate_summary():
    """Test summary generation from findings."""
    findings = [
        Finding(
            check_id="TEST-001",
            title="Test 1",
            severity=Severity.HIGH,
            status=Status.PASS,
            category="test",
            description="Test",
        ),
        Finding(
            check_id="TEST-002",
            title="Test 2",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            category="test",
            description="Test",
        ),
        Finding(
            check_id="TEST-003",
            title="Test 3",
            severity=Severity.LOW,
            status=Status.WARNING,
            category="other",
            description="Test",
        ),
    ]

    summary = _generate_summary(findings)

    assert summary["total"] == 3
    assert summary["passed"] == 1
    assert summary["failed"] == 1
    assert summary["warnings"] == 1
    assert summary["by_severity"]["critical"] == 1
    assert summary["by_severity"]["high"] == 1
    assert summary["by_severity"]["low"] == 1
    assert len(summary["critical_findings"]) == 1


def test_generate_risk_matrix():
    """Test risk matrix generation."""
    config = ProjectConfig(
        project=ProjectInfo(
            name="Test",
            version="1.0",
            owners=[Owner(name="Test", email="test@example.com")],
        ),
        threats=[
            Threat(
                id="T1",
                title="Test Threat 1",
                description="Test",
                likelihood=Likelihood.HIGH,
                impact=Impact.CRITICAL,
            ),
            Threat(
                id="T2",
                title="Test Threat 2",
                description="Test",
                likelihood=Likelihood.LOW,
                impact=Impact.LOW,
            ),
        ],
    )

    matrix = _generate_risk_matrix(config)

    assert matrix["total_threats"] == 2
    assert matrix["high_risk_count"] == 1  # HIGH x CRITICAL = 20


def test_run_all_checks_basic(tmp_path):
    """Test running all checks on minimal config."""
    config = ProjectConfig(
        project=ProjectInfo(
            name="Test",
            version="1.0",
            owners=[Owner(name="Test", email="test@example.com")],
        ),
        environments={"dev": Environment(name="dev")},
    )

    report = run_all_checks(config, tmp_path, "dev", verbose=False)

    assert report.project_name == "Test"
    assert report.version == "1.0"
    assert report.environment == "dev"
    assert report.total_checks > 0
    assert len(report.findings) > 0
