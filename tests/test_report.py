"""Tests for report generation."""

import pytest
from pathlib import Path

from raicb.config.schema import AssessmentReport, Finding, Severity, Status
from raicb.core.report import generate_report, _group_findings_by_category


def test_group_findings_by_category():
    """Test grouping findings by category."""
    findings = [
        Finding(
            check_id="TEST-001",
            title="Test 1",
            severity=Severity.HIGH,
            status=Status.PASS,
            category="data_integrity",
            description="Test",
        ),
        Finding(
            check_id="TEST-002",
            title="Test 2",
            severity=Severity.LOW,
            status=Status.PASS,
            category="data_integrity",
            description="Test",
        ),
        Finding(
            check_id="TEST-003",
            title="Test 3",
            severity=Severity.MEDIUM,
            status=Status.FAIL,
            category="governance",
            description="Test",
        ),
    ]

    grouped = _group_findings_by_category(findings)

    assert len(grouped) == 2
    assert len(grouped["data_integrity"]) == 2
    assert len(grouped["governance"]) == 1


def test_generate_report_markdown(tmp_path):
    """Test Markdown report generation."""
    report = AssessmentReport(
        project_name="Test Project",
        version="1.0.0",
        environment="prod",
        assessment_date="2024-01-20",
        findings=[
            Finding(
                check_id="TEST-001",
                title="Test Finding",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                category="test",
                description="Test description",
            )
        ],
        total_checks=1,
        passed_checks=1,
        failed_checks=0,
        warnings=0,
    )

    files = generate_report(report, tmp_path, ["md"])

    assert len(files) == 1
    assert files[0].suffix == ".md"
    assert files[0].exists()

    content = files[0].read_text()
    assert "Test Project" in content
    assert "Test Finding" in content


def test_generate_report_html(tmp_path):
    """Test HTML report generation."""
    report = AssessmentReport(
        project_name="Test Project",
        version="1.0.0",
        environment="prod",
        assessment_date="2024-01-20",
        findings=[],
        total_checks=0,
        passed_checks=0,
        failed_checks=0,
        warnings=0,
    )

    files = generate_report(report, tmp_path, ["html"])

    assert len(files) == 1
    assert files[0].suffix == ".html"
    assert files[0].exists()

    content = files[0].read_text()
    assert "<!DOCTYPE html>" in content
    assert "Test Project" in content
