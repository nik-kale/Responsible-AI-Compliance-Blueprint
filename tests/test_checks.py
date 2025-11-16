"""Tests for check modules."""

import pytest
from pathlib import Path

from raicb.config.schema import ProjectConfig, ProjectInfo, Owner, Artifacts, Environment
from raicb.checks import data_integrity, governance


def test_data_integrity_checks(tmp_path):
    """Test data integrity checks."""
    config = ProjectConfig(
        project=ProjectInfo(
            name="Test",
            version="1.0",
            owners=[Owner(name="Test", email="test@example.com")],
        ),
        artifacts=Artifacts(),
    )

    findings = data_integrity.run_checks(config, tmp_path, "prod")

    assert len(findings) > 0
    assert all(hasattr(f, "check_id") for f in findings)
    assert all(hasattr(f, "severity") for f in findings)


def test_governance_checks_with_policies(tmp_path):
    """Test governance checks with policies."""
    # Create dummy policy file
    policy_file = tmp_path / "risk_policy.md"
    policy_file.write_text("# Risk Policy\n\nThis is a test policy.")

    config = ProjectConfig(
        project=ProjectInfo(
            name="Test",
            version="1.0",
            owners=[Owner(name="Test", email="test@example.com")],
        ),
    )
    config.policies.risk_management = str(policy_file)

    findings = governance.run_checks(config, tmp_path, "prod")

    assert len(findings) > 0

    # Should have a finding about the risk policy being found
    policy_findings = [f for f in findings if "Risk Management Policy" in f.title]
    assert len(policy_findings) > 0


def test_governance_checks_missing_owners():
    """Test governance checks flag missing owners."""
    config = ProjectConfig(
        project=ProjectInfo(
            name="Test",
            version="1.0",
            owners=[],  # No owners
        ),
    )

    findings = governance.run_checks(config, Path("/tmp"), "prod")

    # Should have a finding about missing owners
    owner_findings = [f for f in findings if "Owner" in f.title]
    assert len(owner_findings) > 0
