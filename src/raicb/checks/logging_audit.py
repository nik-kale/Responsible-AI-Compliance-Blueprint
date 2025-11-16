"""Logging and audit trail checks."""

from pathlib import Path
from typing import List
import os

from ..config.schema import ProjectConfig, Finding, Severity, Status


def run_checks(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """
    Run logging and audit checks.

    Args:
        config: Project configuration
        project_root: Project root directory
        env: Environment name

    Returns:
        List of findings
    """
    findings: List[Finding] = []

    # Get environment config
    env_config = config.environments.get(env)

    # Check 1: Logging configuration
    findings.extend(_check_logging_enabled(config, env_config, env))

    # Check 2: Audit trail presence
    findings.extend(_check_audit_trails(project_root))

    # Check 3: Log rotation policy
    findings.extend(_check_log_rotation(project_root))

    # Check 4: Log integrity/tamper-evidence
    findings.extend(_check_log_integrity(project_root))

    return findings


def _check_logging_enabled(config, env_config, env: str) -> List[Finding]:
    """Check if logging is enabled."""
    findings = []

    if not env_config:
        return findings  # Already flagged elsewhere

    if not env_config.logging_enabled:
        findings.append(
            Finding(
                check_id="LOG-001",
                title="Logging Not Enabled",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="logging_audit",
                description=f"Logging is not enabled for {env} environment",
                evidence=f"Environment: {env}, logging_enabled: false",
                remediation="Enable logging to maintain audit trails",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="LOG-001",
                title="Logging Enabled",
                severity=Severity.INFO,
                status=Status.PASS,
                category="logging_audit",
                description=f"Logging is enabled for {env} environment",
                evidence=f"Environment: {env}",
                remediation="N/A",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )

    return findings


def _check_audit_trails(project_root: Path) -> List[Finding]:
    """Check for audit trail files."""
    findings = []

    # Look for common log directories
    log_locations = [
        project_root / "logs",
        project_root / "log",
        project_root / "var" / "log",
    ]

    found_logs = []
    for loc in log_locations:
        if loc.exists() and loc.is_dir():
            # Count log files
            log_files = list(loc.glob("*.log"))
            if log_files:
                found_logs.append((loc, len(log_files)))

    if not found_logs:
        findings.append(
            Finding(
                check_id="LOG-002",
                title="No Log Files Found",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="logging_audit",
                description="No log files found in standard locations",
                evidence="Checked: logs/, log/, var/log/",
                remediation="Configure logging to create audit trails",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )
    else:
        total_logs = sum(count for _, count in found_logs)
        locations = ", ".join(str(loc.relative_to(project_root)) for loc, _ in found_logs)

        findings.append(
            Finding(
                check_id="LOG-002",
                title="Audit Trails Found",
                severity=Severity.INFO,
                status=Status.PASS,
                category="logging_audit",
                description=f"Found {total_logs} log file(s) in {len(found_logs)} location(s)",
                evidence=f"Locations: {locations}",
                remediation="N/A",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )

    return findings


def _check_log_rotation(project_root: Path) -> List[Finding]:
    """Check for log rotation policy indicators."""
    findings = []

    # Look for logrotate config or similar
    rotation_indicators = [
        project_root / "logrotate.conf",
        project_root / ".logrotate",
        project_root / "config" / "logrotate.conf",
    ]

    found_rotation = False
    for indicator in rotation_indicators:
        if indicator.exists():
            found_rotation = True
            findings.append(
                Finding(
                    check_id="LOG-003",
                    title="Log Rotation Configured",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="logging_audit",
                    description="Log rotation configuration found",
                    evidence=f"File: {indicator.relative_to(project_root)}",
                    remediation="N/A",
                    owasp_mapping=["LLM06"],
                    iso_mapping=["Clause_9"],
                )
            )
            break

    if not found_rotation:
        findings.append(
            Finding(
                check_id="LOG-003",
                title="Log Rotation Not Configured",
                severity=Severity.LOW,
                status=Status.WARNING,
                category="logging_audit",
                description="No log rotation policy detected",
                evidence="No logrotate.conf or similar found",
                remediation="Implement log rotation to manage storage and retention",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )

    return findings


def _check_log_integrity(project_root: Path) -> List[Finding]:
    """Check for log integrity/tamper-evidence features."""
    findings = []

    # Check for log signing or similar
    integrity_indicators = [
        project_root / "logs" / "checksums.txt",
        project_root / "logs" / "signatures",
        project_root / "log" / "checksums.txt",
    ]

    found_integrity = False
    for indicator in integrity_indicators:
        if indicator.exists():
            found_integrity = True
            findings.append(
                Finding(
                    check_id="LOG-004",
                    title="Log Integrity Checks Present",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="logging_audit",
                    description="Log integrity verification configured",
                    evidence=f"Found: {indicator.relative_to(project_root)}",
                    remediation="N/A",
                    owasp_mapping=["LLM06"],
                    iso_mapping=["Clause_9"],
                )
            )
            break

    if not found_integrity:
        findings.append(
            Finding(
                check_id="LOG-004",
                title="No Log Integrity Checks",
                severity=Severity.LOW,
                status=Status.WARNING,
                category="logging_audit",
                description="No tamper-evident logging detected",
                evidence="Consider implementing log signing or checksums",
                remediation="Implement log integrity checks to detect tampering",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )

    return findings
