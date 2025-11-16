"""PII and privacy checks."""

from pathlib import Path
from typing import List

from ..config.schema import ProjectConfig, Finding, Severity, Status
from ..core.utils import scan_file_for_pii
from ..core.loader import resolve_path
from ..core.logger import get_logger

logger = get_logger(__name__)


def run_checks(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """
    Run PII and privacy checks.

    Args:
        config: Project configuration
        project_root: Project root directory
        env: Environment name

    Returns:
        List of findings
    """
    findings: List[Finding] = []

    # Check 1: PII handling configuration
    findings.extend(_check_pii_config(config, project_root))

    # Check 2: Log scanning for PII (opt-in)
    if config.pii_config.scan_enabled and config.pii_config.scan_logs:
        findings.extend(_scan_logs_for_pii(config, project_root))

    # Check 3: Privacy policy presence
    findings.extend(_check_privacy_policy(config, project_root))

    return findings


def _check_pii_config(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check PII configuration."""
    findings = []

    if not config.pii_config.scan_enabled:
        findings.append(
            Finding(
                check_id="PII-001",
                title="PII Scanning Disabled",
                severity=Severity.INFO,
                status=Status.SKIP,
                category="pii_privacy",
                description="PII scanning is not enabled (opt-in)",
                evidence="pii_config.scan_enabled = false",
                remediation="Enable PII scanning in config to detect potential data leaks",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="PII-001",
                title="PII Scanning Enabled",
                severity=Severity.INFO,
                status=Status.PASS,
                category="pii_privacy",
                description=f"PII scanning is enabled (redaction: {config.pii_config.redaction_enabled})",
                evidence=f"Will scan up to {config.pii_config.scan_samples} lines per file",
                remediation="N/A",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _scan_logs_for_pii(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Scan log files for potential PII."""
    findings = []

    # Look for log files
    log_dirs = [
        project_root / "logs",
        project_root / "log",
        project_root / "var" / "log",
    ]

    log_files = []
    for log_dir in log_dirs:
        if log_dir.exists() and log_dir.is_dir():
            log_files.extend(log_dir.glob("*.log"))

    if not log_files:
        findings.append(
            Finding(
                check_id="PII-002",
                title="No Log Files Found",
                severity=Severity.INFO,
                status=Status.SKIP,
                category="pii_privacy",
                description="No log files found to scan",
                evidence="Checked: logs/, log/, var/log/",
                remediation="N/A",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
        return findings

    # Scan log files
    pii_found_total = False

    for log_file in log_files[:10]:  # Limit to 10 files
        result = scan_file_for_pii(
            log_file,
            max_lines=config.pii_config.scan_samples,
            patterns=config.pii_config.patterns,
            redact=config.pii_config.redaction_enabled,
        )

        if result.get("pii_found"):
            pii_found_total = True
            details = result.get("details", {})
            categories = [k for k, v in details.items() if v > 0]

            findings.append(
                Finding(
                    check_id=f"PII-003-{log_file.name}",
                    title=f"Potential PII in Log: {log_file.name}",
                    severity=Severity.HIGH,
                    status=Status.WARNING,
                    category="pii_privacy",
                    description=f"Found potential PII: {', '.join(categories)}",
                    evidence=f"File: {log_file.name}, Lines scanned: {result['lines_scanned']}",
                    remediation="Review logging code to avoid capturing PII. Implement log scrubbing.",
                    owasp_mapping=["LLM06"],
                    iso_mapping=["Clause_8"],
                )
            )

    if not pii_found_total:
        findings.append(
            Finding(
                check_id="PII-003",
                title="No PII Detected in Logs",
                severity=Severity.INFO,
                status=Status.PASS,
                category="pii_privacy",
                description=f"Scanned {len(log_files)} log files, no obvious PII found",
                evidence=f"Sampled {config.pii_config.scan_samples} lines per file",
                remediation="N/A",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_privacy_policy(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for privacy policy documentation."""
    findings = []

    if not config.policies.privacy:
        findings.append(
            Finding(
                check_id="PII-004",
                title="Privacy Policy Not Configured",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="pii_privacy",
                description="No privacy policy document configured",
                evidence="config.policies.privacy is not set",
                remediation="Create and configure privacy policy document",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        policy_path = resolve_path(project_root, config.policies.privacy)

        if policy_path and policy_path.exists():
            findings.append(
                Finding(
                    check_id="PII-004",
                    title="Privacy Policy Documented",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="pii_privacy",
                    description="Privacy policy is documented",
                    evidence=f"File: {policy_path}",
                    remediation="N/A",
                    owasp_mapping=["LLM06"],
                    iso_mapping=["Clause_8"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="PII-004",
                    title="Privacy Policy File Not Found",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    category="pii_privacy",
                    description="Privacy policy configured but file not found",
                    evidence=f"Path: {config.policies.privacy}",
                    remediation="Create privacy policy at specified path",
                    owasp_mapping=["LLM06"],
                    iso_mapping=["Clause_8"],
                )
            )

    return findings
