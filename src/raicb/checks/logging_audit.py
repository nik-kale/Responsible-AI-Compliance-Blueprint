"""Logging and audit trail checks."""

from pathlib import Path
from typing import List
import os

from ..config.schema import ProjectConfig, Finding, Severity, Status
from ..core.logger import get_logger

logger = get_logger(__name__)


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

    # Check 5: Audit log completeness
    findings.extend(_check_audit_completeness(config, project_root))

    # Check 6: SIEM integration
    findings.extend(_check_siem_integration(config, project_root))

    # Check 7: Prediction/Inference logging
    findings.extend(_check_prediction_logging(config, project_root))

    # Check 8: Security event logging
    findings.extend(_check_security_event_logging(config, project_root))

    # Check 9: Log retention compliance
    findings.extend(_check_log_retention_compliance(config, project_root))

    # Check 10: Centralized logging
    findings.extend(_check_centralized_logging(config, project_root))

    # Check 11: Log access controls
    findings.extend(_check_log_access_controls(project_root))

    # Check 12: Audit trail immutability
    findings.extend(_check_audit_immutability(project_root))

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


def _check_audit_completeness(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if all critical events are logged."""
    findings = []

    audit_policy_docs = [
        "docs/audit_policy.md",
        "AUDIT_POLICY.md",
        "docs/logging_requirements.md",
    ]

    # Critical events that should be logged
    critical_events = [
        "authentication",
        "authorization",
        "data_access",
        "model_inference",
        "configuration_change",
        "security_event",
    ]

    audit_policy_exists = any((project_root / doc).exists() for doc in audit_policy_docs)

    # Check code for logging of critical events
    logged_events = []
    src_dir = project_root / "src"

    if src_dir.exists():
        for py_file in list(src_dir.rglob("*.py"))[:50]:
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore").lower()
                for event in critical_events:
                    if f"log" in content and event in content:
                        if event not in logged_events:
                            logged_events.append(event)
            except Exception as e:
                logger.warning(f"Error reading {py_file}: {e}")

    if not audit_policy_exists and len(logged_events) < 3:
        findings.append(
            Finding(
                check_id="LOG-005",
                title="Incomplete Audit Logging",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="logging_audit",
                description=f"Critical events may not be fully logged. Found {len(logged_events)}/6 event types.",
                evidence=f"Logged events: {', '.join(logged_events) if logged_events else 'none detected'}",
                remediation="Implement comprehensive audit logging:\n"
                           "1. Log all authentication attempts (success/failure)\n"
                           "2. Log authorization decisions\n"
                           "3. Log all data access (who, what, when)\n"
                           "4. Log model inference requests and responses\n"
                           "5. Log configuration changes\n"
                           "6. Log security events (rate limits, validations)\n"
                           "7. Include user ID, timestamp, action, result in all logs",
                owasp_mapping=["LLM06", "LLM01"],
                iso_mapping=["Clause_9"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="LOG-005",
                title="Audit Logging Appears Complete",
                severity=Severity.INFO,
                status=Status.PASS,
                category="logging_audit",
                description=f"Found {len(logged_events)} critical event types being logged.",
                evidence=f"Events: {', '.join(logged_events) if logged_events else 'policy documented'}",
                remediation="Regularly review audit logs for completeness",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )

    return findings


def _check_siem_integration(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for SIEM (Security Information and Event Management) integration."""
    findings = []

    siem_indicators = [
        "splunk",
        "elasticsearch",
        "logstash",
        "fluentd",
        "datadog",
        "sumo",
        "siem",
    ]

    siem_configs = [
        "filebeat.yml",
        "fluent.conf",
        "logstash.conf",
        "siem_config.yml",
    ]

    siem_config_found = any((project_root / cfg).exists() for cfg in siem_configs)
    siem_code_found = False

    # Check requirements for SIEM libraries
    req_file = project_root / "requirements.txt"
    if req_file.exists():
        try:
            content = req_file.read_text(encoding="utf-8").lower()
            if any(indicator in content for indicator in siem_indicators):
                siem_code_found = True
        except Exception as e:
            logger.warning(f"Error reading requirements.txt: {e}")

    if not siem_config_found and not siem_code_found:
        findings.append(
            Finding(
                check_id="LOG-006",
                title="No SIEM Integration Found",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="logging_audit",
                description="No SIEM integration detected. Centralized security monitoring not configured.",
                evidence=f"Checked for: {', '.join(siem_configs)}",
                remediation="Integrate with SIEM platform:\n"
                           "1. Use Splunk, ELK Stack, or Datadog for log aggregation\n"
                           "2. Configure log shipping (Filebeat, Fluentd, etc.)\n"
                           "3. Set up alerts for security events\n"
                           "4. Create dashboards for monitoring\n"
                           "5. Implement correlation rules\n"
                           "6. Configure retention policies\n"
                           "7. Test alert notifications",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="LOG-006",
                title="SIEM Integration Found",
                severity=Severity.INFO,
                status=Status.PASS,
                category="logging_audit",
                description="SIEM integration detected.",
                evidence="SIEM configuration or integration found",
                remediation="Regularly review SIEM alerts and dashboards",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )

    return findings


def _check_prediction_logging(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if model predictions/inferences are logged."""
    findings = []

    prediction_log_patterns = [
        "prediction_log",
        "inference_log",
        "model_output",
        "log_prediction",
    ]

    prediction_logging_found = False
    src_dir = project_root / "src"

    if src_dir.exists():
        for py_file in list(src_dir.rglob("*.py"))[:40]:
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore").lower()
                if any(pattern in content for pattern in prediction_log_patterns):
                    prediction_logging_found = True
                    break
            except Exception as e:
                logger.warning(f"Error reading {py_file}: {e}")

    if not prediction_logging_found:
        findings.append(
            Finding(
                check_id="LOG-007",
                title="Prediction Logging Not Implemented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="logging_audit",
                description="Model predictions/inferences are not being logged. Critical for model monitoring and auditing.",
                evidence="No prediction logging patterns found in code",
                remediation="Implement prediction logging:\n"
                           "1. Log all model inputs and outputs\n"
                           "2. Include timestamp, user ID, model version\n"
                           "3. Log confidence scores\n"
                           "4. Store request IDs for traceability\n"
                           "5. Implement sampling for high-volume scenarios\n"
                           "6. Use structured logging (JSON)\n"
                           "7. Enable prediction drift detection",
                owasp_mapping=["LLM10", "LLM09"],
                iso_mapping=["Clause_9"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="LOG-007",
                title="Prediction Logging Implemented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="logging_audit",
                description="Model predictions appear to be logged.",
                evidence="Prediction logging patterns found in code",
                remediation="Ensure all predictions are logged with sufficient detail",
                owasp_mapping=["LLM10"],
                iso_mapping=["Clause_9"],
            )
        )

    return findings


def _check_security_event_logging(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if security events are logged."""
    findings = []

    security_event_patterns = [
        "security_event",
        "suspicious_activity",
        "blocked_request",
        "rate_limit",
        "validation_failed",
        "unauthorized",
    ]

    security_logging_count = 0
    src_dir = project_root / "src"

    if src_dir.exists():
        for py_file in list(src_dir.rglob("*.py"))[:40]:
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore").lower()
                for pattern in security_event_patterns:
                    if "log" in content and pattern in content:
                        security_logging_count += 1
                        break
            except Exception as e:
                logger.warning(f"Error reading {py_file}: {e}")

    if security_logging_count < 2:
        findings.append(
            Finding(
                check_id="LOG-008",
                title="Security Event Logging Insufficient",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="logging_audit",
                description="Security events may not be adequately logged.",
                evidence=f"Found minimal security event logging patterns",
                remediation="Implement security event logging:\n"
                           "1. Log all authentication failures\n"
                           "2. Log authorization denials\n"
                           "3. Log rate limiting triggers\n"
                           "4. Log input validation failures\n"
                           "5. Log suspicious patterns (SQL injection attempts, etc.)\n"
                           "6. Log blocked requests\n"
                           "7. Alert on critical security events",
                owasp_mapping=["LLM01", "LLM06"],
                iso_mapping=["Clause_9"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="LOG-008",
                title="Security Event Logging Implemented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="logging_audit",
                description="Security events appear to be logged.",
                evidence="Security logging patterns found",
                remediation="Regularly review security event logs",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )

    return findings


def _check_log_retention_compliance(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check log retention policy compliance."""
    findings = []

    retention_docs = [
        "docs/log_retention.md",
        "LOG_RETENTION.md",
        "docs/retention_policy.md",
    ]

    retention_exists = any((project_root / doc).exists() for doc in retention_docs)

    # Check for automated retention enforcement
    retention_code_patterns = [
        "log_retention",
        "rotate",
        "delete_old_logs",
        "cleanup_logs",
    ]

    retention_automated = False
    src_dir = project_root / "src"

    if src_dir.exists():
        for py_file in list(src_dir.rglob("*.py"))[:30]:
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore").lower()
                if any(pattern in content for pattern in retention_code_patterns):
                    retention_automated = True
                    break
            except Exception as e:
                logger.warning(f"Error reading {py_file}: {e}")

    if not retention_exists and not retention_automated:
        findings.append(
            Finding(
                check_id="LOG-009",
                title="Log Retention Policy Not Defined",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="logging_audit",
                description="No log retention policy found. May violate compliance requirements.",
                evidence=f"Checked for: {', '.join(retention_docs)}",
                remediation="Define log retention policy:\n"
                           "1. Specify retention periods (e.g., 90 days, 1 year, 7 years)\n"
                           "2. Comply with regulatory requirements (GDPR, SOX, HIPAA, etc.)\n"
                           "3. Automate log archival\n"
                           "4. Implement secure deletion after retention period\n"
                           "5. Document retention justification\n"
                           "6. Test restore procedures\n"
                           "7. Encrypt archived logs",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="LOG-009",
                title="Log Retention Policy Defined",
                severity=Severity.INFO,
                status=Status.PASS,
                category="logging_audit",
                description="Log retention policy documented or automated.",
                evidence="Retention policy or automation found",
                remediation="Regularly audit retention compliance",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )

    return findings


def _check_centralized_logging(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for centralized logging configuration."""
    findings = []

    centralized_indicators = [
        "logging_config.yml",
        "logging.conf",
        "log_config.json",
        "centralized_logging.py",
    ]

    centralized_found = any((project_root / ind).exists() for ind in centralized_indicators)

    # Check for logging configuration in code
    if not centralized_found:
        src_dir = project_root / "src"
        if src_dir.exists():
            for py_file in list(src_dir.rglob("*logging*.py"))[:5]:
                if py_file.exists():
                    centralized_found = True
                    break

    if not centralized_found:
        findings.append(
            Finding(
                check_id="LOG-010",
                title="Centralized Logging Not Configured",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="logging_audit",
                description="No centralized logging configuration found. Logs may be inconsistent.",
                evidence=f"Checked for: {', '.join(centralized_indicators)}",
                remediation="Implement centralized logging:\n"
                           "1. Create central logging configuration\n"
                           "2. Use consistent log formats (JSON recommended)\n"
                           "3. Include standard fields (timestamp, level, user, action)\n"
                           "4. Configure all modules to use central logger\n"
                           "5. Set appropriate log levels per environment\n"
                           "6. Route logs to central collection point\n"
                           "7. Use structured logging libraries",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="LOG-010",
                title="Centralized Logging Configured",
                severity=Severity.INFO,
                status=Status.PASS,
                category="logging_audit",
                description="Centralized logging configuration found.",
                evidence="Logging configuration exists",
                remediation="Ensure all modules use centralized logger",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )

    return findings


def _check_log_access_controls(project_root: Path) -> List[Finding]:
    """Check if log files have appropriate access controls."""
    findings = []

    log_dirs = [
        project_root / "logs",
        project_root / "log",
    ]

    access_issues = []

    for log_dir in log_dirs:
        if log_dir.exists() and log_dir.is_dir():
            try:
                # Check directory permissions (should be restricted)
                stat_info = log_dir.stat()
                mode = oct(stat_info.st_mode)[-3:]

                # Warn if world-readable (last digit > 0)
                if mode[-1] != '0':
                    access_issues.append(f"{log_dir.name}: world-readable ({mode})")

                # Check for log files
                for log_file in list(log_dir.glob("*.log"))[:5]:
                    file_stat = log_file.stat()
                    file_mode = oct(file_stat.st_mode)[-3:]

                    if file_mode[-1] != '0':
                        access_issues.append(f"{log_file.name}: world-readable ({file_mode})")

            except Exception as e:
                logger.warning(f"Error checking permissions for {log_dir}: {e}")

    if access_issues:
        findings.append(
            Finding(
                check_id="LOG-011",
                title="Log Access Control Issues",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="logging_audit",
                description=f"Found {len(access_issues)} log access control issues.",
                evidence="; ".join(access_issues[:3]),
                remediation="Restrict log file access:\n"
                           "1. Set log directory permissions to 750 or 700\n"
                           "2. Set log file permissions to 640 or 600\n"
                           "3. Ensure only authorized users can read logs\n"
                           "4. Use ACLs for fine-grained control\n"
                           "5. Implement log access auditing\n"
                           "6. Rotate credentials for log access\n"
                           "7. Never expose logs via web without authentication",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="LOG-011",
                title="Log Access Controls Appropriate",
                severity=Severity.INFO,
                status=Status.PASS,
                category="logging_audit",
                description="Log access controls appear appropriate.",
                evidence="No world-readable log files detected",
                remediation="Regularly audit log access permissions",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )

    return findings


def _check_audit_immutability(project_root: Path) -> List[Finding]:
    """Check for audit trail immutability mechanisms."""
    findings = []

    immutability_indicators = [
        "write_once",
        "append_only",
        "immutable",
        "blockchain",
        "merkle",
    ]

    immutability_docs = [
        "docs/audit_immutability.md",
        "docs/log_immutability.md",
    ]

    immutability_doc_found = any((project_root / doc).exists() for doc in immutability_docs)
    immutability_code_found = False

    # Check for immutability implementation
    src_dir = project_root / "src"
    if src_dir.exists():
        for py_file in list(src_dir.rglob("*.py"))[:30]:
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore").lower()
                if any(indicator in content for indicator in immutability_indicators):
                    immutability_code_found = True
                    break
            except Exception as e:
                logger.warning(f"Error reading {py_file}: {e}")

    if not immutability_doc_found and not immutability_code_found:
        findings.append(
            Finding(
                check_id="LOG-012",
                title="Audit Trail Immutability Not Implemented",
                severity=Severity.LOW,
                status=Status.WARNING,
                category="logging_audit",
                description="No audit trail immutability mechanisms found. Logs may be tampered with.",
                evidence="No immutability indicators found",
                remediation="Implement audit trail immutability:\n"
                           "1. Use append-only logging\n"
                           "2. Implement write-once-read-many (WORM) storage\n"
                           "3. Use cryptographic hashing (Merkle trees)\n"
                           "4. Consider blockchain for critical audit trails\n"
                           "5. Implement log signing\n"
                           "6. Use dedicated audit log storage\n"
                           "7. Regular integrity verification",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="LOG-012",
                title="Audit Trail Immutability Implemented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="logging_audit",
                description="Audit trail immutability mechanisms found.",
                evidence="Immutability implementation or documentation detected",
                remediation="Regularly verify log integrity",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_9"],
            )
        )

    return findings
