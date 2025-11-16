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

    # Check 4: GDPR compliance documentation
    findings.extend(_check_gdpr_compliance(config, project_root))

    # Check 5: Consent management
    findings.extend(_check_consent_management(config, project_root))

    # Check 6: Data subject rights implementation
    findings.extend(_check_data_subject_rights(config, project_root))

    # Check 7: Privacy Impact Assessment (PIA/DPIA)
    findings.extend(_check_privacy_impact_assessment(config, project_root))

    # Check 8: Data retention policy
    findings.extend(_check_data_retention(config, project_root))

    # Check 9: Cross-border data transfer compliance
    findings.extend(_check_cross_border_transfers(config, project_root))

    # Check 10: Data minimization practices
    findings.extend(_check_data_minimization(config, project_root))

    # Check 11: Purpose limitation
    findings.extend(_check_purpose_limitation(config, project_root))

    # Check 12: Anonymization/Pseudonymization
    findings.extend(_check_anonymization(config, project_root))

    # Check 13: Breach notification procedures
    findings.extend(_check_breach_notification(config, project_root))

    # Check 14: Privacy by design
    findings.extend(_check_privacy_by_design(config, project_root))

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


def _check_gdpr_compliance(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for GDPR compliance documentation."""
    findings = []

    gdpr_docs = [
        "GDPR_COMPLIANCE.md",
        "docs/gdpr.md",
        "docs/gdpr_compliance.md",
        "GDPR.md",
    ]

    gdpr_exists = any((project_root / doc).exists() for doc in gdpr_docs)

    if not gdpr_exists:
        findings.append(
            Finding(
                check_id="PII-005",
                title="GDPR Compliance Not Documented",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="pii_privacy",
                description="No GDPR compliance documentation found. Required for EU data processing.",
                evidence=f"Checked for: {', '.join(gdpr_docs)}",
                remediation="Document GDPR compliance:\n"
                           "1. Legal basis for data processing (Art. 6)\n"
                           "2. Data protection principles (Art. 5)\n"
                           "3. Data subject rights implementation (Art. 12-23)\n"
                           "4. Data protection officer (if required)\n"
                           "5. Records of processing activities (Art. 30)\n"
                           "6. Data breach procedures (Art. 33-34)\n"
                           "7. Privacy by design and default (Art. 25)",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="PII-005",
                title="GDPR Compliance Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="pii_privacy",
                description="GDPR compliance documentation found.",
                evidence="Compliance documentation exists",
                remediation="Regularly review and update GDPR compliance",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_consent_management(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for consent management system."""
    findings = []

    consent_docs = [
        "docs/consent_management.md",
        "CONSENT.md",
        "consent_policy.md",
    ]

    consent_code_patterns = [
        "consent",
        "opt-in",
        "opt_in",
        "user_consent",
    ]

    consent_documented = any((project_root / doc).exists() for doc in consent_docs)
    consent_implemented = False

    # Check for consent management in code
    src_dir = project_root / "src"
    if src_dir.exists():
        for py_file in list(src_dir.rglob("*.py"))[:50]:  # Limit search
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore").lower()
                if any(pattern in content for pattern in consent_code_patterns):
                    consent_implemented = True
                    break
            except Exception as e:
                logger.warning(f"Error reading {py_file}: {e}")

    if not consent_documented and not consent_implemented:
        findings.append(
            Finding(
                check_id="PII-006",
                title="Consent Management Not Implemented",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="pii_privacy",
                description="No consent management system found. Required for GDPR compliance.",
                evidence="No consent documentation or implementation found",
                remediation="Implement consent management:\n"
                           "1. Obtain explicit consent before processing personal data\n"
                           "2. Document consent records (who, when, what, how)\n"
                           "3. Allow consent withdrawal at any time\n"
                           "4. Implement granular consent (per purpose)\n"
                           "5. Ensure consent is freely given, specific, informed\n"
                           "6. Store consent audit trail\n"
                           "7. Regularly review consent validity",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="PII-006",
                title="Consent Management Found",
                severity=Severity.INFO,
                status=Status.PASS,
                category="pii_privacy",
                description="Consent management system found.",
                evidence="Consent documentation or implementation detected",
                remediation="Ensure consent meets GDPR requirements",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_data_subject_rights(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for data subject rights implementation."""
    findings = []

    dsr_docs = [
        "docs/data_subject_rights.md",
        "DATA_SUBJECT_RIGHTS.md",
        "docs/user_rights.md",
    ]

    # Check for documentation
    dsr_documented = any((project_root / doc).exists() for doc in dsr_docs)

    # Check for key GDPR rights implementation
    rights = {
        "access": ["data_export", "user_data", "get_my_data"],
        "erasure": ["delete_user", "right_to_be_forgotten", "erase_data"],
        "portability": ["export_data", "download_data", "data_portability"],
        "rectification": ["update_user", "correct_data", "modify_data"],
    }

    implemented_rights = []
    src_dir = project_root / "src"

    if src_dir.exists():
        for right_name, patterns in rights.items():
            for py_file in list(src_dir.rglob("*.py"))[:30]:
                try:
                    content = py_file.read_text(encoding="utf-8", errors="ignore").lower()
                    if any(pattern in content for pattern in patterns):
                        implemented_rights.append(right_name)
                        break
                except Exception as e:
                    logger.warning(f"Error reading {py_file}: {e}")

    if not dsr_documented and len(implemented_rights) < 2:
        findings.append(
            Finding(
                check_id="PII-007",
                title="Data Subject Rights Not Implemented",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="pii_privacy",
                description="Data subject rights are not adequately implemented. Required by GDPR Art. 12-23.",
                evidence=f"Found {len(implemented_rights)}/4 rights implemented: {', '.join(implemented_rights) if implemented_rights else 'none'}",
                remediation="Implement GDPR data subject rights:\n"
                           "1. Right of access (Art. 15) - export user data\n"
                           "2. Right to erasure (Art. 17) - delete user data\n"
                           "3. Right to data portability (Art. 20) - machine-readable export\n"
                           "4. Right to rectification (Art. 16) - update inaccurate data\n"
                           "5. Right to restrict processing (Art. 18)\n"
                           "6. Right to object (Art. 21)\n"
                           "7. Document procedures for each right",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="PII-007",
                title="Data Subject Rights Implemented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="pii_privacy",
                description=f"Found {len(implemented_rights)} data subject rights implemented.",
                evidence=f"Rights: {', '.join(implemented_rights)}" if implemented_rights else "Documentation exists",
                remediation="Ensure all GDPR rights are fully functional",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_privacy_impact_assessment(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for Privacy Impact Assessment (PIA/DPIA)."""
    findings = []

    pia_docs = [
        "PIA.md",
        "DPIA.md",
        "docs/privacy_impact_assessment.md",
        "docs/data_protection_impact_assessment.md",
        "privacy_impact_assessment.md",
    ]

    pia_exists = any((project_root / doc).exists() for doc in pia_docs)

    if not pia_exists:
        findings.append(
            Finding(
                check_id="PII-008",
                title="Privacy Impact Assessment Not Found",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="pii_privacy",
                description="No Privacy/Data Protection Impact Assessment found. Required by GDPR Art. 35 for high-risk processing.",
                evidence=f"Checked for: {', '.join(pia_docs)}",
                remediation="Conduct Privacy Impact Assessment:\n"
                           "1. Describe data processing operations\n"
                           "2. Assess necessity and proportionality\n"
                           "3. Identify privacy risks to individuals\n"
                           "4. Document mitigation measures\n"
                           "5. Consult Data Protection Officer (if applicable)\n"
                           "6. Required for: profiling, automated decisions, large-scale processing\n"
                           "7. Review and update regularly",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="PII-008",
                title="Privacy Impact Assessment Found",
                severity=Severity.INFO,
                status=Status.PASS,
                category="pii_privacy",
                description="Privacy Impact Assessment documentation found.",
                evidence="PIA/DPIA documentation exists",
                remediation="Review PIA annually or when processing changes",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_data_retention(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for data retention policy."""
    findings = []

    retention_docs = [
        "DATA_RETENTION.md",
        "docs/data_retention.md",
        "docs/retention_policy.md",
        "RETENTION_POLICY.md",
    ]

    retention_exists = any((project_root / doc).exists() for doc in retention_docs)

    if not retention_exists:
        findings.append(
            Finding(
                check_id="PII-009",
                title="Data Retention Policy Not Documented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="pii_privacy",
                description="No data retention policy found. Required by GDPR storage limitation principle.",
                evidence=f"Checked for: {', '.join(retention_docs)}",
                remediation="Create data retention policy:\n"
                           "1. Define retention periods for each data category\n"
                           "2. Document legal/business justification\n"
                           "3. Implement automated deletion after retention period\n"
                           "4. Log all data deletions\n"
                           "5. Review retention periods annually\n"
                           "6. Ensure backups follow retention policy\n"
                           "7. Comply with GDPR storage limitation (Art. 5(1)(e))",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="PII-009",
                title="Data Retention Policy Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="pii_privacy",
                description="Data retention policy documentation found.",
                evidence="Retention policy exists",
                remediation="Ensure automated enforcement of retention policy",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_cross_border_transfers(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for cross-border data transfer compliance."""
    findings = []

    transfer_docs = [
        "docs/data_transfers.md",
        "CROSS_BORDER_TRANSFERS.md",
        "docs/international_transfers.md",
    ]

    transfer_exists = any((project_root / doc).exists() for doc in transfer_docs)

    if not transfer_exists:
        findings.append(
            Finding(
                check_id="PII-010",
                title="Cross-Border Transfer Policy Not Documented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="pii_privacy",
                description="No cross-border data transfer policy found. Required by GDPR Ch. V for international transfers.",
                evidence=f"Checked for: {', '.join(transfer_docs)}",
                remediation="Document cross-border data transfers:\n"
                           "1. Identify all international data transfers\n"
                           "2. Ensure adequacy decisions or safeguards (Art. 45-46)\n"
                           "3. Use Standard Contractual Clauses (SCCs) if needed\n"
                           "4. Conduct Transfer Impact Assessments\n"
                           "5. Document lawful transfer mechanisms\n"
                           "6. Comply with data localization requirements\n"
                           "7. Review post-Schrems II requirements",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="PII-010",
                title="Cross-Border Transfer Policy Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="pii_privacy",
                description="Cross-border data transfer policy found.",
                evidence="Transfer policy exists",
                remediation="Ensure SCCs are up to date (2021 version)",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_data_minimization(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for data minimization practices."""
    findings = []

    minimization_docs = [
        "docs/data_minimization.md",
        "DATA_MINIMIZATION.md",
        "docs/data_collection_policy.md",
    ]

    minimization_exists = any((project_root / doc).exists() for doc in minimization_docs)

    if not minimization_exists:
        findings.append(
            Finding(
                check_id="PII-011",
                title="Data Minimization Not Documented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="pii_privacy",
                description="Data minimization practices not documented. Required by GDPR Art. 5(1)(c).",
                evidence=f"Checked for: {', '.join(minimization_docs)}",
                remediation="Implement data minimization:\n"
                           "1. Collect only necessary data for stated purpose\n"
                           "2. Document why each data field is needed\n"
                           "3. Review data collection regularly\n"
                           "4. Remove unnecessary fields from forms\n"
                           "5. Limit data retention to minimum necessary\n"
                           "6. Implement data aggregation where possible\n"
                           "7. Document minimization decisions",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="PII-011",
                title="Data Minimization Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="pii_privacy",
                description="Data minimization practices documented.",
                evidence="Minimization documentation exists",
                remediation="Regularly audit data collection for necessity",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_purpose_limitation(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for purpose limitation documentation."""
    findings = []

    purpose_docs = [
        "docs/purpose_limitation.md",
        "docs/data_purposes.md",
        "PURPOSE_SPECIFICATION.md",
    ]

    purpose_exists = any((project_root / doc).exists() for doc in purpose_docs)

    if not purpose_exists:
        findings.append(
            Finding(
                check_id="PII-012",
                title="Purpose Limitation Not Documented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="pii_privacy",
                description="Purpose limitation not documented. Required by GDPR Art. 5(1)(b).",
                evidence=f"Checked for: {', '.join(purpose_docs)}",
                remediation="Document purpose limitation:\n"
                           "1. Specify purposes for data collection\n"
                           "2. Ensure purposes are explicit and legitimate\n"
                           "3. Prohibit incompatible further processing\n"
                           "4. Document purpose specification in privacy notice\n"
                           "5. Obtain new consent for new purposes\n"
                           "6. Implement purpose-based access controls\n"
                           "7. Audit data use against stated purposes",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="PII-012",
                title="Purpose Limitation Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="pii_privacy",
                description="Purpose limitation documentation found.",
                evidence="Purpose documentation exists",
                remediation="Ensure all data use matches stated purposes",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_anonymization(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for anonymization/pseudonymization implementation."""
    findings = []

    anon_docs = [
        "docs/anonymization.md",
        "docs/pseudonymization.md",
        "ANONYMIZATION.md",
    ]

    anon_code_patterns = [
        "anonymize",
        "pseudonymize",
        "hash_pii",
        "tokenize",
        "de-identify",
    ]

    anon_documented = any((project_root / doc).exists() for doc in anon_docs)
    anon_implemented = False

    # Check for anonymization in code
    src_dir = project_root / "src"
    if src_dir.exists():
        for py_file in list(src_dir.rglob("*.py"))[:30]:
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore").lower()
                if any(pattern in content for pattern in anon_code_patterns):
                    anon_implemented = True
                    break
            except Exception as e:
                logger.warning(f"Error reading {py_file}: {e}")

    if not anon_documented and not anon_implemented:
        findings.append(
            Finding(
                check_id="PII-013",
                title="Anonymization/Pseudonymization Not Implemented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="pii_privacy",
                description="No anonymization or pseudonymization found. Recommended by GDPR Art. 25, 32.",
                evidence="No anonymization documentation or implementation found",
                remediation="Implement anonymization/pseudonymization:\n"
                           "1. Pseudonymize data where possible (reversible)\n"
                           "2. Anonymize data for analytics (irreversible)\n"
                           "3. Use techniques: hashing, tokenization, masking, generalization\n"
                           "4. Document anonymization methods\n"
                           "5. Ensure anonymization is effective (re-identification risk)\n"
                           "6. Apply to training data, logs, analytics\n"
                           "7. Regular re-identification risk assessment",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="PII-013",
                title="Anonymization/Pseudonymization Found",
                severity=Severity.INFO,
                status=Status.PASS,
                category="pii_privacy",
                description="Anonymization or pseudonymization found.",
                evidence="Anonymization documentation or implementation detected",
                remediation="Test effectiveness against re-identification attacks",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_breach_notification(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for data breach notification procedures."""
    findings = []

    breach_docs = [
        "docs/breach_notification.md",
        "BREACH_RESPONSE.md",
        "docs/incident_response.md",
        "SECURITY_INCIDENT.md",
    ]

    breach_exists = any((project_root / doc).exists() for doc in breach_docs)

    if not breach_exists:
        findings.append(
            Finding(
                check_id="PII-014",
                title="Breach Notification Procedures Not Documented",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="pii_privacy",
                description="No data breach notification procedures found. Required by GDPR Art. 33-34.",
                evidence=f"Checked for: {', '.join(breach_docs)}",
                remediation="Document breach notification procedures:\n"
                           "1. 72-hour notification to supervisory authority (Art. 33)\n"
                           "2. Notification to affected individuals if high risk (Art. 34)\n"
                           "3. Maintain breach register\n"
                           "4. Define breach detection and assessment process\n"
                           "5. Establish incident response team\n"
                           "6. Document notification templates\n"
                           "7. Regular breach simulation exercises",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="PII-014",
                title="Breach Notification Procedures Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="pii_privacy",
                description="Data breach notification procedures found.",
                evidence="Breach response documentation exists",
                remediation="Test breach procedures annually",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_privacy_by_design(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for privacy by design implementation."""
    findings = []

    pbd_docs = [
        "docs/privacy_by_design.md",
        "PRIVACY_BY_DESIGN.md",
        "docs/privacy_engineering.md",
    ]

    pbd_exists = any((project_root / doc).exists() for doc in pbd_docs)

    if not pbd_exists:
        findings.append(
            Finding(
                check_id="PII-015",
                title="Privacy by Design Not Documented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="pii_privacy",
                description="Privacy by design principles not documented. Required by GDPR Art. 25.",
                evidence=f"Checked for: {', '.join(pbd_docs)}",
                remediation="Implement privacy by design:\n"
                           "1. Privacy as default setting\n"
                           "2. Privacy embedded into design\n"
                           "3. Full functionality (positive-sum, not zero-sum)\n"
                           "4. End-to-end security (lifecycle protection)\n"
                           "5. Visibility and transparency\n"
                           "6. Respect for user privacy\n"
                           "7. Proactive not reactive privacy",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="PII-015",
                title="Privacy by Design Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="pii_privacy",
                description="Privacy by design documentation found.",
                evidence="Privacy by design documentation exists",
                remediation="Ensure privacy by design in all new features",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings
