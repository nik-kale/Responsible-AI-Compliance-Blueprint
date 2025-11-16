"""Model security checks for LLM10 - Model Theft."""

from pathlib import Path
from typing import List
import hashlib
import json

from ..config.schema import ProjectConfig, Finding, Severity, Status
from ..core.logger import get_logger
from ..core.utils import compute_file_hash

logger = get_logger(__name__)


def run_checks(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """
    Run model security checks.

    Covers:
    - OWASP LLM10: Model Theft
    - Model watermarking
    - Model fingerprinting
    - Extraction attack detection
    - Model access controls
    - Model versioning

    Args:
        config: Project configuration
        project_root: Root directory of the project
        env: Environment (dev/staging/prod)

    Returns:
        List of findings from model security checks
    """
    logger.info("Running model security checks")

    findings = []

    # MODEL-001: Model watermarking
    findings.extend(_check_model_watermarking(config, project_root))

    # MODEL-002: Model fingerprinting
    findings.extend(_check_model_fingerprinting(config, project_root))

    # MODEL-003: Extraction attack detection
    findings.extend(_check_extraction_detection(config, project_root, env))

    # MODEL-004: Model access controls
    findings.extend(_check_model_access_controls(config, project_root, env))

    # MODEL-005: Model versioning
    findings.extend(_check_model_versioning(config, project_root))

    # MODEL-006: Model registry security
    findings.extend(_check_model_registry_security(config, project_root))

    # MODEL-007: Query pattern monitoring
    findings.extend(_check_query_monitoring(config, project_root, env))

    # MODEL-008: Rate limiting for model inference
    findings.extend(_check_model_rate_limiting(config, project_root, env))

    # MODEL-009: Model output randomization
    findings.extend(_check_output_randomization(config, project_root, env))

    # MODEL-010: Model backup security
    findings.extend(_check_model_backup_security(config, project_root))

    logger.info(f"Model security checks complete: {len(findings)} findings")
    return findings


def _check_model_watermarking(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if model watermarking is implemented."""
    watermark_docs = [
        "docs/model_watermarking.md",
        "WATERMARKING.md",
        "watermark_config.json",
    ]

    watermark_exists = any((project_root / f).exists() for f in watermark_docs)

    # Check for watermarking code
    watermark_code_patterns = [
        "watermark",
        "trigger_set",
        "backdoor_defense",
    ]

    watermark_code_found = False
    if (project_root / "src").exists():
        for py_file in (project_root / "src").rglob("*.py"):
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                if any(pattern in content.lower() for pattern in watermark_code_patterns):
                    watermark_code_found = True
                    break
            except Exception as e:
                logger.warning(f"Error reading file {py_file}: {e}")

    if not watermark_exists and not watermark_code_found:
        return [
            Finding(
                check_id="MODEL-001",
                title="Model Watermarking Not Implemented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="Model Security",
                description="Model watermarking not found. Cannot verify model ownership or detect unauthorized copies.",
                evidence=f"Checked for: {', '.join(watermark_docs)}",
                remediation="Implement model watermarking:\n"
                           "1. Embed watermarks during training (trigger sets, adversarial examples)\n"
                           "2. Use output-based watermarking for inference-only access\n"
                           "3. Document watermarking methodology\n"
                           "4. Test watermark extraction and verification\n"
                           "5. Implement watermark detection API\n"
                           "6. Consider techniques: backdoor watermarks, out-of-distribution triggers\n"
                           "7. Balance watermark robustness vs. model performance",
                owasp_mapping=["LLM10"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="MODEL-001",
            title="Model Watermarking Found",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Model Security",
            description="Model watermarking documentation or implementation found.",
            evidence="Watermarking indicators found",
            remediation="Regularly test watermark robustness against removal attacks",
            owasp_mapping=["LLM10"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_model_fingerprinting(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if model fingerprinting is documented."""
    fingerprint_docs = [
        "docs/model_fingerprinting.md",
        "model_fingerprint.json",
        "FINGERPRINT.md",
    ]

    fingerprint_exists = any((project_root / f).exists() for f in fingerprint_docs)

    if not fingerprint_exists:
        return [
            Finding(
                check_id="MODEL-002",
                title="Model Fingerprinting Not Documented",
                severity=Severity.LOW,
                status=Status.WARNING,
                category="Model Security",
                description="No model fingerprinting found. Difficult to identify stolen model copies.",
                evidence=f"Checked for: {', '.join(fingerprint_docs)}",
                remediation="Implement model fingerprinting:\n"
                           "1. Create unique model fingerprints (architecture hash, weight patterns)\n"
                           "2. Document model characteristics (behavior signatures)\n"
                           "3. Use fingerprinting to identify stolen copies\n"
                           "4. Test fingerprint uniqueness and persistence\n"
                           "5. Monitor for fingerprint matches in wild\n"
                           "6. Consider API-based fingerprinting (query-response patterns)",
                owasp_mapping=["LLM10"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="MODEL-002",
            title="Model Fingerprinting Documented",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Model Security",
            description="Model fingerprinting documentation found.",
            evidence="Fingerprinting documentation exists",
            remediation="Regularly update fingerprints with model versions",
            owasp_mapping=["LLM10"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_extraction_detection(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """Check if extraction attack detection is implemented."""
    # Check configuration
    env_config = config.environments.get(env)
    if not env_config:
        return []

    extraction_detection = getattr(env_config, "extraction_detection", False)

    if not extraction_detection:
        severity = Severity.HIGH if env in ["prod", "production"] else Severity.MEDIUM
        return [
            Finding(
                check_id="MODEL-003",
                title="Extraction Attack Detection Not Configured",
                severity=severity,
                status=Status.FAIL,
                category="Model Security",
                description="No extraction attack detection found. Model may be stolen through repeated queries.",
                evidence=f"Environment: {env}, extraction_detection: false",
                remediation="Implement extraction attack detection:\n"
                           "1. Monitor query patterns (high frequency, sequential, systematic)\n"
                           "2. Detect adversarial query patterns\n"
                           "3. Track queries per user/IP over time\n"
                           "4. Alert on suspicious query behavior\n"
                           "5. Implement progressive rate limiting for suspicious users\n"
                           "6. Use CAPTCHA or human verification for suspicious patterns\n"
                           "7. Log and analyze extraction attempt indicators",
                owasp_mapping=["LLM10"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="MODEL-003",
            title="Extraction Attack Detection Configured",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Model Security",
            description="Extraction attack detection is enabled.",
            evidence=f"Environment: {env}, extraction_detection: true",
            remediation="Regularly review extraction detection alerts",
            owasp_mapping=["LLM10"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_model_access_controls(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """Check if model access controls are configured."""
    env_config = config.environments.get(env)
    if not env_config:
        return []

    # Check for authentication and authorization
    auth_required = getattr(env_config, "auth_required", False)
    model_access_control = getattr(env_config, "model_access_control", False)

    if not auth_required or not model_access_control:
        severity = Severity.HIGH if env in ["prod", "production"] else Severity.MEDIUM
        return [
            Finding(
                check_id="MODEL-004",
                title="Model Access Controls Insufficient",
                severity=severity,
                status=Status.FAIL,
                category="Model Security",
                description="Model access controls are not properly configured.",
                evidence=f"Environment: {env}, auth_required: {auth_required}, model_access_control: {model_access_control}",
                remediation="Implement model access controls:\n"
                           "1. Require authentication for all model access\n"
                           "2. Implement role-based access control (RBAC)\n"
                           "3. Use API keys with limited scopes\n"
                           "4. Track model access per user/organization\n"
                           "5. Implement usage quotas\n"
                           "6. Log all model access attempts\n"
                           "7. Revoke compromised credentials promptly",
                owasp_mapping=["LLM10", "LLM01"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="MODEL-004",
            title="Model Access Controls Configured",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Model Security",
            description="Model access controls are properly configured.",
            evidence=f"Environment: {env}, authentication and access control enabled",
            remediation="Regularly audit access control logs",
            owasp_mapping=["LLM10"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_model_versioning(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if model versioning is implemented."""
    # Check for version in project config
    model_version = getattr(config.project, "version", None)

    # Check for model registry or versioning system
    versioning_systems = [
        "mlflow",
        "model_registry.json",
        "models/versions.json",
        ".dvc",
    ]

    versioning_found = any((project_root / v).exists() for v in versioning_systems)

    # Check artifacts for version tracking
    if config.artifacts and config.artifacts.model_path:
        model_path = project_root / config.artifacts.model_path
        if model_path.exists() and model_path.is_dir():
            # Check for VERSION file or metadata
            version_files = list(model_path.glob("VERSION*")) + list(model_path.glob("*version*"))
            if version_files:
                versioning_found = True

    if not model_version and not versioning_found:
        return [
            Finding(
                check_id="MODEL-005",
                title="Model Versioning Not Implemented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="Model Security",
                description="Model versioning not found. Cannot track model changes or detect unauthorized modifications.",
                evidence="No version in config, no versioning system found",
                remediation="Implement model versioning:\n"
                           "1. Use semantic versioning for models (MAJOR.MINOR.PATCH)\n"
                           "2. Track model versions in registry (MLflow, DVC, etc.)\n"
                           "3. Store model checksums/hashes for each version\n"
                           "4. Document model changes in changelog\n"
                           "5. Implement model lineage tracking\n"
                           "6. Version model artifacts, configs, and code together\n"
                           "7. Use immutable model storage",
                owasp_mapping=["LLM10"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="MODEL-005",
            title="Model Versioning Implemented",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Model Security",
            description="Model versioning system found.",
            evidence=f"Version: {model_version or 'versioning system detected'}",
            remediation="Maintain comprehensive model version history",
            owasp_mapping=["LLM10"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_model_registry_security(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if model registry has security controls."""
    registry_configs = [
        "mlflow.yaml",
        "model_registry_config.yaml",
        ".mlflow",
    ]

    registry_exists = any((project_root / f).exists() for f in registry_configs)

    if registry_exists:
        # Check for security configuration
        registry_security_found = False

        for config_file in registry_configs:
            file_path = project_root / config_file
            if file_path.exists() and file_path.is_file():
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    if any(keyword in content.lower() for keyword in ["auth", "token", "password", "tls", "ssl"]):
                        registry_security_found = True
                        break
                except Exception as e:
                    logger.warning(f"Error reading registry config {file_path}: {e}")

        if not registry_security_found:
            return [
                Finding(
                    check_id="MODEL-006",
                    title="Model Registry Security Not Configured",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    category="Model Security",
                    description="Model registry found but security not configured. Models may be accessed or modified without authorization.",
                    evidence="Registry exists but no security configuration found",
                    remediation="Secure model registry:\n"
                               "1. Enable authentication for registry access\n"
                               "2. Use TLS/SSL for registry connections\n"
                               "3. Implement access control for model read/write\n"
                               "4. Audit all registry operations\n"
                               "5. Encrypt models at rest in registry\n"
                               "6. Use separate credentials for different environments\n"
                               "7. Regularly rotate registry credentials",
                    owasp_mapping=["LLM10"],
                    iso_mapping=["Clause_8"],
                )
            ]

        return [
            Finding(
                check_id="MODEL-006",
                title="Model Registry Security Configured",
                severity=Severity.INFO,
                status=Status.PASS,
                category="Model Security",
                description="Model registry has security configuration.",
                evidence="Registry security settings found",
                remediation="Regularly audit registry access logs",
                owasp_mapping=["LLM10"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="MODEL-006",
            title="No Model Registry Detected",
            severity=Severity.LOW,
            status=Status.WARNING,
            category="Model Security",
            description="No model registry detected. Consider using a centralized model registry.",
            evidence=f"Checked for: {', '.join(registry_configs)}",
            remediation="Implement model registry (MLflow, DVC, etc.) for better model management",
            owasp_mapping=["LLM10"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_query_monitoring(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """Check if query pattern monitoring is configured."""
    env_config = config.environments.get(env)
    if not env_config:
        return []

    query_monitoring = getattr(env_config, "query_monitoring", False)

    if not query_monitoring:
        severity = Severity.MEDIUM if env in ["prod", "production"] else Severity.LOW
        return [
            Finding(
                check_id="MODEL-007",
                title="Query Pattern Monitoring Not Configured",
                severity=severity,
                status=Status.WARNING,
                category="Model Security",
                description="Query pattern monitoring is not enabled. Cannot detect model extraction attempts.",
                evidence=f"Environment: {env}, query_monitoring: false",
                remediation="Implement query monitoring:\n"
                           "1. Log all inference queries with metadata\n"
                           "2. Track query frequency per user/session\n"
                           "3. Detect systematic or sequential query patterns\n"
                           "4. Monitor for adversarial example queries\n"
                           "5. Alert on anomalous query behavior\n"
                           "6. Analyze query distributions over time\n"
                           "7. Use ML to detect extraction patterns",
                owasp_mapping=["LLM10"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="MODEL-007",
            title="Query Pattern Monitoring Configured",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Model Security",
            description="Query pattern monitoring is enabled.",
            evidence=f"Environment: {env}, query_monitoring: true",
            remediation="Regularly analyze query patterns for anomalies",
            owasp_mapping=["LLM10"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_model_rate_limiting(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """Check if model-specific rate limiting is configured."""
    env_config = config.environments.get(env)
    if not env_config:
        return []

    rate_limiting = getattr(env_config, "rate_limiting", False)
    model_rate_limit = getattr(env_config, "model_rate_limit", None)

    if not rate_limiting and not model_rate_limit:
        severity = Severity.MEDIUM if env in ["prod", "production"] else Severity.LOW
        return [
            Finding(
                check_id="MODEL-008",
                title="Model Rate Limiting Not Configured",
                severity=severity,
                status=Status.WARNING,
                category="Model Security",
                description="Rate limiting not configured for model inference. Enables rapid model extraction.",
                evidence=f"Environment: {env}, rate_limiting: false",
                remediation="Implement model rate limiting:\n"
                           "1. Set query limits per user/IP (e.g., 100 queries/hour)\n"
                           "2. Implement progressive rate limiting for heavy users\n"
                           "3. Use token bucket or sliding window algorithms\n"
                           "4. Apply stricter limits for anonymous users\n"
                           "5. Increase limits for verified enterprise customers\n"
                           "6. Log rate limit violations\n"
                           "7. Temporarily block repeated violators",
                owasp_mapping=["LLM10", "LLM04"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="MODEL-008",
            title="Model Rate Limiting Configured",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Model Security",
            description="Rate limiting is configured for model inference.",
            evidence=f"Environment: {env}, rate limiting enabled",
            remediation="Monitor and adjust rate limits based on usage patterns",
            owasp_mapping=["LLM10"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_output_randomization(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """Check if output randomization is configured to prevent extraction."""
    env_config = config.environments.get(env)
    if not env_config:
        return []

    output_randomization = getattr(env_config, "output_randomization", False)
    temperature = getattr(env_config, "temperature", None)

    if not output_randomization and not temperature:
        return [
            Finding(
                check_id="MODEL-009",
                title="Output Randomization Not Configured",
                severity=Severity.LOW,
                status=Status.WARNING,
                category="Model Security",
                description="No output randomization configured. Deterministic outputs aid model extraction.",
                evidence=f"Environment: {env}, output_randomization: false, temperature: not set",
                remediation="Consider output randomization:\n"
                           "1. Add small amount of noise to outputs (temperature > 0)\n"
                           "2. Use sampling instead of greedy decoding\n"
                           "3. Randomly truncate or round numerical outputs\n"
                           "4. Add non-deterministic elements to responses\n"
                           "5. Balance randomization vs. output quality\n"
                           "6. Document randomization methodology\n"
                           "Note: May impact reproducibility and user experience",
                owasp_mapping=["LLM10"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="MODEL-009",
            title="Output Randomization Configured",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Model Security",
            description="Output randomization is configured.",
            evidence=f"Environment: {env}, randomization or temperature configured",
            remediation="Monitor impact on output quality",
            owasp_mapping=["LLM10"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_model_backup_security(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if model backups are secured."""
    backup_locations = [
        "backups/",
        "models/backups/",
        ".backup/",
    ]

    backup_found = any((project_root / loc).exists() for loc in backup_locations)

    if backup_found:
        # Check if backups are encrypted or access-controlled
        backup_security_docs = [
            "docs/backup_security.md",
            "BACKUP_POLICY.md",
        ]

        backup_security_documented = any((project_root / doc).exists() for doc in backup_security_docs)

        if not backup_security_documented:
            return [
                Finding(
                    check_id="MODEL-010",
                    title="Model Backup Security Not Documented",
                    severity=Severity.MEDIUM,
                    status=Status.WARNING,
                    category="Model Security",
                    description="Model backups found but security measures not documented.",
                    evidence="Backup directories exist but no security documentation",
                    remediation="Secure model backups:\n"
                               "1. Encrypt backups at rest\n"
                               "2. Use separate credentials for backup access\n"
                               "3. Implement access control on backup storage\n"
                               "4. Audit backup access regularly\n"
                               "5. Store backups in separate security zones\n"
                               "6. Document backup and restore procedures\n"
                               "7. Test backup integrity regularly",
                    owasp_mapping=["LLM10"],
                    iso_mapping=["Clause_8"],
                )
            ]

        return [
            Finding(
                check_id="MODEL-010",
                title="Model Backup Security Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="Model Security",
                description="Model backup security is documented.",
                evidence="Backup security documentation found",
                remediation="Regularly test backup security controls",
                owasp_mapping=["LLM10"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="MODEL-010",
            title="No Model Backups Detected",
            severity=Severity.LOW,
            status=Status.WARNING,
            category="Model Security",
            description="No model backup directories found. Consider implementing backup strategy.",
            evidence=f"Checked for: {', '.join(backup_locations)}",
            remediation="Implement secure model backup and recovery process",
            owasp_mapping=["LLM10"],
            iso_mapping=["Clause_8"],
        )
    ]
