"""Model artifact checks for completeness and security."""

from pathlib import Path
from typing import List

from ..config.schema import ProjectConfig, Finding, Severity, Status
from ..core.loader import load_model_card, resolve_path
from ..core.utils import check_dangerous_patterns, compute_file_hash


def run_checks(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """
    Run model artifact checks.

    Args:
        config: Project configuration
        project_root: Project root directory
        env: Environment name

    Returns:
        List of findings
    """
    findings: List[Finding] = []

    # Check 1: Model card presence and completeness
    findings.extend(_check_model_card(config, project_root))

    # Check 2: Reproducible build hash
    findings.extend(_check_reproducibility(config, project_root))

    # Check 3: Secret detection
    findings.extend(_check_secrets(config, project_root))

    # Check 4: Serialization safety
    findings.extend(_check_serialization_safety(config, project_root))

    return findings


def _check_model_card(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check model card presence and completeness."""
    findings = []

    if not config.artifacts.model_card:
        findings.append(
            Finding(
                check_id="MODEL-001",
                title="Model Card Not Configured",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="model_artifacts",
                description="No model card specified in configuration",
                evidence="config.artifacts.model_card is not set",
                remediation="Add model_card path to configuration and create documentation",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_8"],
            )
        )
        return findings

    model_card_path = resolve_path(project_root, config.artifacts.model_card)

    if not model_card_path or not model_card_path.exists():
        findings.append(
            Finding(
                check_id="MODEL-002",
                title="Model Card File Not Found",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="model_artifacts",
                description="Model card file does not exist",
                evidence=f"Path: {config.artifacts.model_card}",
                remediation="Create model card with required documentation",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_8"],
            )
        )
        return findings

    # Load and check completeness
    try:
        model_card = load_model_card(model_card_path)

        if not model_card:
            findings.append(
                Finding(
                    check_id="MODEL-003",
                    title="Model Card Empty",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    category="model_artifacts",
                    description="Model card file is empty or invalid",
                    evidence=f"Path: {model_card_path}",
                    remediation="Populate model card with required fields",
                    owasp_mapping=["LLM09"],
                    iso_mapping=["Clause_8"],
                )
            )
            return findings

        # Check required fields
        required_fields = {
            "model_name": model_card.model_name,
            "version": model_card.version,
            "intended_use": model_card.intended_use,
            "limitations": model_card.limitations,
        }

        missing_fields = [k for k, v in required_fields.items() if not v]

        if missing_fields:
            findings.append(
                Finding(
                    check_id="MODEL-004",
                    title="Model Card Incomplete",
                    severity=Severity.MEDIUM,
                    status=Status.WARNING,
                    category="model_artifacts",
                    description=f"Model card missing required fields: {', '.join(missing_fields)}",
                    evidence=f"Path: {model_card_path}",
                    remediation=f"Add missing fields: {', '.join(missing_fields)}",
                    owasp_mapping=["LLM09"],
                    iso_mapping=["Clause_8"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="MODEL-004",
                    title="Model Card Complete",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="model_artifacts",
                    description="Model card contains all required fields",
                    evidence=f"Path: {model_card_path}",
                    remediation="N/A",
                    owasp_mapping=["LLM09"],
                    iso_mapping=["Clause_8"],
                )
            )

        # Check for bias considerations
        if not model_card.bias_considerations:
            findings.append(
                Finding(
                    check_id="MODEL-005",
                    title="Missing Bias Considerations",
                    severity=Severity.MEDIUM,
                    status=Status.WARNING,
                    category="model_artifacts",
                    description="Model card does not document bias considerations",
                    evidence="bias_considerations field is empty",
                    remediation="Add bias analysis and mitigation strategies",
                    owasp_mapping=["LLM09"],
                    iso_mapping=["Clause_8"],
                )
            )

    except Exception as e:
        findings.append(
            Finding(
                check_id="MODEL-006",
                title="Model Card Parse Error",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="model_artifacts",
                description="Failed to parse model card",
                evidence=f"Error: {str(e)}",
                remediation="Fix model card YAML syntax",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_reproducibility(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for reproducible build artifacts."""
    findings = []

    if not config.artifacts.model_path:
        return findings

    model_path = resolve_path(project_root, config.artifacts.model_path)

    if not model_path or not model_path.exists():
        return findings  # Already flagged elsewhere

    # Check if model hash is documented
    checksums_path = resolve_path(project_root, config.artifacts.checksums)

    if not checksums_path or not checksums_path.exists():
        findings.append(
            Finding(
                check_id="MODEL-007",
                title="Model Hash Not Documented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="model_artifacts",
                description="Model artifact hash is not documented for reproducibility",
                evidence=f"Model: {config.artifacts.model_path}",
                remediation="Add model hash to checksums file for reproducibility verification",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="MODEL-007",
                title="Checksums File Present",
                severity=Severity.INFO,
                status=Status.PASS,
                category="model_artifacts",
                description="Checksums file available for reproducibility checks",
                evidence=f"File: {checksums_path}",
                remediation="N/A",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_secrets(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for hardcoded secrets in artifacts."""
    findings = []

    # Check common config files for secrets
    files_to_check = []

    if config.artifacts.model_path:
        # Don't scan binary model files, but check associated configs
        pass

    if config.artifacts.tokenizer:
        tokenizer_path = resolve_path(project_root, config.artifacts.tokenizer)
        if tokenizer_path and tokenizer_path.exists() and tokenizer_path.suffix == ".json":
            files_to_check.append(("tokenizer", tokenizer_path))

    if config.artifacts.preprocessor:
        prep_path = resolve_path(project_root, config.artifacts.preprocessor)
        if prep_path and prep_path.exists():
            files_to_check.append(("preprocessor", prep_path))

    if not files_to_check:
        findings.append(
            Finding(
                check_id="MODEL-008",
                title="Secret Scan Skipped",
                severity=Severity.INFO,
                status=Status.SKIP,
                category="model_artifacts",
                description="No text-based artifacts to scan for secrets",
                evidence="Only binary model files present",
                remediation="N/A",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
        return findings

    secrets_found = False

    for file_type, file_path in files_to_check:
        dangerous = check_dangerous_patterns(file_path)

        if dangerous:
            secrets_found = True
            patterns = [d["pattern"] for d in dangerous]
            findings.append(
                Finding(
                    check_id=f"MODEL-009-{file_type}",
                    title=f"Potential Secrets in {file_type.title()}",
                    severity=Severity.CRITICAL,
                    status=Status.FAIL,
                    category="model_artifacts",
                    description=f"Detected potential hardcoded secrets: {', '.join(set(patterns))}",
                    evidence=f"File: {file_path}",
                    remediation="Remove hardcoded secrets. Use environment variables or secret management.",
                    owasp_mapping=["LLM06"],
                    iso_mapping=["Clause_8"],
                )
            )

    if not secrets_found:
        findings.append(
            Finding(
                check_id="MODEL-009",
                title="No Secrets Detected",
                severity=Severity.INFO,
                status=Status.PASS,
                category="model_artifacts",
                description="No obvious secrets found in scanned artifacts",
                evidence=f"Scanned {len(files_to_check)} files",
                remediation="N/A",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_serialization_safety(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for unsafe serialization formats."""
    findings = []

    if not config.artifacts.model_path:
        return findings

    model_path_str = config.artifacts.model_path.lower()

    # Check for pickle files (unsafe)
    if model_path_str.endswith((".pkl", ".pickle")):
        findings.append(
            Finding(
                check_id="MODEL-010",
                title="Unsafe Pickle Serialization Detected",
                severity=Severity.HIGH,
                status=Status.WARNING,
                category="model_artifacts",
                description="Model uses pickle format, which is vulnerable to arbitrary code execution",
                evidence=f"File: {config.artifacts.model_path}",
                remediation="Consider using safer formats like SafeTensors, ONNX, or HDF5",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
                references=[
                    "https://huggingface.co/docs/safetensors/index",
                ],
            )
        )
    elif model_path_str.endswith(".safetensors"):
        findings.append(
            Finding(
                check_id="MODEL-010",
                title="Safe Serialization Format",
                severity=Severity.INFO,
                status=Status.PASS,
                category="model_artifacts",
                description="Model uses SafeTensors format",
                evidence=f"File: {config.artifacts.model_path}",
                remediation="N/A",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="MODEL-010",
                title="Model Serialization Format",
                severity=Severity.INFO,
                status=Status.PASS,
                category="model_artifacts",
                description=f"Model format: {Path(config.artifacts.model_path).suffix}",
                evidence=f"File: {config.artifacts.model_path}",
                remediation="Ensure format is from trusted source and properly validated",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings
