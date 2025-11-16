"""Data integrity checks for datasets and artifacts."""

from pathlib import Path
from typing import List, Dict, Any

from ..config.schema import ProjectConfig, Finding, Severity, Status
from ..core.utils import compute_file_hash, load_checksums, verify_file_hash
from ..core.loader import resolve_path


def run_checks(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """
    Run data integrity checks.

    Args:
        config: Project configuration
        project_root: Project root directory
        env: Environment name

    Returns:
        List of findings
    """
    findings: List[Finding] = []

    # Check 1: Dataset hash verification
    findings.extend(_check_dataset_hashes(config, project_root))

    # Check 2: Checksums file presence
    findings.extend(_check_checksums_file(config, project_root))

    # Check 3: Artifact integrity
    findings.extend(_check_artifact_integrity(config, project_root))

    return findings


def _check_dataset_hashes(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if datasets have documented hashes."""
    findings = []

    if not config.artifacts.datasets:
        findings.append(
            Finding(
                check_id="DATA-001",
                title="No Datasets Declared",
                severity=Severity.LOW,
                status=Status.WARNING,
                category="data_integrity",
                description="No datasets are declared in configuration",
                evidence="config.artifacts.datasets is empty",
                remediation="Add dataset references to configuration with paths and checksums",
                owasp_mapping=["LLM03"],
                iso_mapping=["Clause_8"],
            )
        )
        return findings

    # Check if checksums file exists
    checksums_path = resolve_path(project_root, config.artifacts.checksums)
    checksums = {}

    if checksums_path and checksums_path.exists():
        checksums = load_checksums(checksums_path)
        findings.append(
            Finding(
                check_id="DATA-002",
                title="Checksums File Found",
                severity=Severity.INFO,
                status=Status.PASS,
                category="data_integrity",
                description="Checksums file is present",
                evidence=f"Found at: {checksums_path}",
                remediation="N/A",
                owasp_mapping=["LLM03"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="DATA-002",
                title="Missing Checksums File",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                category="data_integrity",
                description="No checksums file found for dataset verification",
                evidence=f"Expected at: {config.artifacts.checksums or 'not specified'}",
                remediation="Create a checksums file with SHA256 hashes of all datasets",
                owasp_mapping=["LLM03"],
                iso_mapping=["Clause_8"],
            )
        )

    # Verify dataset file hashes if they exist
    for dataset_name, dataset_path in config.artifacts.datasets.items():
        resolved_path = resolve_path(project_root, dataset_path)

        if not resolved_path or not resolved_path.exists():
            findings.append(
                Finding(
                    check_id=f"DATA-003-{dataset_name}",
                    title=f"Dataset Not Found: {dataset_name}",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    category="data_integrity",
                    description=f"Dataset file does not exist: {dataset_name}",
                    evidence=f"Path: {dataset_path}",
                    remediation="Ensure dataset file exists at specified path",
                    owasp_mapping=["LLM03"],
                    iso_mapping=["Clause_8"],
                )
            )
            continue

        # Check if hash is documented
        if dataset_path in checksums:
            expected_hash = checksums[dataset_path]
            if verify_file_hash(resolved_path, expected_hash):
                findings.append(
                    Finding(
                        check_id=f"DATA-004-{dataset_name}",
                        title=f"Dataset Hash Verified: {dataset_name}",
                        severity=Severity.INFO,
                        status=Status.PASS,
                        category="data_integrity",
                        description=f"Dataset hash matches expected value",
                        evidence=f"SHA256: {expected_hash[:16]}...",
                        remediation="N/A",
                        owasp_mapping=["LLM03"],
                        iso_mapping=["Clause_8"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=f"DATA-004-{dataset_name}",
                        title=f"Dataset Hash Mismatch: {dataset_name}",
                        severity=Severity.CRITICAL,
                        status=Status.FAIL,
                        category="data_integrity",
                        description=f"Dataset hash does not match expected value - possible tampering",
                        evidence=f"File: {dataset_path}",
                        remediation="Investigate file integrity. Re-download or restore from backup.",
                        owasp_mapping=["LLM03"],
                        iso_mapping=["Clause_8"],
                    )
                )
        else:
            findings.append(
                Finding(
                    check_id=f"DATA-005-{dataset_name}",
                    title=f"Dataset Hash Not Documented: {dataset_name}",
                    severity=Severity.MEDIUM,
                    status=Status.WARNING,
                    category="data_integrity",
                    description=f"No checksum found for dataset",
                    evidence=f"File: {dataset_path}",
                    remediation="Add hash to checksums file for verification",
                    owasp_mapping=["LLM03"],
                    iso_mapping=["Clause_8"],
                )
            )

    return findings


def _check_checksums_file(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check checksums file format and completeness."""
    findings = []

    checksums_path = resolve_path(project_root, config.artifacts.checksums)

    if not checksums_path or not checksums_path.exists():
        return findings  # Already handled in previous check

    try:
        checksums = load_checksums(checksums_path)

        if not checksums:
            findings.append(
                Finding(
                    check_id="DATA-006",
                    title="Empty Checksums File",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    category="data_integrity",
                    description="Checksums file exists but contains no entries",
                    evidence=f"File: {checksums_path}",
                    remediation="Add checksums for all critical artifacts",
                    owasp_mapping=["LLM03"],
                    iso_mapping=["Clause_8"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="DATA-006",
                    title="Checksums File Valid",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="data_integrity",
                    description=f"Checksums file contains {len(checksums)} entries",
                    evidence=f"File: {checksums_path}",
                    remediation="N/A",
                    owasp_mapping=["LLM03"],
                    iso_mapping=["Clause_8"],
                )
            )

    except Exception as e:
        findings.append(
            Finding(
                check_id="DATA-007",
                title="Checksums File Parse Error",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="data_integrity",
                description="Failed to parse checksums file",
                evidence=f"Error: {str(e)}",
                remediation="Fix checksums file format. Expected: '<hash> <filename>' per line",
                owasp_mapping=["LLM03"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_artifact_integrity(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check integrity of model artifacts."""
    findings = []

    # Check model file
    if config.artifacts.model_path:
        model_path = resolve_path(project_root, config.artifacts.model_path)

        if model_path and model_path.exists():
            findings.append(
                Finding(
                    check_id="DATA-008",
                    title="Model Artifact Found",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="data_integrity",
                    description="Model file exists",
                    evidence=f"Path: {model_path}, Size: {model_path.stat().st_size} bytes",
                    remediation="N/A",
                    owasp_mapping=["LLM05"],
                    iso_mapping=["Clause_8"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="DATA-008",
                    title="Model Artifact Not Found",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    category="data_integrity",
                    description="Model file does not exist",
                    evidence=f"Path: {config.artifacts.model_path}",
                    remediation="Ensure model file exists at specified path",
                    owasp_mapping=["LLM05"],
                    iso_mapping=["Clause_8"],
                )
            )

    return findings
