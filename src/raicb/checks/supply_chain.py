"""Supply chain security checks for dependencies and provenance."""

import json
import subprocess
from pathlib import Path
from typing import List, Optional

from ..config.schema import ProjectConfig, Finding, Severity, Status
from ..core.loader import resolve_path


def run_checks(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """
    Run supply chain security checks.

    Args:
        config: Project configuration
        project_root: Project root directory
        env: Environment name

    Returns:
        List of findings
    """
    findings: List[Finding] = []

    # Check 1: Dependencies file presence
    findings.extend(_check_dependencies_file(config, project_root))

    # Check 2: Run pip-audit for known vulnerabilities
    findings.extend(_check_vulnerabilities(config, project_root))

    # Check 3: License compliance (basic check)
    findings.extend(_check_licenses(config, project_root))

    # Check 4: Model provenance
    findings.extend(_check_model_provenance(config, project_root))

    return findings


def _check_dependencies_file(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for dependencies documentation."""
    findings = []

    if not config.artifacts.dependencies:
        # Look for common dependency files
        common_files = ["requirements.txt", "pyproject.toml", "Pipfile", "environment.yml"]
        found_files = [f for f in common_files if (project_root / f).exists()]

        if found_files:
            findings.append(
                Finding(
                    check_id="SUPPLY-001",
                    title="Dependencies File Found",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="supply_chain",
                    description=f"Found dependency files: {', '.join(found_files)}",
                    evidence=f"Files: {', '.join(found_files)}",
                    remediation="Consider adding to config.artifacts.dependencies",
                    owasp_mapping=["LLM05"],
                    iso_mapping=["Clause_8"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="SUPPLY-001",
                    title="No Dependencies File",
                    severity=Severity.MEDIUM,
                    status=Status.WARNING,
                    category="supply_chain",
                    description="No dependencies file found or configured",
                    evidence="Common files (requirements.txt, etc.) not found",
                    remediation="Create requirements.txt or similar to document dependencies",
                    owasp_mapping=["LLM05"],
                    iso_mapping=["Clause_8"],
                )
            )
    else:
        dep_path = resolve_path(project_root, config.artifacts.dependencies)
        if dep_path and dep_path.exists():
            findings.append(
                Finding(
                    check_id="SUPPLY-001",
                    title="Dependencies Documented",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="supply_chain",
                    description="Dependencies file is configured and exists",
                    evidence=f"File: {dep_path}",
                    remediation="N/A",
                    owasp_mapping=["LLM05"],
                    iso_mapping=["Clause_8"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="SUPPLY-001",
                    title="Dependencies File Not Found",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    category="supply_chain",
                    description="Configured dependencies file does not exist",
                    evidence=f"Path: {config.artifacts.dependencies}",
                    remediation="Ensure dependencies file exists at specified path",
                    owasp_mapping=["LLM05"],
                    iso_mapping=["Clause_8"],
                )
            )

    return findings


def _check_vulnerabilities(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Run pip-audit to check for known vulnerabilities."""
    findings = []

    try:
        # Run pip-audit with JSON output
        result = subprocess.run(
            ["pip-audit", "--format", "json", "--desc"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode == 0:
            # No vulnerabilities found
            findings.append(
                Finding(
                    check_id="SUPPLY-002",
                    title="No Known Vulnerabilities",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="supply_chain",
                    description="pip-audit found no known vulnerabilities",
                    evidence="All dependencies are up to date",
                    remediation="N/A",
                    owasp_mapping=["LLM05"],
                    iso_mapping=["Clause_8"],
                )
            )
        else:
            # Parse vulnerabilities
            try:
                vulns = json.loads(result.stdout)
                vuln_count = len(vulns.get("dependencies", []))

                findings.append(
                    Finding(
                        check_id="SUPPLY-002",
                        title=f"Known Vulnerabilities Found: {vuln_count}",
                        severity=Severity.HIGH,
                        status=Status.FAIL,
                        category="supply_chain",
                        description=f"pip-audit found {vuln_count} vulnerabilities in dependencies",
                        evidence=f"Run 'pip-audit' for details",
                        remediation="Update vulnerable packages to patched versions",
                        owasp_mapping=["LLM05"],
                        iso_mapping=["Clause_8"],
                    )
                )

            except json.JSONDecodeError:
                findings.append(
                    Finding(
                        check_id="SUPPLY-002",
                        title="Vulnerability Scan Issues",
                        severity=Severity.MEDIUM,
                        status=Status.WARNING,
                        category="supply_chain",
                        description="pip-audit completed but output could not be parsed",
                        evidence=result.stderr[:200] if result.stderr else "Unknown error",
                        remediation="Review pip-audit output manually",
                        owasp_mapping=["LLM05"],
                        iso_mapping=["Clause_8"],
                    )
                )

    except subprocess.TimeoutExpired:
        findings.append(
            Finding(
                check_id="SUPPLY-002",
                title="Vulnerability Scan Timeout",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="supply_chain",
                description="pip-audit timed out after 60 seconds",
                evidence="Scan exceeded timeout",
                remediation="Run pip-audit manually to check for vulnerabilities",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )

    except FileNotFoundError:
        findings.append(
            Finding(
                check_id="SUPPLY-002",
                title="pip-audit Not Available",
                severity=Severity.MEDIUM,
                status=Status.SKIP,
                category="supply_chain",
                description="pip-audit is not installed",
                evidence="Command not found",
                remediation="Install pip-audit: pip install pip-audit",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )

    except Exception as e:
        findings.append(
            Finding(
                check_id="SUPPLY-002",
                title="Vulnerability Scan Error",
                severity=Severity.MEDIUM,
                status=Status.ERROR,
                category="supply_chain",
                description="Failed to run pip-audit",
                evidence=f"Error: {str(e)}",
                remediation="Check pip-audit installation and permissions",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_licenses(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Basic license compliance check."""
    findings = []

    # This is a simplified check - full license compliance requires specialized tools
    findings.append(
        Finding(
            check_id="SUPPLY-003",
            title="License Compliance Check",
            severity=Severity.INFO,
            status=Status.SKIP,
            category="supply_chain",
            description="Automated license compliance requires specialized tools",
            evidence="Use tools like pip-licenses or license-checker",
            remediation="Manually review dependency licenses for compatibility",
            owasp_mapping=["LLM05"],
            iso_mapping=["Clause_8"],
        )
    )

    return findings


def _check_model_provenance(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for model provenance documentation."""
    findings = []

    # Check if model card has provenance info
    if not config.artifacts.model_card:
        findings.append(
            Finding(
                check_id="SUPPLY-004",
                title="Model Provenance Not Documented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="supply_chain",
                description="No model card to document provenance",
                evidence="Model card not configured",
                remediation="Create model card with authors, license, and citation info",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )
        return findings

    # Load model card and check provenance fields
    from ..core.loader import load_model_card

    model_card_path = resolve_path(project_root, config.artifacts.model_card)

    if model_card_path and model_card_path.exists():
        model_card = load_model_card(model_card_path)

        if model_card:
            provenance_fields = {
                "authors": model_card.authors,
                "license": model_card.license,
            }

            missing = [k for k, v in provenance_fields.items() if not v]

            if missing:
                findings.append(
                    Finding(
                        check_id="SUPPLY-004",
                        title="Incomplete Model Provenance",
                        severity=Severity.MEDIUM,
                        status=Status.WARNING,
                        category="supply_chain",
                        description=f"Model card missing provenance: {', '.join(missing)}",
                        evidence=f"File: {model_card_path}",
                        remediation=f"Add {', '.join(missing)} to model card",
                        owasp_mapping=["LLM05"],
                        iso_mapping=["Clause_8"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="SUPPLY-004",
                        title="Model Provenance Documented",
                        severity=Severity.INFO,
                        status=Status.PASS,
                        category="supply_chain",
                        description="Model provenance is documented in model card",
                        evidence=f"Authors: {', '.join(model_card.authors[:3])}",
                        remediation="N/A",
                        owasp_mapping=["LLM05"],
                        iso_mapping=["Clause_8"],
                    )
                )

    return findings
