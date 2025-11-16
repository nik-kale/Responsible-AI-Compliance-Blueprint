"""Supply chain security checks for dependencies and provenance."""

import json
import subprocess
from pathlib import Path
from typing import List, Optional

from ..config.schema import ProjectConfig, Finding, Severity, Status
from ..core.loader import resolve_path
from ..core.logger import get_logger

logger = get_logger(__name__)


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

    # Check 5: SBOM (Software Bill of Materials)
    findings.extend(_check_sbom(config, project_root))

    # Check 6: Dependency pinning
    findings.extend(_check_dependency_pinning(config, project_root))

    # Check 7: Container security
    findings.extend(_check_container_security(config, project_root))

    # Check 8: Code signing
    findings.extend(_check_code_signing(config, project_root))

    # Check 9: Repository security
    findings.extend(_check_repository_security(config, project_root))

    # Check 10: Build reproducibility
    findings.extend(_check_build_reproducibility(config, project_root))

    # Check 11: Third-party model risks
    findings.extend(_check_third_party_models(config, project_root))

    # Check 12: Update policy
    findings.extend(_check_update_policy(config, project_root))

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
    """Check license compliance using pip-licenses."""
    findings = []

    try:
        import subprocess

        # Try to run pip-licenses
        result = subprocess.run(
            ["pip-licenses", "--format=json", "--with-system"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            import json

            licenses = json.loads(result.stdout)

            # Define problematic license types
            COPYLEFT_LICENSES = {"GPL", "GPLv2", "GPLv3", "AGPL", "AGPLv3", "LGPL"}
            UNKNOWN_LICENSES = {"UNKNOWN", "Unknown"}

            copyleft_packages = []
            unknown_packages = []

            for lic in licenses:
                license_name = lic.get("License", "").upper()

                # Check for copyleft licenses
                if any(gpl in license_name for gpl in COPYLEFT_LICENSES):
                    copyleft_packages.append(lic["Name"])

                # Check for unknown licenses
                if any(unk in license_name for unk in UNKNOWN_LICENSES):
                    unknown_packages.append(lic["Name"])

            # Report copyleft findings
            if copyleft_packages:
                findings.append(
                    Finding(
                        check_id="SUPPLY-003a",
                        title=f"Copyleft Licenses Found: {len(copyleft_packages)}",
                        severity=Severity.MEDIUM,
                        status=Status.WARNING,
                        category="supply_chain",
                        description=f"Found {len(copyleft_packages)} packages with GPL/copyleft licenses",
                        evidence=", ".join(copyleft_packages[:5])
                        + (f" (+{len(copyleft_packages) - 5} more)" if len(copyleft_packages) > 5 else ""),
                        remediation="Review license compatibility. Copyleft licenses may have distribution restrictions.",
                        owasp_mapping=["LLM05"],
                        iso_mapping=["Clause_8"],
                    )
                )

            # Report unknown licenses
            if unknown_packages:
                findings.append(
                    Finding(
                        check_id="SUPPLY-003b",
                        title=f"Unknown Licenses: {len(unknown_packages)}",
                        severity=Severity.LOW,
                        status=Status.WARNING,
                        category="supply_chain",
                        description=f"Found {len(unknown_packages)} packages with unknown licenses",
                        evidence=", ".join(unknown_packages[:5])
                        + (f" (+{len(unknown_packages) - 5} more)" if len(unknown_packages) > 5 else ""),
                        remediation="Investigate and document licenses for these packages",
                        owasp_mapping=["LLM05"],
                        iso_mapping=["Clause_8"],
                    )
                )

            # If no issues, report success
            if not copyleft_packages and not unknown_packages:
                findings.append(
                    Finding(
                        check_id="SUPPLY-003",
                        title="No License Conflicts Detected",
                        severity=Severity.INFO,
                        status=Status.PASS,
                        category="supply_chain",
                        description="All dependencies have permissive licenses",
                        evidence=f"Checked {len(licenses)} packages",
                        remediation="N/A",
                        owasp_mapping=["LLM05"],
                        iso_mapping=["Clause_8"],
                    )
                )

        else:
            # pip-licenses returned error
            findings.append(
                Finding(
                    check_id="SUPPLY-003",
                    title="License Check Failed",
                    severity=Severity.LOW,
                    status=Status.WARNING,
                    category="supply_chain",
                    description="pip-licenses command failed",
                    evidence=result.stderr[:200] if result.stderr else "Unknown error",
                    remediation="Check pip-licenses installation and run manually",
                    owasp_mapping=["LLM05"],
                    iso_mapping=["Clause_8"],
                )
            )

    except subprocess.TimeoutExpired:
        findings.append(
            Finding(
                check_id="SUPPLY-003",
                title="License Check Timeout",
                severity=Severity.LOW,
                status=Status.WARNING,
                category="supply_chain",
                description="License check timed out after 30 seconds",
                evidence="Scan exceeded timeout",
                remediation="Run 'pip-licenses' manually to review licenses",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )

    except FileNotFoundError:
        findings.append(
            Finding(
                check_id="SUPPLY-003",
                title="pip-licenses Not Available",
                severity=Severity.LOW,
                status=Status.SKIP,
                category="supply_chain",
                description="pip-licenses is not installed",
                evidence="Command not found",
                remediation="Install pip-licenses: pip install pip-licenses",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )

    except Exception as e:
        findings.append(
            Finding(
                check_id="SUPPLY-003",
                title="License Check Error",
                severity=Severity.LOW,
                status=Status.ERROR,
                category="supply_chain",
                description="Error running license compliance check",
                evidence=f"Error: {str(e)}",
                remediation="Check system configuration and try manual license review",
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


def _check_sbom(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for Software Bill of Materials (SBOM)."""
    findings = []

    # Check for SBOM files
    sbom_files = [
        "sbom.json",
        "SBOM.json",
        "bom.json",
        "cyclonedx.json",
        "spdx.json",
        "sbom.xml",
    ]

    sbom_exists = any((project_root / f).exists() for f in sbom_files)

    if not sbom_exists:
        findings.append(
            Finding(
                check_id="SUPPLY-005",
                title="No SBOM Found",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="supply_chain",
                description="No Software Bill of Materials (SBOM) found. SBOM is critical for supply chain transparency and vulnerability management.",
                evidence=f"Checked for: {', '.join(sbom_files)}",
                remediation="Generate SBOM using tools like:\n"
                           "1. cyclonedx-bom (pip install cyclonedx-bom)\n"
                           "2. syft (for containers)\n"
                           "3. SPDX tools\n"
                           "4. GitHub Dependency Graph\n"
                           "Run: cyclonedx-py -o sbom.json",
                owasp_mapping=["LLM05", "LLM03"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        sbom_file = next((project_root / f for f in sbom_files if (project_root / f).exists()), None)
        findings.append(
            Finding(
                check_id="SUPPLY-005",
                title="SBOM Found",
                severity=Severity.INFO,
                status=Status.PASS,
                category="supply_chain",
                description="Software Bill of Materials (SBOM) found.",
                evidence=f"File: {sbom_file.name if sbom_file else 'SBOM file'}",
                remediation="Regularly update SBOM with dependency changes",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_dependency_pinning(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if dependencies are pinned to specific versions."""
    findings = []

    # Check requirements.txt for version pinning
    req_file = project_root / "requirements.txt"

    if req_file.exists():
        try:
            content = req_file.read_text(encoding="utf-8")
            lines = [line.strip() for line in content.split("\n") if line.strip() and not line.startswith("#")]

            unpinned = []
            for line in lines:
                # Check if version is pinned with ==
                if "==" not in line and not line.startswith("-"):
                    unpinned.append(line.split()[0] if " " in line else line)

            if unpinned:
                findings.append(
                    Finding(
                        check_id="SUPPLY-006",
                        title=f"Unpinned Dependencies Found: {len(unpinned)}",
                        severity=Severity.MEDIUM,
                        status=Status.WARNING,
                        category="supply_chain",
                        description=f"Found {len(unpinned)} dependencies without version pinning. This can lead to supply chain attacks.",
                        evidence=", ".join(unpinned[:5])
                        + (f" (+{len(unpinned) - 5} more)" if len(unpinned) > 5 else ""),
                        remediation="Pin all dependencies to specific versions:\n"
                                   "1. Use == instead of >= or ~=\n"
                                   "2. Run: pip freeze > requirements.txt\n"
                                   "3. Use pip-compile (pip-tools) for better management\n"
                                   "4. Document why unpinned versions are needed (if any)",
                        owasp_mapping=["LLM05", "LLM03"],
                        iso_mapping=["Clause_8"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="SUPPLY-006",
                        title="Dependencies Properly Pinned",
                        severity=Severity.INFO,
                        status=Status.PASS,
                        category="supply_chain",
                        description="All dependencies are pinned to specific versions.",
                        evidence=f"Checked {len(lines)} dependencies",
                        remediation="N/A",
                        owasp_mapping=["LLM05"],
                        iso_mapping=["Clause_8"],
                    )
                )

        except Exception as e:
            logger.warning(f"Error reading requirements.txt: {e}")

    else:
        findings.append(
            Finding(
                check_id="SUPPLY-006",
                title="No requirements.txt Found",
                severity=Severity.LOW,
                status=Status.SKIP,
                category="supply_chain",
                description="Cannot check dependency pinning without requirements.txt",
                evidence="File not found",
                remediation="Create requirements.txt with pinned versions",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_container_security(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check container security if Dockerfile exists."""
    findings = []

    dockerfile = project_root / "Dockerfile"

    if not dockerfile.exists():
        return [
            Finding(
                check_id="SUPPLY-007",
                title="No Dockerfile Found",
                severity=Severity.INFO,
                status=Status.SKIP,
                category="supply_chain",
                description="No Dockerfile found, skipping container security checks",
                evidence="Dockerfile not present",
                remediation="N/A",
                owasp_mapping=[],
                iso_mapping=[],
            )
        ]

    try:
        content = dockerfile.read_text(encoding="utf-8").lower()

        issues = []

        # Check for latest tag
        if ":latest" in content or "from python\n" in content:
            issues.append("Using ':latest' tag (unpinned base image)")

        # Check for root user
        if "user" not in content:
            issues.append("Not running as non-root user")

        # Check for HEALTHCHECK
        if "healthcheck" not in content:
            issues.append("No HEALTHCHECK defined")

        # Check for secrets in build
        dangerous_patterns = ["password", "secret", "token", "key"]
        if any(pattern in content for pattern in dangerous_patterns):
            issues.append("Potential secrets in Dockerfile")

        if issues:
            findings.append(
                Finding(
                    check_id="SUPPLY-007",
                    title=f"Container Security Issues: {len(issues)}",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    category="supply_chain",
                    description=f"Found {len(issues)} container security issues",
                    evidence="; ".join(issues),
                    remediation="Container security best practices:\n"
                               "1. Pin base image to specific version (e.g., python:3.11.5-slim)\n"
                               "2. Run as non-root user (USER appuser)\n"
                               "3. Add HEALTHCHECK instruction\n"
                               "4. Never include secrets in Dockerfile\n"
                               "5. Use .dockerignore file\n"
                               "6. Scan images with trivy or similar tools\n"
                               "7. Use minimal base images",
                    owasp_mapping=["LLM05", "LLM03"],
                    iso_mapping=["Clause_8"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="SUPPLY-007",
                    title="Container Security Good Practices",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="supply_chain",
                    description="Dockerfile follows security best practices",
                    evidence="No major issues found",
                    remediation="Consider regular container scanning",
                    owasp_mapping=["LLM05"],
                    iso_mapping=["Clause_8"],
                )
            )

    except Exception as e:
        logger.warning(f"Error reading Dockerfile: {e}")

    return findings


def _check_code_signing(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for code signing and verification."""
    findings = []

    # Check for signing artifacts
    signing_artifacts = [
        ".signature",
        "checksums.txt",
        "CHECKSUMS",
        "SHA256SUMS",
        ".sig",
    ]

    signing_found = any((project_root / f).exists() for f in signing_artifacts)

    # Check for GPG/PGP keys
    gpg_files = list(project_root.glob("*.asc")) + list(project_root.glob("*.gpg"))

    if not signing_found and not gpg_files:
        findings.append(
            Finding(
                check_id="SUPPLY-008",
                title="Code Signing Not Implemented",
                severity=Severity.LOW,
                status=Status.WARNING,
                category="supply_chain",
                description="No code signing or checksums found. Cannot verify artifact integrity.",
                evidence=f"Checked for: {', '.join(signing_artifacts)}",
                remediation="Implement code signing:\n"
                           "1. Generate checksums for releases (sha256sum)\n"
                           "2. Sign releases with GPG/PGP keys\n"
                           "3. Publish checksums and signatures\n"
                           "4. Document verification process\n"
                           "5. Use signed commits in Git\n"
                           "6. Consider code signing certificates for production",
                owasp_mapping=["LLM05", "LLM03"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="SUPPLY-008",
                title="Code Signing Artifacts Found",
                severity=Severity.INFO,
                status=Status.PASS,
                category="supply_chain",
                description="Code signing or verification artifacts found.",
                evidence=f"Found {len(gpg_files)} signature files" if gpg_files else "Checksums found",
                remediation="Regularly rotate signing keys",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_repository_security(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check Git repository security settings."""
    findings = []

    git_dir = project_root / ".git"

    if not git_dir.exists():
        return [
            Finding(
                check_id="SUPPLY-009",
                title="Not a Git Repository",
                severity=Severity.INFO,
                status=Status.SKIP,
                category="supply_chain",
                description="Project is not in a Git repository",
                evidence=".git directory not found",
                remediation="N/A",
                owasp_mapping=[],
                iso_mapping=[],
            )
        ]

    try:
        # Check for .gitignore
        gitignore = project_root / ".gitignore"
        if not gitignore.exists():
            findings.append(
                Finding(
                    check_id="SUPPLY-009",
                    title="No .gitignore File",
                    severity=Severity.MEDIUM,
                    status=Status.WARNING,
                    category="supply_chain",
                    description=".gitignore file not found. Sensitive files may be committed.",
                    evidence=".gitignore missing",
                    remediation="Create .gitignore to exclude:\n"
                               "1. .env files\n"
                               "2. API keys and secrets\n"
                               "3. Virtual environments (venv/)\n"
                               "4. Model files (*.pkl, *.pth, *.h5)\n"
                               "5. Cache directories (__pycache__/)\n"
                               "6. IDE files (.vscode/, .idea/)",
                    owasp_mapping=["LLM06", "LLM05"],
                    iso_mapping=["Clause_8"],
                )
            )
        else:
            # Check if common sensitive patterns are ignored
            gitignore_content = gitignore.read_text(encoding="utf-8").lower()
            important_patterns = [".env", "*.key", "*.pem", "secret"]

            missing_patterns = [p for p in important_patterns if p not in gitignore_content]

            if missing_patterns:
                findings.append(
                    Finding(
                        check_id="SUPPLY-009",
                        title="Incomplete .gitignore",
                        severity=Severity.MEDIUM,
                        status=Status.WARNING,
                        category="supply_chain",
                        description=f".gitignore may not cover all sensitive files",
                        evidence=f"Missing patterns: {', '.join(missing_patterns)}",
                        remediation=f"Add to .gitignore: {', '.join(missing_patterns)}",
                        owasp_mapping=["LLM06"],
                        iso_mapping=["Clause_8"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="SUPPLY-009",
                        title="Repository Security Configured",
                        severity=Severity.INFO,
                        status=Status.PASS,
                        category="supply_chain",
                        description=".gitignore covers common sensitive patterns",
                        evidence="Key patterns found in .gitignore",
                        remediation="N/A",
                        owasp_mapping=["LLM05"],
                        iso_mapping=["Clause_8"],
                    )
                )

    except Exception as e:
        logger.warning(f"Error checking repository security: {e}")

    return findings


def _check_build_reproducibility(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for build reproducibility."""
    findings = []

    # Check for lockfiles (ensure reproducible builds)
    lockfiles = [
        "poetry.lock",
        "Pipfile.lock",
        "requirements.lock",
        "conda-lock.yml",
    ]

    lockfile_exists = any((project_root / f).exists() for f in lockfiles)

    if not lockfile_exists:
        findings.append(
            Finding(
                check_id="SUPPLY-010",
                title="No Dependency Lockfile Found",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="supply_chain",
                description="No lockfile found. Builds may not be reproducible.",
                evidence=f"Checked for: {', '.join(lockfiles)}",
                remediation="Create lockfile for reproducible builds:\n"
                           "1. Use poetry (poetry.lock)\n"
                           "2. Use pipenv (Pipfile.lock)\n"
                           "3. Use pip-tools (pip-compile)\n"
                           "4. Use conda-lock for Conda environments\n"
                           "This ensures exact dependency versions across environments",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        lockfile = next((project_root / f for f in lockfiles if (project_root / f).exists()), None)
        findings.append(
            Finding(
                check_id="SUPPLY-010",
                title="Dependency Lockfile Found",
                severity=Severity.INFO,
                status=Status.PASS,
                category="supply_chain",
                description="Lockfile ensures reproducible builds.",
                evidence=f"File: {lockfile.name if lockfile else 'lockfile'}",
                remediation="Keep lockfile updated with dependency changes",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_third_party_models(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for third-party model usage and risks."""
    findings = []

    # Check if using third-party models (HuggingFace, etc.)
    third_party_indicators = [
        "transformers",
        "huggingface",
        "openai",
        "anthropic",
        "cohere",
    ]

    # Check requirements files
    req_files = [
        project_root / "requirements.txt",
        project_root / "pyproject.toml",
    ]

    third_party_found = False
    packages_found = []

    for req_file in req_files:
        if req_file.exists():
            try:
                content = req_file.read_text(encoding="utf-8").lower()
                for indicator in third_party_indicators:
                    if indicator in content:
                        third_party_found = True
                        packages_found.append(indicator)
            except Exception as e:
                logger.warning(f"Error reading {req_file}: {e}")

    if third_party_found:
        # Check if risk assessment is documented
        risk_docs = [
            "docs/third_party_risk.md",
            "THIRD_PARTY_MODELS.md",
            "docs/model_risk_assessment.md",
        ]

        risk_documented = any((project_root / doc).exists() for doc in risk_docs)

        if not risk_documented:
            findings.append(
                Finding(
                    check_id="SUPPLY-011",
                    title="Third-Party Model Risks Not Documented",
                    severity=Severity.MEDIUM,
                    status=Status.WARNING,
                    category="supply_chain",
                    description=f"Using third-party models ({', '.join(set(packages_found))}) without documented risk assessment.",
                    evidence=f"Packages: {', '.join(set(packages_found))}",
                    remediation="Document third-party model risks:\n"
                               "1. Identify all third-party models used\n"
                               "2. Assess model provenance and trustworthiness\n"
                               "3. Review model licenses and usage restrictions\n"
                               "4. Document potential bias and fairness risks\n"
                               "5. Evaluate data privacy implications\n"
                               "6. Monitor for model updates and vulnerabilities\n"
                               "7. Implement fallback plans for model unavailability",
                    owasp_mapping=["LLM05", "LLM03"],
                    iso_mapping=["Clause_8"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="SUPPLY-011",
                    title="Third-Party Model Risks Documented",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="supply_chain",
                    description="Third-party model risk assessment found.",
                    evidence="Risk documentation exists",
                    remediation="Regularly review third-party model risks",
                    owasp_mapping=["LLM05"],
                    iso_mapping=["Clause_8"],
                )
            )
    else:
        findings.append(
            Finding(
                check_id="SUPPLY-011",
                title="No Third-Party Models Detected",
                severity=Severity.INFO,
                status=Status.PASS,
                category="supply_chain",
                description="No third-party model dependencies found.",
                evidence="Using custom or internal models only",
                remediation="N/A",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_update_policy(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if dependency update policy is documented."""
    findings = []

    update_docs = [
        "UPDATE_POLICY.md",
        "docs/update_policy.md",
        "SECURITY.md",
        "docs/security_policy.md",
    ]

    update_policy_exists = any((project_root / doc).exists() for doc in update_docs)

    if not update_policy_exists:
        findings.append(
            Finding(
                check_id="SUPPLY-012",
                title="No Dependency Update Policy",
                severity=Severity.LOW,
                status=Status.WARNING,
                category="supply_chain",
                description="No documented policy for dependency updates. May miss critical security patches.",
                evidence=f"Checked for: {', '.join(update_docs)}",
                remediation="Document dependency update policy:\n"
                           "1. Define update cadence (e.g., monthly security updates)\n"
                           "2. Specify testing requirements before updates\n"
                           "3. Document emergency patch process\n"
                           "4. Use automated tools (Dependabot, Renovate)\n"
                           "5. Define SLA for critical security updates\n"
                           "6. Document rollback procedures\n"
                           "7. Track update history and decisions",
                owasp_mapping=["LLM05", "LLM03"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        update_doc = next((project_root / doc for doc in update_docs if (project_root / doc).exists()), None)
        findings.append(
            Finding(
                check_id="SUPPLY-012",
                title="Update Policy Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="supply_chain",
                description="Dependency update policy is documented.",
                evidence=f"File: {update_doc.name if update_doc else 'policy documentation'}",
                remediation="Follow update policy consistently",
                owasp_mapping=["LLM05"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings
