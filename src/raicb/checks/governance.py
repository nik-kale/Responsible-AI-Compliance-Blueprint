"""Governance and policy checks."""

from pathlib import Path
from typing import List, Dict

from ..config.schema import ProjectConfig, Finding, Severity, Status, Impact
from ..core.loader import resolve_path


def run_checks(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """
    Run governance checks.

    Args:
        config: Project configuration
        project_root: Project root directory
        env: Environment name

    Returns:
        List of findings
    """
    findings: List[Finding] = []

    # Check 1: Policy documentation
    findings.extend(_check_policy_docs(config, project_root))

    # Check 2: Role assignments
    findings.extend(_check_role_assignments(config))

    # Check 3: Risk management
    findings.extend(_check_risk_management(config))

    # Check 4: Change control
    findings.extend(_check_change_control(config, project_root))

    # Check 5: Model lifecycle tracking
    findings.extend(_check_model_lifecycle(config))

    return findings


def _check_policy_docs(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for required policy documentation."""
    findings = []

    critical_policies = {
        "risk_management": ("Risk Management Policy", Severity.HIGH),
        "incident_response": ("Incident Response Plan", Severity.HIGH),
        "model_lifecycle": ("Model Lifecycle Policy", Severity.MEDIUM),
        "security": ("Security Policy", Severity.MEDIUM),
    }

    recommended_policies = {
        "data_governance": ("Data Governance Policy", Severity.LOW),
        "ethics": ("AI Ethics Policy", Severity.LOW),
        "privacy": ("Privacy Policy", Severity.MEDIUM),
        "acceptable_use": ("Acceptable Use Policy", Severity.LOW),
    }

    all_policies = {**critical_policies, **recommended_policies}

    missing_critical = []
    missing_recommended = []

    for policy_key, (policy_name, severity) in all_policies.items():
        policy_path_str = getattr(config.policies, policy_key, None)

        if not policy_path_str:
            if policy_key in critical_policies:
                missing_critical.append(policy_name)
                findings.append(
                    Finding(
                        check_id=f"GOV-001-{policy_key}",
                        title=f"Missing {policy_name}",
                        severity=severity,
                        status=Status.FAIL,
                        category="governance",
                        description=f"{policy_name} is not configured",
                        evidence=f"config.policies.{policy_key} is not set",
                        remediation=f"Create and configure {policy_name}",
                        owasp_mapping=["LLM08", "LLM09"],
                        iso_mapping=["Clause_5", "Clause_6"],
                    )
                )
            else:
                missing_recommended.append(policy_name)
        else:
            policy_path = resolve_path(project_root, policy_path_str)

            if policy_path and policy_path.exists():
                findings.append(
                    Finding(
                        check_id=f"GOV-001-{policy_key}",
                        title=f"{policy_name} Found",
                        severity=Severity.INFO,
                        status=Status.PASS,
                        category="governance",
                        description=f"{policy_name} is documented",
                        evidence=f"File: {policy_path.relative_to(project_root)}",
                        remediation="N/A",
                        owasp_mapping=["LLM08", "LLM09"],
                        iso_mapping=["Clause_5", "Clause_6"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=f"GOV-001-{policy_key}",
                        title=f"{policy_name} File Not Found",
                        severity=severity,
                        status=Status.FAIL,
                        category="governance",
                        description=f"{policy_name} configured but file not found",
                        evidence=f"Path: {policy_path_str}",
                        remediation=f"Create {policy_name} at specified path",
                        owasp_mapping=["LLM08", "LLM09"],
                        iso_mapping=["Clause_5", "Clause_6"],
                    )
                )

    if missing_recommended:
        findings.append(
            Finding(
                check_id="GOV-002",
                title="Recommended Policies Missing",
                severity=Severity.LOW,
                status=Status.WARNING,
                category="governance",
                description=f"Recommended policies not configured: {', '.join(missing_recommended)}",
                evidence=f"{len(missing_recommended)} recommended policies missing",
                remediation="Consider creating these policies for comprehensive governance",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_5"],
            )
        )

    return findings


def _check_role_assignments(config: ProjectConfig) -> List[Finding]:
    """Check for role assignments and ownership."""
    findings = []

    # Check project owners
    if not config.project.owners:
        findings.append(
            Finding(
                check_id="GOV-003",
                title="No Project Owners Assigned",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="governance",
                description="No project owners are assigned",
                evidence="config.project.owners is empty",
                remediation="Assign project owners with clear responsibilities",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_5"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="GOV-003",
                title="Project Owners Assigned",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description=f"{len(config.project.owners)} project owner(s) assigned",
                evidence=f"Owners: {', '.join(o.name for o in config.project.owners)}",
                remediation="N/A",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_5"],
            )
        )

    # Check emergency contacts
    if not config.project.contacts:
        findings.append(
            Finding(
                check_id="GOV-004",
                title="No Emergency Contacts",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="governance",
                description="No emergency contacts configured",
                evidence="config.project.contacts is empty",
                remediation="Add emergency contacts for incident response",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_5"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="GOV-004",
                title="Emergency Contacts Configured",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description=f"{len(config.project.contacts)} emergency contact(s) configured",
                evidence=f"Contacts: {', '.join(c.name for c in config.project.contacts)}",
                remediation="N/A",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_5"],
            )
        )

    return findings


def _check_risk_management(config: ProjectConfig) -> List[Finding]:
    """Check risk management implementation."""
    findings = []

    if not config.threats:
        findings.append(
            Finding(
                check_id="GOV-005",
                title="No Threats Documented",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="governance",
                description="No threats or risks are documented",
                evidence="config.threats is empty",
                remediation="Conduct risk assessment and document identified threats",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_6", "Clause_6.1"],
            )
        )
    else:
        # Analyze risk coverage (compare Enum values properly)
        high_impact_threats = [
            t for t in config.threats if t.impact in [Impact.HIGH, Impact.CRITICAL]
        ]

        findings.append(
            Finding(
                check_id="GOV-005",
                title="Threats Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description=f"{len(config.threats)} threats documented ({len(high_impact_threats)} high/critical impact)",
                evidence=f"Total threats: {len(config.threats)}",
                remediation="N/A",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_6", "Clause_6.1"],
            )
        )

        # Check if controls are assigned to threats
        threats_without_controls = [t for t in config.threats if not t.controls]

        if threats_without_controls:
            findings.append(
                Finding(
                    check_id="GOV-006",
                    title="Threats Without Controls",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    category="governance",
                    description=f"{len(threats_without_controls)} threat(s) have no assigned controls",
                    evidence=f"Unmitigated threats: {', '.join(t.id for t in threats_without_controls[:5])}",
                    remediation="Assign controls to all identified threats",
                    owasp_mapping=["LLM08"],
                    iso_mapping=["Clause_6.1"],
                )
            )

    # Check controls
    if not config.controls:
        findings.append(
            Finding(
                check_id="GOV-007",
                title="No Controls Documented",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="governance",
                description="No security controls are documented",
                evidence="config.controls is empty",
                remediation="Document implemented security controls",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_6.1"],
            )
        )
    else:
        implemented_controls = [c for c in config.controls if c.implemented]

        findings.append(
            Finding(
                check_id="GOV-007",
                title="Controls Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description=f"{len(implemented_controls)}/{len(config.controls)} controls implemented",
                evidence=f"Total controls: {len(config.controls)}",
                remediation="N/A" if len(implemented_controls) == len(config.controls)
                    else "Implement remaining planned controls",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_6.1"],
            )
        )

    return findings


def _check_change_control(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check change control procedures."""
    findings = []

    if not config.policies.change_control:
        findings.append(
            Finding(
                check_id="GOV-008",
                title="Change Control Not Documented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="governance",
                description="No change control procedure documented",
                evidence="config.policies.change_control is not set",
                remediation="Document change control and approval process",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_10"],
            )
        )
    else:
        change_control_path = resolve_path(project_root, config.policies.change_control)

        if change_control_path and change_control_path.exists():
            findings.append(
                Finding(
                    check_id="GOV-008",
                    title="Change Control Documented",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="governance",
                    description="Change control procedure is documented",
                    evidence=f"File: {change_control_path.relative_to(project_root)}",
                    remediation="N/A",
                    owasp_mapping=["LLM08"],
                    iso_mapping=["Clause_10"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="GOV-008",
                    title="Change Control File Not Found",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    category="governance",
                    description="Change control configured but file not found",
                    evidence=f"Path: {config.policies.change_control}",
                    remediation="Create change control documentation",
                    owasp_mapping=["LLM08"],
                    iso_mapping=["Clause_10"],
                )
            )

    return findings


def _check_model_lifecycle(config: ProjectConfig) -> List[Finding]:
    """Check model lifecycle tracking."""
    findings = []

    # Check if model card exists (indicates lifecycle tracking)
    if not config.artifacts.model_card:
        findings.append(
            Finding(
                check_id="GOV-009",
                title="Model Lifecycle Not Tracked",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="governance",
                description="No model card for lifecycle tracking",
                evidence="config.artifacts.model_card is not set",
                remediation="Create model card to track model lifecycle",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_8", "Clause_8.1"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="GOV-009",
                title="Model Lifecycle Tracked",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description="Model card configured for lifecycle tracking",
                evidence=f"Model card: {config.artifacts.model_card}",
                remediation="N/A",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_8", "Clause_8.1"],
            )
        )

    # Check version tracking
    if not config.project.version:
        findings.append(
            Finding(
                check_id="GOV-010",
                title="No Version Tracking",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="governance",
                description="Project version not specified",
                evidence="config.project.version is not set",
                remediation="Implement version tracking for changes",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="GOV-010",
                title="Version Tracked",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description=f"Project version: {config.project.version}",
                evidence=f"Version: {config.project.version}",
                remediation="N/A",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings
