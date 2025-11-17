"""Governance and policy checks."""

from pathlib import Path
from typing import List, Dict

from ..config.schema import ProjectConfig, Finding, Severity, Status, Impact
from ..core.loader import resolve_path
from ..core.logger import get_logger

logger = get_logger(__name__)


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

    # Check 6: AI objectives documentation (ISO 6.2)
    findings.extend(_check_ai_objectives(config, project_root))

    # Check 7: AI objectives measurability (ISO 6.2)
    findings.extend(_check_objectives_measurability(config))

    # Check 8: Continuous improvement process (ISO 10)
    findings.extend(_check_continuous_improvement(config, project_root))

    # Check 9: Corrective actions documentation (ISO 10)
    findings.extend(_check_corrective_actions(project_root))

    # Check 10: Nonconformity tracking (ISO 10)
    findings.extend(_check_nonconformity_tracking(project_root))

    # Check 11: Performance monitoring (ISO 9)
    findings.extend(_check_performance_monitoring(config, project_root))

    # Check 12: Internal audit program (ISO 9)
    findings.extend(_check_internal_audit(project_root))

    # Check 13: Management review process (ISO 9)
    findings.extend(_check_management_review(project_root))

    # Check 14: Stakeholder communication (ISO 7.4)
    findings.extend(_check_stakeholder_communication(config, project_root))

    # Check 15: Competence and training (ISO 7.2)
    findings.extend(_check_competence_training(project_root))

    # Check 16: Documentation control (ISO 7.5)
    findings.extend(_check_documentation_control(project_root))

    # Check 17: Third-party risk management (ISO 8.2)
    findings.extend(_check_third_party_risk(config, project_root))

    # Check 18: Procurement controls (ISO 8.2)
    findings.extend(_check_procurement_controls(project_root))

    # Check 19: AI system decommissioning (ISO 8.3)
    findings.extend(_check_decommissioning_plan(project_root))

    # Check 20: Incident learning and improvement (ISO 10.2)
    findings.extend(_check_incident_learning(project_root))

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


def _check_ai_objectives(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for AI objectives documentation (ISO 6.2)."""
    findings = []

    objectives_docs = [
        "docs/ai_objectives.md",
        "AI_OBJECTIVES.md",
        "docs/objectives.md",
        "OBJECTIVES.md",
    ]

    objectives_found = any((project_root / doc).exists() for doc in objectives_docs)

    # Check for objectives in code/config
    objectives_in_config = False
    if hasattr(config, 'objectives') and config.objectives:
        objectives_in_config = True

    if not objectives_found and not objectives_in_config:
        findings.append(
            Finding(
                check_id="GOV-011",
                title="AI Objectives Not Documented",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="governance",
                description="AI system objectives are not documented (ISO 6.2 requirement)",
                evidence="No objectives documentation found",
                remediation="Document AI system objectives including:\n"
                           "1. Business objectives the AI system supports\n"
                           "2. Performance objectives (accuracy, speed, etc.)\n"
                           "3. Fairness and bias mitigation objectives\n"
                           "4. Safety and security objectives\n"
                           "5. Timeline and milestones for achievement",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_6.2"],
            )
        )
    else:
        doc_location = "configuration" if objectives_in_config else "documentation"
        findings.append(
            Finding(
                check_id="GOV-011",
                title="AI Objectives Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description=f"AI system objectives found in {doc_location}",
                evidence=f"Objectives documented (ISO 6.2 compliant)",
                remediation="N/A",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_6.2"],
            )
        )

    return findings


def _check_objectives_measurability(config: ProjectConfig) -> List[Finding]:
    """Check if AI objectives are measurable (ISO 6.2)."""
    findings = []

    # Check if objectives have measurable criteria
    measurable_keywords = [
        "metric", "measure", "kpi", "target", "threshold",
        "accuracy", "precision", "recall", "f1", "performance",
    ]

    has_measurable_objectives = False

    # Check config for objectives with metrics
    if hasattr(config, 'objectives') and config.objectives:
        objectives_str = str(config.objectives).lower()
        if any(keyword in objectives_str for keyword in measurable_keywords):
            has_measurable_objectives = True

    if not has_measurable_objectives:
        findings.append(
            Finding(
                check_id="GOV-012",
                title="AI Objectives Lack Measurability",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="governance",
                description="AI objectives should include measurable criteria (ISO 6.2)",
                evidence="No measurable metrics found in objectives",
                remediation="Define measurable success criteria:\n"
                           "1. Quantitative performance metrics (accuracy >= 95%)\n"
                           "2. Response time targets (< 100ms p95)\n"
                           "3. Fairness metrics (demographic parity, equal opportunity)\n"
                           "4. Safety thresholds (error rate < 0.1%)\n"
                           "5. Regular measurement and reporting schedule",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_6.2"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="GOV-012",
                title="AI Objectives Are Measurable",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description="AI objectives include measurable criteria",
                evidence="Measurable metrics defined in objectives",
                remediation="N/A",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_6.2"],
            )
        )

    return findings


def _check_continuous_improvement(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for continuous improvement process (ISO 10)."""
    findings = []

    improvement_docs = [
        "docs/continuous_improvement.md",
        "IMPROVEMENT.md",
        "docs/improvement_plan.md",
    ]

    improvement_found = any((project_root / doc).exists() for doc in improvement_docs)

    # Check for improvement tracking in code
    improvement_patterns = [
        "improvement", "optimization", "enhancement", "iteration",
    ]

    improvement_in_code = False
    src_dir = project_root / "src"

    if src_dir.exists():
        for py_file in list(src_dir.rglob("*improvement*.py"))[:5]:
            improvement_in_code = True
            break

    if not improvement_found:
        findings.append(
            Finding(
                check_id="GOV-013",
                title="Continuous Improvement Process Not Documented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="governance",
                description="No continuous improvement process documented (ISO 10)",
                evidence="No improvement documentation found",
                remediation="Establish continuous improvement process:\n"
                           "1. Regular performance review cycles\n"
                           "2. Feedback collection mechanisms\n"
                           "3. Improvement prioritization framework\n"
                           "4. Implementation and validation procedures\n"
                           "5. Lessons learned documentation",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_10", "Clause_10.1"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="GOV-013",
                title="Continuous Improvement Process Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description="Continuous improvement process is documented",
                evidence=f"Found improvement documentation",
                remediation="N/A",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_10", "Clause_10.1"],
            )
        )

    return findings


def _check_corrective_actions(project_root: Path) -> List[Finding]:
    """Check for corrective actions documentation (ISO 10)."""
    findings = []

    corrective_docs = [
        "docs/corrective_actions.md",
        "CORRECTIVE_ACTIONS.md",
        "docs/action_items.md",
    ]

    # Check for issue tracking integration
    issue_tracking_files = [
        ".github/ISSUE_TEMPLATE",
        ".gitlab/issue_templates",
        "ISSUES.md",
    ]

    corrective_found = any((project_root / doc).exists() for doc in corrective_docs)
    issue_tracking_found = any((project_root / f).exists() for f in issue_tracking_files)

    if not corrective_found and not issue_tracking_found:
        findings.append(
            Finding(
                check_id="GOV-014",
                title="Corrective Actions Not Tracked",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="governance",
                description="No corrective action tracking system (ISO 10.2)",
                evidence="No corrective action documentation or issue tracking found",
                remediation="Implement corrective action tracking:\n"
                           "1. Document identified issues and nonconformities\n"
                           "2. Assign ownership and due dates\n"
                           "3. Track implementation status\n"
                           "4. Verify effectiveness of corrections\n"
                           "5. Prevent recurrence through process updates",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_10.2"],
            )
        )
    else:
        evidence = "Issue tracking configured" if issue_tracking_found else "Corrective actions documented"
        findings.append(
            Finding(
                check_id="GOV-014",
                title="Corrective Actions Tracked",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description="Corrective action tracking system in place",
                evidence=evidence,
                remediation="N/A",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_10.2"],
            )
        )

    return findings


def _check_nonconformity_tracking(project_root: Path) -> List[Finding]:
    """Check for nonconformity tracking (ISO 10)."""
    findings = []

    nonconformity_docs = [
        "docs/nonconformities.md",
        "NONCONFORMITIES.md",
        "docs/compliance_issues.md",
    ]

    # Check for test failure tracking
    test_dirs = [
        "tests",
        "test",
    ]

    nonconformity_found = any((project_root / doc).exists() for doc in nonconformity_docs)
    has_tests = any((project_root / d).exists() and (project_root / d).is_dir() for d in test_dirs)

    if not nonconformity_found:
        severity = Severity.MEDIUM if has_tests else Severity.HIGH
        findings.append(
            Finding(
                check_id="GOV-015",
                title="Nonconformity Tracking Not Implemented",
                severity=severity,
                status=Status.WARNING,
                category="governance",
                description="No nonconformity tracking system (ISO 10.2)",
                evidence="No nonconformity documentation found",
                remediation="Implement nonconformity tracking:\n"
                           "1. Log all detected nonconformities\n"
                           "2. Classify by severity and impact\n"
                           "3. Investigate root causes\n"
                           "4. Implement corrective actions\n"
                           "5. Monitor for recurrence",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_10.2"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="GOV-015",
                title="Nonconformity Tracking Implemented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description="Nonconformity tracking system in place",
                evidence="Nonconformity documentation found",
                remediation="N/A",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_10.2"],
            )
        )

    return findings


def _check_performance_monitoring(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for performance monitoring (ISO 9)."""
    findings = []

    # Check for monitoring configuration
    monitoring_files = [
        "monitoring.yml",
        "prometheus.yml",
        "grafana",
        "datadog.yml",
    ]

    monitoring_found = any((project_root / f).exists() for f in monitoring_files)

    # Check for performance tracking in code
    perf_patterns = [
        "performance", "metrics", "monitoring", "telemetry",
        "prometheus", "statsd", "datadog",
    ]

    perf_in_code = False
    src_dir = project_root / "src"

    if src_dir.exists():
        for py_file in list(src_dir.rglob("*.py"))[:30]:
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore").lower()
                if any(pattern in content for pattern in perf_patterns):
                    perf_in_code = True
                    break
            except Exception:
                pass

    if not monitoring_found and not perf_in_code:
        findings.append(
            Finding(
                check_id="GOV-016",
                title="Performance Monitoring Not Implemented",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="governance",
                description="No performance monitoring system detected (ISO 9)",
                evidence="No monitoring configuration or instrumentation found",
                remediation="Implement performance monitoring:\n"
                           "1. Define key performance indicators (KPIs)\n"
                           "2. Instrument code with metrics collection\n"
                           "3. Set up monitoring dashboards\n"
                           "4. Configure alerting for anomalies\n"
                           "5. Regular performance review and analysis",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_9", "Clause_9.1"],
            )
        )
    else:
        evidence = "Monitoring configuration found" if monitoring_found else "Performance instrumentation in code"
        findings.append(
            Finding(
                check_id="GOV-016",
                title="Performance Monitoring Implemented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description="Performance monitoring system in place",
                evidence=evidence,
                remediation="N/A",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_9", "Clause_9.1"],
            )
        )

    return findings


def _check_internal_audit(project_root: Path) -> List[Finding]:
    """Check for internal audit program (ISO 9)."""
    findings = []

    audit_docs = [
        "docs/internal_audit.md",
        "AUDIT.md",
        "docs/audit_plan.md",
        "docs/audit_schedule.md",
    ]

    audit_found = any((project_root / doc).exists() for doc in audit_docs)

    if not audit_found:
        findings.append(
            Finding(
                check_id="GOV-017",
                title="Internal Audit Program Not Established",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="governance",
                description="No internal audit program documented (ISO 9.2)",
                evidence="No audit documentation found",
                remediation="Establish internal audit program:\n"
                           "1. Define audit scope and frequency\n"
                           "2. Assign qualified auditors\n"
                           "3. Create audit checklists and procedures\n"
                           "4. Document audit findings and actions\n"
                           "5. Track and verify corrective actions",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_9.2"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="GOV-017",
                title="Internal Audit Program Established",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description="Internal audit program is documented",
                evidence="Audit documentation found",
                remediation="N/A",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_9.2"],
            )
        )

    return findings


def _check_management_review(project_root: Path) -> List[Finding]:
    """Check for management review process (ISO 9)."""
    findings = []

    review_docs = [
        "docs/management_review.md",
        "MANAGEMENT_REVIEW.md",
        "docs/reviews",
    ]

    review_found = any((project_root / doc).exists() for doc in review_docs)

    if not review_found:
        findings.append(
            Finding(
                check_id="GOV-018",
                title="Management Review Process Not Documented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="governance",
                description="No management review process documented (ISO 9.3)",
                evidence="No management review documentation found",
                remediation="Establish management review process:\n"
                           "1. Schedule regular management reviews (quarterly/annually)\n"
                           "2. Review AI system performance and compliance status\n"
                           "3. Assess risks, incidents, and nonconformities\n"
                           "4. Evaluate improvement opportunities\n"
                           "5. Make decisions on resources and changes\n"
                           "6. Document review outcomes and action items",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_9.3"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="GOV-018",
                title="Management Review Process Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description="Management review process is documented",
                evidence="Management review documentation found",
                remediation="N/A",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_9.3"],
            )
        )

    return findings


def _check_stakeholder_communication(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for stakeholder communication plan (ISO 7.4)."""
    findings = []

    comm_docs = [
        "docs/communication_plan.md",
        "COMMUNICATION.md",
        "docs/stakeholders.md",
        "STAKEHOLDERS.md",
    ]

    comm_found = any((project_root / doc).exists() for doc in comm_docs)

    # Check for README or CONTRIBUTING as basic communication
    basic_comm = (project_root / "README.md").exists() or (project_root / "CONTRIBUTING.md").exists()

    if not comm_found:
        severity = Severity.MEDIUM if basic_comm else Severity.HIGH
        findings.append(
            Finding(
                check_id="GOV-019",
                title="Stakeholder Communication Not Planned",
                severity=severity,
                status=Status.WARNING,
                category="governance",
                description="No stakeholder communication plan (ISO 7.4)",
                evidence="No communication plan documentation found",
                remediation="Create stakeholder communication plan:\n"
                           "1. Identify key stakeholders (users, regulators, etc.)\n"
                           "2. Define communication objectives and channels\n"
                           "3. Establish communication schedule and triggers\n"
                           "4. Document escalation procedures\n"
                           "5. Include transparency requirements for AI decisions",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_7.4"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="GOV-019",
                title="Stakeholder Communication Planned",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description="Stakeholder communication plan is documented",
                evidence="Communication plan documentation found",
                remediation="N/A",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_7.4"],
            )
        )

    return findings


def _check_competence_training(project_root: Path) -> List[Finding]:
    """Check for competence and training documentation (ISO 7.2)."""
    findings = []

    training_docs = [
        "docs/training.md",
        "TRAINING.md",
        "docs/onboarding.md",
        "ONBOARDING.md",
        "docs/competence.md",
    ]

    training_found = any((project_root / doc).exists() for doc in training_docs)

    if not training_found:
        findings.append(
            Finding(
                check_id="GOV-020",
                title="Competence and Training Not Documented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="governance",
                description="No competence/training documentation (ISO 7.2)",
                evidence="No training documentation found",
                remediation="Document competence requirements:\n"
                           "1. Define required competencies for AI roles\n"
                           "2. Create training materials and onboarding\n"
                           "3. Establish training schedules and refreshers\n"
                           "4. Track training completion and competence\n"
                           "5. Address AI-specific skills (bias, fairness, safety)",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_7.2"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="GOV-020",
                title="Competence and Training Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description="Competence and training requirements are documented",
                evidence="Training documentation found",
                remediation="N/A",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_7.2"],
            )
        )

    return findings


def _check_documentation_control(project_root: Path) -> List[Finding]:
    """Check for documentation control (ISO 7.5)."""
    findings = []

    # Check for version control
    has_git = (project_root / ".git").exists()

    # Check for documentation standards
    doc_standards = [
        "docs/README.md",
        "DOCUMENTATION.md",
        "docs/standards.md",
    ]

    doc_standards_found = any((project_root / doc).exists() for doc in doc_standards)

    if not has_git:
        findings.append(
            Finding(
                check_id="GOV-021",
                title="Documentation Control Not Implemented",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="governance",
                description="No version control system for documentation (ISO 7.5)",
                evidence="No .git directory found",
                remediation="Implement documentation control:\n"
                           "1. Use version control (Git) for all documentation\n"
                           "2. Define documentation standards and templates\n"
                           "3. Establish review and approval process\n"
                           "4. Control access to documentation\n"
                           "5. Maintain version history and change log",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_7.5"],
            )
        )
    else:
        if not doc_standards_found:
            findings.append(
                Finding(
                    check_id="GOV-021",
                    title="Documentation Standards Not Defined",
                    severity=Severity.LOW,
                    status=Status.WARNING,
                    category="governance",
                    description="Version control in place but no documentation standards",
                    evidence="Git repository exists but no documentation standards file",
                    remediation="Define documentation standards and templates",
                    owasp_mapping=["LLM08"],
                    iso_mapping=["Clause_7.5"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="GOV-021",
                    title="Documentation Control Implemented",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="governance",
                    description="Version control and documentation standards in place",
                    evidence="Git repository and documentation standards found",
                    remediation="N/A",
                    owasp_mapping=["LLM08"],
                    iso_mapping=["Clause_7.5"],
                )
            )

    return findings


def _check_third_party_risk(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for third-party risk management (ISO 8.2)."""
    findings = []

    third_party_docs = [
        "docs/third_party_risk.md",
        "THIRD_PARTY_RISK.md",
        "docs/vendor_management.md",
        "VENDOR_MANAGEMENT.md",
    ]

    third_party_found = any((project_root / doc).exists() for doc in third_party_docs)

    # Check for dependency scanning
    security_files = [
        ".github/dependabot.yml",
        ".github/workflows/security.yml",
        "renovate.json",
    ]

    dependency_scanning = any((project_root / f).exists() for f in security_files)

    if not third_party_found and not dependency_scanning:
        findings.append(
            Finding(
                check_id="GOV-022",
                title="Third-Party Risk Not Managed",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="governance",
                description="No third-party risk management process (ISO 8.2)",
                evidence="No third-party risk documentation or dependency scanning found",
                remediation="Implement third-party risk management:\n"
                           "1. Inventory all third-party components and services\n"
                           "2. Assess security and compliance risks\n"
                           "3. Implement dependency scanning and updates\n"
                           "4. Review vendor security practices\n"
                           "5. Establish SLAs and monitoring",
                owasp_mapping=["LLM03", "LLM05"],
                iso_mapping=["Clause_8.2"],
            )
        )
    else:
        evidence = "Dependency scanning configured" if dependency_scanning else "Third-party risk documented"
        findings.append(
            Finding(
                check_id="GOV-022",
                title="Third-Party Risk Managed",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description="Third-party risk management in place",
                evidence=evidence,
                remediation="N/A",
                owasp_mapping=["LLM03", "LLM05"],
                iso_mapping=["Clause_8.2"],
            )
        )

    return findings


def _check_procurement_controls(project_root: Path) -> List[Finding]:
    """Check for procurement controls (ISO 8.2)."""
    findings = []

    procurement_docs = [
        "docs/procurement.md",
        "PROCUREMENT.md",
        "docs/acquisition_policy.md",
    ]

    procurement_found = any((project_root / doc).exists() for doc in procurement_docs)

    if not procurement_found:
        findings.append(
            Finding(
                check_id="GOV-023",
                title="Procurement Controls Not Documented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="governance",
                description="No procurement control process documented (ISO 8.2)",
                evidence="No procurement documentation found",
                remediation="Document procurement controls:\n"
                           "1. Define approval process for AI components/services\n"
                           "2. Establish security and compliance requirements\n"
                           "3. Require vendor assessments and due diligence\n"
                           "4. Review licensing and usage restrictions\n"
                           "5. Ensure ongoing monitoring and re-assessment",
                owasp_mapping=["LLM03", "LLM05"],
                iso_mapping=["Clause_8.2"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="GOV-023",
                title="Procurement Controls Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description="Procurement control process is documented",
                evidence="Procurement documentation found",
                remediation="N/A",
                owasp_mapping=["LLM03", "LLM05"],
                iso_mapping=["Clause_8.2"],
            )
        )

    return findings


def _check_decommissioning_plan(project_root: Path) -> List[Finding]:
    """Check for AI system decommissioning plan (ISO 8.3)."""
    findings = []

    decom_docs = [
        "docs/decommissioning.md",
        "DECOMMISSIONING.md",
        "docs/sunset_plan.md",
        "docs/retirement_plan.md",
    ]

    decom_found = any((project_root / doc).exists() for doc in decom_docs)

    if not decom_found:
        findings.append(
            Finding(
                check_id="GOV-024",
                title="Decommissioning Plan Not Documented",
                severity=Severity.LOW,
                status=Status.WARNING,
                category="governance",
                description="No AI system decommissioning plan (ISO 8.3)",
                evidence="No decommissioning documentation found",
                remediation="Create decommissioning plan:\n"
                           "1. Define criteria for system retirement\n"
                           "2. Plan for data migration/archival\n"
                           "3. Document knowledge transfer procedures\n"
                           "4. Ensure user communication and transition\n"
                           "5. Address legal/regulatory retention requirements",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8.3"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="GOV-024",
                title="Decommissioning Plan Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description="AI system decommissioning plan is documented",
                evidence="Decommissioning documentation found",
                remediation="N/A",
                owasp_mapping=["LLM06"],
                iso_mapping=["Clause_8.3"],
            )
        )

    return findings


def _check_incident_learning(project_root: Path) -> List[Finding]:
    """Check for incident learning and improvement (ISO 10.2)."""
    findings = []

    incident_docs = [
        "docs/incident_postmortems.md",
        "POSTMORTEMS.md",
        "docs/lessons_learned.md",
        "LESSONS_LEARNED.md",
        "docs/incidents",
    ]

    incident_found = any((project_root / doc).exists() for doc in incident_docs)

    if not incident_found:
        findings.append(
            Finding(
                check_id="GOV-025",
                title="Incident Learning Not Documented",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="governance",
                description="No incident learning process documented (ISO 10.2)",
                evidence="No incident learning documentation found",
                remediation="Implement incident learning process:\n"
                           "1. Conduct post-incident reviews (blameless postmortems)\n"
                           "2. Document root causes and contributing factors\n"
                           "3. Identify improvement actions and preventive measures\n"
                           "4. Track implementation of improvements\n"
                           "5. Share lessons learned across organization",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_10.2"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="GOV-025",
                title="Incident Learning Documented",
                severity=Severity.INFO,
                status=Status.PASS,
                category="governance",
                description="Incident learning process is documented",
                evidence="Incident learning documentation found",
                remediation="N/A",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_10.2"],
            )
        )

    return findings
