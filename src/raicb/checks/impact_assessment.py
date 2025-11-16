"""Impact assessment checks for fairness, bias, and stakeholder impact (ISO Clause 8.2)."""

from pathlib import Path
from typing import List
import json

from ..config.schema import ProjectConfig, Finding, Severity, Status
from ..core.logger import get_logger
from ..core.loader import resolve_path

logger = get_logger(__name__)


def run_checks(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """
    Run impact assessment checks.

    Covers:
    - ISO/IEC 42001 Clause 8.2: Impact Assessment
    - OWASP LLM06: Sensitive Information Disclosure (fairness aspect)
    - OWASP LLM08: Excessive Agency (impact control)
    - OWASP LLM09: Overreliance (bias awareness)

    Args:
        config: Project configuration
        project_root: Root directory of the project
        env: Environment (dev/staging/prod)

    Returns:
        List of findings from impact assessment checks
    """
    logger.info("Running impact assessment checks")

    findings = []

    # IMPACT-001: Fairness assessment
    findings.extend(_check_fairness_assessment(config, project_root))

    # IMPACT-002: Bias testing
    findings.extend(_check_bias_testing(config, project_root))

    # IMPACT-003: Algorithmic impact assessment
    findings.extend(_check_algorithmic_impact(config, project_root))

    # IMPACT-004: Stakeholder impact analysis
    findings.extend(_check_stakeholder_impact(config, project_root))

    # IMPACT-005: Environmental impact
    findings.extend(_check_environmental_impact(config, project_root))

    # IMPACT-006: Demographic parity
    findings.extend(_check_demographic_parity(config, project_root))

    # IMPACT-007: Equal opportunity metrics
    findings.extend(_check_equal_opportunity(config, project_root))

    # IMPACT-008: Disparate impact analysis
    findings.extend(_check_disparate_impact(config, project_root))

    # IMPACT-009: Accessibility compliance
    findings.extend(_check_accessibility(config, project_root))

    # IMPACT-010: Societal impact assessment
    findings.extend(_check_societal_impact(config, project_root))

    logger.info(f"Impact assessment checks complete: {len(findings)} findings")
    return findings


def _check_fairness_assessment(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if fairness assessment has been documented."""
    fairness_files = [
        "fairness_assessment.md",
        "fairness_report.md",
        "FAIRNESS.md",
        "docs/fairness.md",
        "docs/fairness_assessment.md",
    ]

    fairness_exists = any((project_root / f).exists() for f in fairness_files)

    if not fairness_exists:
        return [
            Finding(
                check_id="IMPACT-001",
                title="Missing Fairness Assessment",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="Impact Assessment",
                description="No fairness assessment documentation found. ISO/IEC 42001 Clause 8.2 requires assessment of fairness and bias impacts.",
                evidence=f"Checked for: {', '.join(fairness_files)}",
                remediation="Create a fairness assessment document that:\n"
                           "1. Identifies protected characteristics (race, gender, age, etc.)\n"
                           "2. Documents fairness metrics used (demographic parity, equal opportunity, etc.)\n"
                           "3. Reports fairness testing results across subgroups\n"
                           "4. Identifies mitigation strategies for unfair outcomes\n"
                           "5. Establishes ongoing monitoring processes",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_8.2"],
            )
        ]

    # Check if fairness assessment is comprehensive
    fairness_file = next((project_root / f for f in fairness_files if (project_root / f).exists()), None)

    if fairness_file:
        content = fairness_file.read_text(encoding="utf-8", errors="ignore")

        # Check for key sections
        required_sections = [
            ("protected", "protected characteristics or attributes"),
            ("metric", "fairness metrics"),
            ("test", "testing or evaluation"),
            ("mitigation", "mitigation strategies"),
        ]

        missing_sections = [desc for keyword, desc in required_sections if keyword not in content.lower()]

        if missing_sections:
            return [
                Finding(
                    check_id="IMPACT-001",
                    title="Incomplete Fairness Assessment",
                    severity=Severity.MEDIUM,
                    status=Status.WARNING,
                    category="Impact Assessment",
                    description=f"Fairness assessment exists but is missing key sections: {', '.join(missing_sections)}",
                    evidence=f"Found: {fairness_file.name}",
                    remediation=f"Update fairness assessment to include: {', '.join(missing_sections)}",
                    owasp_mapping=["LLM09"],
                    iso_mapping=["Clause_8.2"],
                )
            ]

    return [
        Finding(
            check_id="IMPACT-001",
            title="Fairness Assessment Documented",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Impact Assessment",
            description="Fairness assessment documentation found and appears comprehensive.",
            evidence=f"Found: {fairness_file.name if fairness_file else 'fairness documentation'}",
            remediation="",
            owasp_mapping=["LLM09"],
            iso_mapping=["Clause_8.2"],
        )
    ]


def _check_bias_testing(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if bias testing has been performed and documented."""
    bias_test_paths = [
        "tests/test_bias.py",
        "tests/bias/",
        "tests/fairness/",
        "bias_testing_results.json",
        "docs/bias_testing.md",
    ]

    bias_tests_exist = any(
        (project_root / p).exists() for p in bias_test_paths
    )

    if not bias_tests_exist:
        return [
            Finding(
                check_id="IMPACT-002",
                title="Missing Bias Testing",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="Impact Assessment",
                description="No bias testing implementation found. Models must be tested for bias across demographic groups.",
                evidence=f"Checked for: {', '.join(bias_test_paths)}",
                remediation="Implement bias testing:\n"
                           "1. Create test suite for bias detection (tests/test_bias.py)\n"
                           "2. Test model predictions across demographic subgroups\n"
                           "3. Measure disparate impact and statistical parity\n"
                           "4. Document bias testing methodology and results\n"
                           "5. Establish thresholds for acceptable bias levels",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_8.2"],
            )
        ]

    return [
        Finding(
            check_id="IMPACT-002",
            title="Bias Testing Implemented",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Impact Assessment",
            description="Bias testing artifacts found.",
            evidence=f"Found bias testing in project",
            remediation="",
            owasp_mapping=["LLM09"],
            iso_mapping=["Clause_8.2"],
        )
    ]


def _check_algorithmic_impact(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if algorithmic impact assessment has been performed."""
    aia_files = [
        "algorithmic_impact_assessment.md",
        "AIA.md",
        "docs/algorithmic_impact.md",
        "docs/aia.md",
        "impact_assessment.json",
    ]

    aia_exists = any((project_root / f).exists() for f in aia_files)

    if not aia_exists:
        return [
            Finding(
                check_id="IMPACT-003",
                title="Missing Algorithmic Impact Assessment",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="Impact Assessment",
                description="No Algorithmic Impact Assessment (AIA) found. Required for high-risk AI systems under ISO 8.2 and regulatory frameworks.",
                evidence=f"Checked for: {', '.join(aia_files)}",
                remediation="Create an Algorithmic Impact Assessment that:\n"
                           "1. Describes the algorithmic decision-making process\n"
                           "2. Identifies potential harms and benefits\n"
                           "3. Assesses impact on different stakeholder groups\n"
                           "4. Documents mitigation measures for negative impacts\n"
                           "5. Establishes monitoring and review processes\n"
                           "6. Considers regulatory requirements (EU AI Act, etc.)",
                owasp_mapping=["LLM08", "LLM09"],
                iso_mapping=["Clause_8.2"],
            )
        ]

    return [
        Finding(
            check_id="IMPACT-003",
            title="Algorithmic Impact Assessment Found",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Impact Assessment",
            description="Algorithmic Impact Assessment documentation exists.",
            evidence="AIA documentation found",
            remediation="",
            owasp_mapping=["LLM08", "LLM09"],
            iso_mapping=["Clause_8.2"],
        )
    ]


def _check_stakeholder_impact(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if stakeholder impact analysis has been performed."""
    stakeholder_files = [
        "stakeholder_analysis.md",
        "STAKEHOLDERS.md",
        "docs/stakeholders.md",
        "docs/stakeholder_impact.md",
    ]

    stakeholder_exists = any((project_root / f).exists() for f in stakeholder_files)

    if not stakeholder_exists:
        return [
            Finding(
                check_id="IMPACT-004",
                title="Missing Stakeholder Impact Analysis",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                category="Impact Assessment",
                description="No stakeholder impact analysis found. ISO 8.2 requires identification and assessment of impacts on different stakeholder groups.",
                evidence=f"Checked for: {', '.join(stakeholder_files)}",
                remediation="Create stakeholder impact analysis:\n"
                           "1. Identify all stakeholder groups (users, affected parties, society)\n"
                           "2. Assess positive and negative impacts on each group\n"
                           "3. Prioritize stakeholders by impact severity\n"
                           "4. Document engagement and consultation processes\n"
                           "5. Establish feedback mechanisms",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_8.2"],
            )
        ]

    return [
        Finding(
            check_id="IMPACT-004",
            title="Stakeholder Impact Analysis Found",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Impact Assessment",
            description="Stakeholder impact analysis documentation exists.",
            evidence="Stakeholder documentation found",
            remediation="",
            owasp_mapping=["LLM08"],
            iso_mapping=["Clause_8.2"],
        )
    ]


def _check_environmental_impact(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if environmental impact has been assessed."""
    env_files = [
        "environmental_impact.md",
        "carbon_footprint.md",
        "docs/environmental_impact.md",
        "docs/sustainability.md",
    ]

    env_exists = any((project_root / f).exists() for f in env_files)

    # Also check config for carbon tracking
    has_carbon_config = hasattr(config, "sustainability") or hasattr(config, "carbon_tracking")

    if not env_exists and not has_carbon_config:
        return [
            Finding(
                check_id="IMPACT-005",
                title="Missing Environmental Impact Assessment",
                severity=Severity.LOW,
                status=Status.WARNING,
                category="Impact Assessment",
                description="No environmental impact assessment found. Consider documenting carbon footprint and sustainability measures.",
                evidence=f"Checked for: {', '.join(env_files)}",
                remediation="Document environmental impact:\n"
                           "1. Estimate carbon footprint of model training\n"
                           "2. Estimate carbon footprint of inference\n"
                           "3. Document energy consumption and efficiency measures\n"
                           "4. Consider using carbon tracking tools (CodeCarbon, etc.)\n"
                           "5. Establish sustainability goals",
                owasp_mapping=[],
                iso_mapping=["Clause_8.2"],
            )
        ]

    return [
        Finding(
            check_id="IMPACT-005",
            title="Environmental Impact Documented",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Impact Assessment",
            description="Environmental impact assessment or carbon tracking found.",
            evidence="Environmental documentation found",
            remediation="",
            owasp_mapping=[],
            iso_mapping=["Clause_8.2"],
        )
    ]


def _check_demographic_parity(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if demographic parity metrics are tracked."""
    metrics_files = [
        "fairness_metrics.json",
        "metrics/fairness/",
        "reports/fairness/",
    ]

    metrics_exist = any((project_root / f).exists() for f in metrics_files)

    if metrics_exist:
        # Check if demographic parity is specifically measured
        for metrics_path in metrics_files:
            full_path = project_root / metrics_path
            if full_path.exists():
                if full_path.is_file() and metrics_path.endswith(".json"):
                    try:
                        metrics_data = json.loads(full_path.read_text())
                        if "demographic_parity" in str(metrics_data).lower():
                            return [
                                Finding(
                                    check_id="IMPACT-006",
                                    title="Demographic Parity Tracked",
                                    severity=Severity.INFO,
                                    status=Status.PASS,
                                    category="Impact Assessment",
                                    description="Demographic parity metrics are being tracked.",
                                    evidence=f"Found in {full_path.name}",
                                    remediation="",
                                    owasp_mapping=["LLM09"],
                                    iso_mapping=["Clause_8.2"],
                                )
                            ]
                    except Exception as e:
                        logger.warning(f"Error reading metrics file: {e}")

    return [
        Finding(
            check_id="IMPACT-006",
            title="Demographic Parity Not Tracked",
            severity=Severity.MEDIUM,
            status=Status.WARNING,
            category="Impact Assessment",
            description="No evidence of demographic parity tracking. This metric measures equal positive prediction rates across groups.",
            evidence=f"Checked for: {', '.join(metrics_files)}",
            remediation="Implement demographic parity measurement:\n"
                       "1. Define protected attributes (race, gender, age, etc.)\n"
                       "2. Calculate P(Ŷ=1|A=a) for each group\n"
                       "3. Demographic parity satisfied if ratios are approximately equal\n"
                       "4. Set threshold (e.g., 0.8-1.2 ratio)\n"
                       "5. Monitor continuously and document results",
            owasp_mapping=["LLM09"],
            iso_mapping=["Clause_8.2"],
        )
    ]


def _check_equal_opportunity(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if equal opportunity metrics are tracked."""
    metrics_files = [
        "fairness_metrics.json",
        "metrics/fairness/",
        "reports/fairness/",
    ]

    metrics_exist = any((project_root / f).exists() for f in metrics_files)

    if metrics_exist:
        for metrics_path in metrics_files:
            full_path = project_root / metrics_path
            if full_path.exists() and full_path.is_file() and metrics_path.endswith(".json"):
                try:
                    metrics_data = json.loads(full_path.read_text())
                    if "equal_opportunity" in str(metrics_data).lower() or "tpr" in str(metrics_data).lower():
                        return [
                            Finding(
                                check_id="IMPACT-007",
                                title="Equal Opportunity Tracked",
                                severity=Severity.INFO,
                                status=Status.PASS,
                                category="Impact Assessment",
                                description="Equal opportunity metrics (True Positive Rate parity) are being tracked.",
                                evidence=f"Found in {full_path.name}",
                                remediation="",
                                owasp_mapping=["LLM09"],
                                iso_mapping=["Clause_8.2"],
                            )
                        ]
                except Exception as e:
                    logger.warning(f"Error reading metrics file: {e}")

    return [
        Finding(
            check_id="IMPACT-007",
            title="Equal Opportunity Not Tracked",
            severity=Severity.MEDIUM,
            status=Status.WARNING,
            category="Impact Assessment",
            description="No evidence of equal opportunity tracking. This metric ensures equal True Positive Rates across groups.",
            evidence=f"Checked for: {', '.join(metrics_files)}",
            remediation="Implement equal opportunity measurement:\n"
                       "1. Calculate TPR = TP/(TP+FN) for each protected group\n"
                       "2. Equal opportunity satisfied if TPR is similar across groups\n"
                       "3. This is critical for high-stakes decisions (loan approvals, hiring, etc.)\n"
                       "4. Set acceptable TPR ratio threshold\n"
                       "5. Monitor and report regularly",
            owasp_mapping=["LLM09"],
            iso_mapping=["Clause_8.2"],
        )
    ]


def _check_disparate_impact(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if disparate impact analysis has been performed."""
    analysis_files = [
        "disparate_impact_analysis.md",
        "docs/disparate_impact.md",
        "fairness_metrics.json",
    ]

    analysis_exists = any((project_root / f).exists() for f in analysis_files)

    if not analysis_exists:
        return [
            Finding(
                check_id="IMPACT-008",
                title="Missing Disparate Impact Analysis",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                category="Impact Assessment",
                description="No disparate impact analysis found. Required for compliance with anti-discrimination laws.",
                evidence=f"Checked for: {', '.join(analysis_files)}",
                remediation="Perform disparate impact analysis:\n"
                           "1. Calculate selection rates for protected and unprotected groups\n"
                           "2. Apply 80% rule: P(Ŷ=1|Protected) / P(Ŷ=1|Unprotected) ≥ 0.8\n"
                           "3. If ratio < 0.8, disparate impact may exist\n"
                           "4. Document findings and mitigation strategies\n"
                           "5. Consult legal counsel if disparate impact detected",
                owasp_mapping=["LLM09"],
                iso_mapping=["Clause_8.2"],
            )
        ]

    return [
        Finding(
            check_id="IMPACT-008",
            title="Disparate Impact Analysis Found",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Impact Assessment",
            description="Disparate impact analysis documentation exists.",
            evidence="Disparate impact analysis found",
            remediation="",
            owasp_mapping=["LLM09"],
            iso_mapping=["Clause_8.2"],
        )
    ]


def _check_accessibility(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if accessibility compliance has been assessed."""
    accessibility_files = [
        "ACCESSIBILITY.md",
        "accessibility.md",
        "docs/accessibility.md",
        "a11y.md",
        "WCAG_compliance.md",
    ]

    accessibility_exists = any((project_root / f).exists() for f in accessibility_files)

    if not accessibility_exists:
        return [
            Finding(
                check_id="IMPACT-009",
                title="Missing Accessibility Assessment",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="Impact Assessment",
                description="No accessibility compliance assessment found. AI systems should be accessible to users with disabilities.",
                evidence=f"Checked for: {', '.join(accessibility_files)}",
                remediation="Document accessibility compliance:\n"
                           "1. Assess WCAG 2.1 Level AA compliance for UI components\n"
                           "2. Ensure model outputs are accessible (alt text, transcripts, etc.)\n"
                           "3. Test with assistive technologies (screen readers, etc.)\n"
                           "4. Document accessibility features and limitations\n"
                           "5. Establish accessibility testing processes",
                owasp_mapping=[],
                iso_mapping=["Clause_8.2"],
            )
        ]

    return [
        Finding(
            check_id="IMPACT-009",
            title="Accessibility Assessment Found",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Impact Assessment",
            description="Accessibility compliance documentation exists.",
            evidence="Accessibility documentation found",
            remediation="",
            owasp_mapping=[],
            iso_mapping=["Clause_8.2"],
        )
    ]


def _check_societal_impact(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if broader societal impact has been assessed."""
    societal_files = [
        "societal_impact.md",
        "SOCIETAL_IMPACT.md",
        "docs/societal_impact.md",
        "ethics_assessment.md",
        "docs/ethics.md",
    ]

    societal_exists = any((project_root / f).exists() for f in societal_files)

    if not societal_exists:
        return [
            Finding(
                check_id="IMPACT-010",
                title="Missing Societal Impact Assessment",
                severity=Severity.LOW,
                status=Status.WARNING,
                category="Impact Assessment",
                description="No broader societal impact assessment found. Consider documenting potential societal effects.",
                evidence=f"Checked for: {', '.join(societal_files)}",
                remediation="Document societal impact:\n"
                           "1. Identify potential positive societal impacts\n"
                           "2. Identify potential negative societal impacts\n"
                           "3. Consider dual-use concerns\n"
                           "4. Assess impact on employment, privacy, autonomy, democracy, etc.\n"
                           "5. Engage with ethicists and affected communities\n"
                           "6. Document ethical considerations and principles",
                owasp_mapping=["LLM08"],
                iso_mapping=["Clause_8.2"],
            )
        ]

    return [
        Finding(
            check_id="IMPACT-010",
            title="Societal Impact Assessment Found",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Impact Assessment",
            description="Societal impact assessment documentation exists.",
            evidence="Societal impact documentation found",
            remediation="",
            owasp_mapping=["LLM08"],
            iso_mapping=["Clause_8.2"],
        )
    ]
