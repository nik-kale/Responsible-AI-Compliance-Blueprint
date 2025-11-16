"""Evaluator for running all compliance checks."""

from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..config.schema import (
    ProjectConfig,
    Finding,
    AssessmentReport,
    Severity,
    Status,
)
from ..checks import (
    data_integrity,
    model_artifacts,
    supply_chain,
    pii_privacy,
    inference_security,
    logging_audit,
    governance,
)

console = Console()


def run_all_checks(
    config: ProjectConfig,
    project_root: Path,
    env: str = "prod",
    verbose: bool = False,
) -> AssessmentReport:
    """
    Run all compliance checks and generate assessment report.

    Args:
        config: Project configuration
        project_root: Project root directory
        env: Environment to check
        verbose: Enable verbose output

    Returns:
        AssessmentReport with all findings
    """
    all_findings: List[Finding] = []

    # Define check modules
    check_modules = [
        ("Data Integrity", data_integrity),
        ("Model Artifacts", model_artifacts),
        ("Supply Chain", supply_chain),
        ("PII/Privacy", pii_privacy),
        ("Inference Security", inference_security),
        ("Logging & Audit", logging_audit),
        ("Governance", governance),
    ]

    if verbose:
        console.print(f"\n[bold blue]Running compliance checks for environment: {env}[/bold blue]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        for check_name, check_module in check_modules:
            task = progress.add_task(f"Running {check_name} checks...", total=None)

            try:
                findings = check_module.run_checks(config, project_root, env)
                all_findings.extend(findings)

                if verbose:
                    pass_count = sum(1 for f in findings if f.status == Status.PASS)
                    fail_count = sum(1 for f in findings if f.status == Status.FAIL)
                    console.print(
                        f"  {check_name}: {len(findings)} checks "
                        f"({pass_count} passed, {fail_count} failed)"
                    )

            except Exception as e:
                console.print(f"  [red]Error in {check_name}: {str(e)}[/red]")
                # Add error finding
                all_findings.append(
                    Finding(
                        check_id=f"ERROR-{check_name.replace(' ', '_').upper()}",
                        title=f"Check Module Error: {check_name}",
                        severity=Severity.HIGH,
                        status=Status.ERROR,
                        category="system",
                        description=f"Error running {check_name} checks",
                        evidence=str(e),
                        remediation="Check system logs and configuration",
                        owasp_mapping=[],
                        iso_mapping=[],
                    )
                )

            progress.remove_task(task)

    # Generate summary statistics
    summary = _generate_summary(all_findings)

    # Create risk matrix
    risk_matrix = _generate_risk_matrix(config)

    # Create assessment report
    report = AssessmentReport(
        project_name=config.project.name,
        version=config.project.version,
        environment=env,
        assessment_date=datetime.now().isoformat(),
        assessor=config.assessor,
        findings=all_findings,
        summary=summary,
        risk_matrix=risk_matrix,
        total_checks=len(all_findings),
        passed_checks=summary["passed"],
        failed_checks=summary["failed"],
        warnings=summary["warnings"],
    )

    if verbose:
        _print_summary(summary)

    return report


def _generate_summary(findings: List[Finding]) -> Dict[str, Any]:
    """Generate summary statistics from findings."""
    summary = {
        "total": len(findings),
        "passed": 0,
        "failed": 0,
        "warnings": 0,
        "skipped": 0,
        "errors": 0,
        "by_severity": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
        "by_category": {},
        "critical_findings": [],
    }

    for finding in findings:
        # Status counts
        if finding.status == Status.PASS:
            summary["passed"] += 1
        elif finding.status == Status.FAIL:
            summary["failed"] += 1
        elif finding.status == Status.WARNING:
            summary["warnings"] += 1
        elif finding.status == Status.SKIP:
            summary["skipped"] += 1
        elif finding.status == Status.ERROR:
            summary["errors"] += 1

        # Severity counts
        severity_key = finding.severity.value
        summary["by_severity"][severity_key] = summary["by_severity"].get(severity_key, 0) + 1

        # Category counts
        category = finding.category
        if category not in summary["by_category"]:
            summary["by_category"][category] = {
                "total": 0,
                "passed": 0,
                "failed": 0,
            }
        summary["by_category"][category]["total"] += 1
        if finding.status == Status.PASS:
            summary["by_category"][category]["passed"] += 1
        elif finding.status == Status.FAIL:
            summary["by_category"][category]["failed"] += 1

        # Critical findings
        if finding.severity == Severity.CRITICAL and finding.status == Status.FAIL:
            summary["critical_findings"].append(finding)

    return summary


def _generate_risk_matrix(config: ProjectConfig) -> Dict[str, Any]:
    """Generate risk matrix data from threats."""
    matrix = {
        "threats_by_risk": {},
        "total_threats": len(config.threats),
        "high_risk_count": 0,
    }

    likelihood_scores = {
        "very_low": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "very_high": 5,
    }

    impact_scores = {
        "negligible": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5,
    }

    for threat in config.threats:
        likelihood = likelihood_scores.get(threat.likelihood.value, 3)
        impact = impact_scores.get(threat.impact.value, 3)
        risk_score = likelihood * impact

        key = f"{threat.likelihood.value}_{threat.impact.value}"
        if key not in matrix["threats_by_risk"]:
            matrix["threats_by_risk"][key] = []

        matrix["threats_by_risk"][key].append(
            {
                "id": threat.id,
                "title": threat.title,
                "likelihood": threat.likelihood.value,
                "impact": threat.impact.value,
                "risk_score": risk_score,
            }
        )

        # Count high risk (score >= 12)
        if risk_score >= 12:
            matrix["high_risk_count"] += 1

    return matrix


def _print_summary(summary: Dict[str, Any]) -> None:
    """Print summary to console."""
    console.print("\n[bold]Assessment Summary[/bold]")
    console.print(f"Total Checks: {summary['total']}")
    console.print(f"  ✓ Passed:   {summary['passed']}")
    console.print(f"  ✗ Failed:   {summary['failed']}")
    console.print(f"  ⚠ Warnings: {summary['warnings']}")
    console.print(f"  ○ Skipped:  {summary['skipped']}")

    if summary['errors'] > 0:
        console.print(f"  [red]⚠ Errors:   {summary['errors']}[/red]")

    console.print("\n[bold]By Severity:[/bold]")
    for severity, count in summary["by_severity"].items():
        if count > 0:
            console.print(f"  {severity.title()}: {count}")

    if summary["critical_findings"]:
        console.print(f"\n[bold red]⚠ {len(summary['critical_findings'])} CRITICAL findings require immediate attention[/bold red]")


def get_exit_code(report: AssessmentReport) -> int:
    """
    Get exit code based on report findings.

    Returns:
        0 if all checks passed
        1 if any critical findings
        2 if any high severity failures
        3 if any failures
    """
    has_critical = any(
        f.severity == Severity.CRITICAL and f.status == Status.FAIL
        for f in report.findings
    )

    has_high = any(
        f.severity == Severity.HIGH and f.status == Status.FAIL
        for f in report.findings
    )

    has_failures = report.failed_checks > 0

    if has_critical:
        return 1
    elif has_high:
        return 2
    elif has_failures:
        return 3
    else:
        return 0
