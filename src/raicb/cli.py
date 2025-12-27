"""CLI for Responsible AI Compliance Blueprint."""

import shutil
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table
import yaml

from .config.schema import ProjectConfig, Severity, Status
from .core.loader import load_config, save_config
from .core.evaluator import run_all_checks, get_exit_code
from .core.report import generate_report, generate_sbom
from .core.mapping import generate_mapping_table, get_owasp_description, get_iso_description
from .core.utils import get_project_root
from .core.baseline import Baseline
from .core.cache import CheckCache
from .core.plugin import PluginManager
from .core.dashboard import TrendTracker
from .core.remediation import RemediationWizard
from .integrations.webhook import WebhookIntegration
from .integrations.sarif import SARIFExporter

app = typer.Typer(
    name="raicb",
    help="Responsible AI Compliance Blueprint - Self-audit toolkit for AI systems",
    add_completion=False,
)

console = Console()


@app.command()
def init(
    path: Path = typer.Argument(
        Path.cwd(),
        help="Directory to initialize (default: current directory)",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing files",
    ),
):
    """
    Initialize a new compliance project with sample files.
    """
    console.print("[bold blue]Initializing Responsible AI Compliance Blueprint project...[/bold blue]\n")

    # Get template directory
    template_dir = Path(__file__).parent.parent.parent / "examples" / "sample_project"

    if not template_dir.exists():
        console.print("[red]Error: Sample project template not found.[/red]")
        console.print(f"Expected at: {template_dir}")
        raise typer.Exit(1)

    # Check if target already has raicb.yaml
    target_config = path / "raicb.yaml"
    if target_config.exists() and not force:
        console.print(f"[yellow]Warning: {target_config} already exists.[/yellow]")
        console.print("Use --force to overwrite.")
        raise typer.Exit(1)

    # Copy template files
    try:
        # Create directories
        (path / "artifacts").mkdir(exist_ok=True)
        (path / "logs").mkdir(exist_ok=True)
        (path / "governance").mkdir(exist_ok=True)

        # Copy configuration files
        if template_dir.exists():
            for item in template_dir.rglob("*"):
                if item.is_file():
                    rel_path = item.relative_to(template_dir)
                    target = path / rel_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, target)
                    console.print(f"  Created: {rel_path}")

        console.print(f"\n[green]✓ Project initialized at {path}[/green]")
        console.print("\nNext steps:")
        console.print("  1. Review and customize raicb.yaml")
        console.print("  2. Run 'raicb validate' to check configuration")
        console.print("  3. Run 'raicb run' to perform assessment")

    except Exception as e:
        console.print(f"[red]Error initializing project: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def validate(
    config: Path = typer.Option(
        Path("raicb.yaml"),
        "--config",
        "-c",
        help="Path to configuration file",
    ),
):
    """
    Validate project configuration.
    """
    console.print("[bold blue]Validating configuration...[/bold blue]\n")

    if not config.exists():
        console.print(f"[red]Error: Configuration file not found: {config}[/red]")
        raise typer.Exit(1)

    try:
        # Load and validate configuration
        project_config = load_config(config, validate=True)

        console.print("[green]✓ Configuration is valid[/green]\n")

        # Display summary
        console.print("[bold]Project Information:[/bold]")
        console.print(f"  Name: {project_config.project.name}")
        console.print(f"  Version: {project_config.project.version}")
        console.print(f"  Owners: {len(project_config.project.owners)}")

        console.print("\n[bold]Configuration Summary:[/bold]")
        console.print(f"  Threats: {len(project_config.threats)}")
        console.print(f"  Controls: {len(project_config.controls)}")
        console.print(f"  Environments: {len(project_config.environments)}")

        if project_config.artifacts.model_path:
            console.print(f"  Model: {project_config.artifacts.model_path}")

        console.print("\n[green]✓ Validation successful[/green]")

    except Exception as e:
        console.print(f"[red]✗ Validation failed:[/red]")
        console.print(f"  {str(e)}")
        raise typer.Exit(1)


@app.command()
def run(
    config: Path = typer.Option(
        Path("raicb.yaml"),
        "--config",
        "-c",
        help="Path to configuration file",
    ),
    env: str = typer.Option(
        "prod",
        "--env",
        "-e",
        help="Environment to assess (dev/stage/prod)",
    ),
    out: Path = typer.Option(
        Path("./reports"),
        "--out",
        "-o",
        help="Output directory for reports",
    ),
    format: str = typer.Option(
        "md,html",
        "--format",
        "-f",
        help="Report formats (comma-separated: md,html,pdf,sarif)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Verbose output",
    ),
    fail_on: str = typer.Option(
        "critical",
        "--fail-on",
        help="Exit with error on severity level (critical/high/medium/any)",
    ),
    cache: bool = typer.Option(
        False,
        "--cache",
        help="Enable caching for faster subsequent runs",
    ),
    webhook_url: Optional[str] = typer.Option(
        None,
        "--webhook",
        help="POST results to webhook URL",
    ),
    track: bool = typer.Option(
        False,
        "--track",
        help="Record assessment in trends database",
    ),
    metrics_port: Optional[int] = typer.Option(
        None,
        "--metrics-port",
        help="Expose Prometheus metrics on specified port",
    ),
):
    """
    Run compliance checks and generate reports.
    """
    console.print("[bold blue]Running Compliance Assessment[/bold blue]\n")

    # Start metrics server if requested
    if metrics_port:
        try:
            from prometheus_client import start_http_server
            start_http_server(metrics_port)
            console.print(f"[blue]Metrics server running on port {metrics_port}[/blue]")
        except Exception as e:
            console.print(f"[yellow]Failed to start metrics server: {e}[/yellow]")

    # Validate inputs
    if not config.exists():
        console.print(f"[red]Error: Configuration file not found: {config}[/red]")
        raise typer.Exit(1)

    # Load configuration
    try:
        project_config = load_config(config)
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        raise typer.Exit(1)

    # Get project root
    try:
        project_root = config.parent.resolve()
    except Exception:
        project_root = Path.cwd()

    # Run checks
    try:
        report = run_all_checks(
            project_config,
            project_root,
            env,
            verbose,
            use_cache=cache,
            config_path=config,
            plugins_dir=Path("./plugins") if Path("./plugins").exists() else None,
        )
    except Exception as e:
        console.print(f"[red]Error running checks: {e}[/red]")
        raise typer.Exit(1)

    # Generate reports
    formats = [f.strip() for f in format.split(",")]
    generated_files = []

    try:
        console.print(f"\n[bold]Generating reports in {out}...[/bold]")

        # Handle SARIF separately
        if "sarif" in formats:
            formats.remove("sarif")
            sarif_exporter = SARIFExporter()
            sarif_path = out / f"raicb-{env}.sarif"
            sarif_exporter.export_report(report, sarif_path)
            generated_files.append(sarif_path)
            console.print(f"  ✓ {sarif_path}")

        # Always generate JSON for baseline/fix commands
        if "json" not in formats:
            formats.append("json")

        # Generate standard reports
        if formats:
            standard_files = generate_report(report, out, formats)
            generated_files.extend(standard_files)
            for file_path in standard_files:
                console.print(f"  ✓ {file_path}")

        console.print(f"\n[green]✓ Reports generated successfully[/green]")

    except Exception as e:
        console.print(f"[red]Error generating reports: {e}[/red]")
        raise typer.Exit(1)

    # Post to webhook if requested
    if webhook_url:
        try:
            console.print(f"\n[bold]Posting to webhook...[/bold]")
            webhook = WebhookIntegration(webhook_url)
            success = webhook.post_report(report, format="summary")
            if success:
                console.print("[green]✓ Posted to webhook successfully[/green]")
            else:
                console.print("[yellow]⚠ Failed to post to webhook[/yellow]")
        except Exception as e:
            console.print(f"[yellow]⚠ Webhook error: {e}[/yellow]")

    # Record in trends database if requested
    if track:
        try:
            console.print(f"\n[bold]Recording assessment in trends...[/bold]")
            tracker = TrendTracker()
            assessment_id = tracker.record_assessment(report)
            if assessment_id > 0:
                console.print(f"[green]✓ Recorded assessment (ID: {assessment_id})[/green]")
            else:
                console.print("[yellow]⚠ Failed to record assessment[/yellow]")
        except Exception as e:
            console.print(f"[yellow]⚠ Trend tracking error: {e}[/yellow]")

    # Print summary
    console.print(f"\n[bold]Assessment Complete[/bold]")
    console.print(f"  Total Checks: {report.total_checks}")
    console.print(f"  Passed: {report.passed_checks}")
    console.print(f"  Failed: {report.failed_checks}")
    console.print(f"  Warnings: {report.warnings}")

    # Determine exit code based on fail-on parameter
    exit_code = 0

    if fail_on == "any" and report.failed_checks > 0:
        exit_code = 1
    elif fail_on == "medium":
        if any(f.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM] and f.status == Status.FAIL
               for f in report.findings):
            exit_code = 1
    elif fail_on == "high":
        if any(f.severity in [Severity.CRITICAL, Severity.HIGH] and f.status == Status.FAIL
               for f in report.findings):
            exit_code = 1
    elif fail_on == "critical":
        if any(f.severity == Severity.CRITICAL and f.status == Status.FAIL
               for f in report.findings):
            exit_code = 1

    if exit_code != 0:
        console.print(f"\n[red]✗ Assessment failed (--fail-on {fail_on})[/red]")

    raise typer.Exit(exit_code)


@app.command()
def sbom(
    output: Path = typer.Option(
        Path("sbom.json"),
        "--output",
        "-o",
        help="Output file for SBOM",
    ),
):
    """
    Generate Software Bill of Materials (SBOM) for dependencies.
    """
    console.print("[bold blue]Generating SBOM...[/bold blue]\n")

    try:
        generate_sbom(output)
        console.print(f"[green]✓ SBOM generated: {output}[/green]")

    except Exception as e:
        console.print(f"[red]Error generating SBOM: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def map(
    config: Path = typer.Option(
        Path("raicb.yaml"),
        "--config",
        "-c",
        help="Path to configuration file",
    ),
    framework: str = typer.Option(
        "all",
        "--framework",
        "-f",
        help="Framework to display (owasp/iso/all)",
    ),
):
    """
    Display framework mappings.
    """
    console.print("[bold blue]Framework Mappings[/bold blue]\n")

    if framework in ["owasp", "all"]:
        console.print("[bold]OWASP AI Security Top 10[/bold]\n")

        table = Table(show_header=True, header_style="bold")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Description")

        from .core.mapping import OWASP_MAPPING

        for owasp_id, info in OWASP_MAPPING.items():
            table.add_row(
                owasp_id,
                info["name"],
                info["description"],
            )

        console.print(table)
        console.print()

    if framework in ["iso", "all"]:
        console.print("[bold]ISO/IEC 42001 AI Management System[/bold]\n")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Clause", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Description")

        from .core.mapping import ISO_MAPPING

        for iso_id, info in ISO_MAPPING.items():
            table.add_row(
                iso_id,
                info["name"],
                info["description"],
            )

        console.print(table)
        console.print()

    # Show check mapping
    console.print("[bold]Check Category to Framework Mapping[/bold]\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Check Category", style="cyan")
    table.add_column("OWASP Mapping", style="yellow")
    table.add_column("ISO Mapping", style="blue")

    mappings = generate_mapping_table()

    for mapping in mappings:
        table.add_row(
            mapping["check_category"],
            mapping["owasp"],
            mapping["iso"],
        )

    console.print(table)


@app.command("baseline-create")
def baseline_create(
    report: Path = typer.Argument(..., help="Path to assessment report JSON"),
    output: Path = typer.Option(
        Path("baseline.json"),
        "--output",
        "-o",
        help="Output path for baseline file",
    ),
):
    """Create baseline from assessment report."""
    if not report.exists():
        console.print(f"[red]Error: Report not found: {report}[/red]")
        raise typer.Exit(1)

    try:
        baseline_obj = Baseline(output)
        baseline_obj.create_from_report_file(report)
        console.print(f"[green]✓ Baseline created: {output}[/green]")
    except Exception as e:
        console.print(f"[red]Error creating baseline: {e}[/red]")
        raise typer.Exit(1)


@app.command("baseline-compare")
def baseline_compare(
    report: Path = typer.Argument(..., help="Path to current assessment report JSON"),
    baseline_file: Path = typer.Option(
        Path("baseline.json"),
        "--baseline",
        "-b",
        help="Path to baseline file",
    ),
    fail_on_regression: bool = typer.Option(
        True,
        "--fail-on-regression",
        help="Exit with error if regression detected",
    ),
):
    """Compare assessment against baseline."""
    if not report.exists():
        console.print(f"[red]Error: Report not found: {report}[/red]")
        raise typer.Exit(1)

    if not baseline_file.exists():
        console.print(f"[red]Error: Baseline not found: {baseline_file}[/red]")
        raise typer.Exit(1)

    try:
        baseline_obj = Baseline(baseline_file)

        # Compare report file against baseline
        comparison = baseline_obj.compare_file(report)

        # Display results
        console.print("\n[bold]Baseline Comparison[/bold]")
        console.print(f"  Regression: {'❌ Yes' if comparison['regression'] else '✅ No'}")
        console.print(f"  New Failures: {comparison['new_failures']}")
        console.print(f"  Resolved Issues: {comparison['resolved_issues']}")

        if comparison["regression"] and fail_on_regression:
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"[red]Error comparing baseline: {e}[/red]")
        raise typer.Exit(1)


@app.command("cache-stats")
def cache_stats():
    """Show cache statistics."""
    try:
        cache_obj = CheckCache()
        stats = cache_obj.stats()

        console.print("\n[bold]Cache Statistics[/bold]")
        console.print(f"  Directory: {stats['cache_dir']}")
        console.print(f"  Entries: {stats['total_entries']}")
        console.print(f"  Size: {stats['total_size_mb']} MB")
        if stats['total_entries'] > 0:
            console.print(f"  Oldest: {stats['oldest_entry_age']}")
            console.print(f"  Newest: {stats['newest_entry_age']}")

    except Exception as e:
        console.print(f"[red]Error getting cache stats: {e}[/red]")
        raise typer.Exit(1)


@app.command("cache-clear")
def cache_clear(
    older_than_days: Optional[int] = typer.Option(
        None,
        "--older-than",
        "-o",
        help="Clear only entries older than N days (default: all)",
    ),
):
    """Clear cache entries."""
    try:
        cache_obj = CheckCache()

        if older_than_days:
            from datetime import timedelta
            cleared = cache_obj.clear(older_than=timedelta(days=older_than_days))
            console.print(f"[green]✓ Cleared {cleared} cache entries older than {older_than_days} days[/green]")
        else:
            cleared = cache_obj.clear()
            console.print(f"[green]✓ Cleared {cleared} cache entries[/green]")

    except Exception as e:
        console.print(f"[red]Error clearing cache: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def plugins(
    plugins_dir: Path = typer.Option(
        Path("./plugins"),
        "--dir",
        "-d",
        help="Plugins directory",
    ),
):
    """
    List available compliance check plugins.
    """
    try:
        manager = PluginManager(plugins_dir)
        count = manager.discover_plugins()

        if count == 0:
            console.print(f"[yellow]No plugins found in {plugins_dir}[/yellow]")
            console.print("\nCreate custom check plugins by implementing ComplianceCheckPlugin protocol.")
            return

        console.print(f"\n[bold]Available Plugins ({count})[/bold]\n")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Module")

        for plugin in manager.get_plugins():
            table.add_row(plugin.name, plugin.version, type(plugin).__module__)

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error listing plugins: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def fix(
    config: Path = typer.Option(
        Path("raicb.yaml"),
        "--config",
        "-c",
        help="Path to configuration file",
    ),
    report: Path = typer.Option(
        Path("./reports/assessment.json"),
        "--report",
        "-r",
        help="Path to assessment report JSON",
    ),
    auto: bool = typer.Option(
        False,
        "--auto",
        help="Auto-fix without prompting",
    ),
):
    """
    Interactive wizard to fix compliance issues.
    """
    console.print("[bold blue]Remediation Wizard[/bold blue]\n")

    # Get project root
    try:
        project_root = config.parent.resolve()
    except Exception:
        project_root = Path.cwd()

    # Load report
    if not report.exists():
        console.print(f"[yellow]Report not found: {report}[/yellow]")
        console.print("Run 'raicb run' first to generate a report.")
        raise typer.Exit(1)

    try:
        import json
        from .config.schema import Finding
        from pydantic import ValidationError

        with open(report) as f:
            report_data = json.load(f)

        # Deserialize findings with validation error handling
        findings = []
        for i, finding_dict in enumerate(report_data.get("findings", [])):
            try:
                findings.append(Finding(**finding_dict))
            except ValidationError as e:
                console.print(f"[yellow]Warning: Skipping invalid finding {i}: {e.errors()[0]['msg']}[/yellow]")

        wizard = RemediationWizard(project_root)

        # Find auto-fixable issues
        fixable = [f for f in findings if wizard.can_auto_fix(f)]

        if not fixable:
            console.print("[yellow]No auto-fixable issues found.[/yellow]")
            return

        console.print(f"Found {len(fixable)} auto-fixable issues:\n")

        # List fixable issues
        for i, finding in enumerate(fixable, 1):
            console.print(f"{i}. [{finding.severity.value.upper()}] {finding.title}")
            console.print(f"   Fix: {wizard.get_fix_description(finding)}\n")

        # Apply fixes
        if not auto:
            confirm = typer.confirm("Apply these fixes?")
            if not confirm:
                console.print("Cancelled.")
                return

        # Apply each fix
        for finding in fixable:
            console.print(f"Fixing: {finding.check_id}...")
            success = wizard.apply_fix(finding, interactive=False)

        # Show summary
        summary = wizard.get_summary()
        console.print(f"\n[bold]Remediation Summary[/bold]")
        console.print(f"  Applied: {summary['fixes_applied']}")
        console.print(f"  Failed: {summary['fixes_failed']}")

        if summary['fixes_applied'] > 0:
            console.print("\n[green]✓ Fixes applied successfully[/green]")
            console.print("Run 'raicb run' again to verify.")

    except Exception as e:
        console.print(f"[red]Error in remediation: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def trends(
    project: Optional[str] = typer.Option(
        None,
        "--project",
        "-p",
        help="Filter by project name",
    ),
    env: Optional[str] = typer.Option(
        None,
        "--env",
        "-e",
        help="Filter by environment",
    ),
    days: int = typer.Option(
        30,
        "--days",
        "-d",
        help="Number of days to show",
    ),
    export: Optional[Path] = typer.Option(
        None,
        "--export",
        help="Export trends to JSON file",
    ),
):
    """
    Show compliance trends over time.
    """
    try:
        tracker = TrendTracker()

        if export:
            # Export to file
            tracker.export_trends(export, project, env, days)
            console.print(f"[green]✓ Trends exported to: {export}[/green]")
            return

        # Get statistics
        stats = tracker.get_statistics(project, env)

        if "error" in stats:
            console.print(f"[yellow]{stats['error']}[/yellow]")
            return

        console.print("\n[bold]Compliance Trends[/bold]\n")
        console.print(f"  Total Assessments: {stats['total_assessments']}")
        console.print(f"  First Assessment: {stats['first_assessment']}")
        console.print(f"  Latest Assessment: {stats['latest_assessment']}")

        console.print("\n[bold]Averages:[/bold]")
        console.print(f"  Critical: {stats['avg_critical']}")
        console.print(f"  High: {stats['avg_high']}")
        console.print(f"  Medium: {stats['avg_medium']}")

        console.print("\n[bold]Latest:[/bold]")
        console.print(f"  Critical: {stats['latest_critical']}")
        console.print(f"  High: {stats['latest_high']}")
        console.print(f"  Medium: {stats['latest_medium']}")

    except Exception as e:
        console.print(f"[red]Error getting trends: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def version():
    """
    Display version information.
    """
    from . import __version__

    console.print(f"Responsible AI Compliance Blueprint v{__version__}")
    console.print("Apache License 2.0")


if __name__ == "__main__":
    app()
