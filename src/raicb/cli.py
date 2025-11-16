"""CLI for Responsible AI Compliance Blueprint."""

import shutil
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table
import yaml

from .config.schema import ProjectConfig
from .core.loader import load_config, save_config
from .core.evaluator import run_all_checks, get_exit_code
from .core.report import generate_report, generate_sbom
from .core.mapping import generate_mapping_table, get_owasp_description, get_iso_description
from .core.utils import get_project_root

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
        help="Report formats (comma-separated: md,html,pdf)",
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
):
    """
    Run compliance checks and generate reports.
    """
    console.print("[bold blue]Running Compliance Assessment[/bold blue]\n")

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
        report = run_all_checks(project_config, project_root, env, verbose)
    except Exception as e:
        console.print(f"[red]Error running checks: {e}[/red]")
        raise typer.Exit(1)

    # Generate reports
    formats = [f.strip() for f in format.split(",")]

    try:
        console.print(f"\n[bold]Generating reports in {out}...[/bold]")
        generated_files = generate_report(report, out, formats)

        for file_path in generated_files:
            console.print(f"  ✓ {file_path}")

        console.print(f"\n[green]✓ Reports generated successfully[/green]")

    except Exception as e:
        console.print(f"[red]Error generating reports: {e}[/red]")
        raise typer.Exit(1)

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
        from .config.schema import Severity, Status
        if any(f.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM] and f.status == Status.FAIL
               for f in report.findings):
            exit_code = 1
    elif fail_on == "high":
        from .config.schema import Severity, Status
        if any(f.severity in [Severity.CRITICAL, Severity.HIGH] and f.status == Status.FAIL
               for f in report.findings):
            exit_code = 1
    elif fail_on == "critical":
        from .config.schema import Severity, Status
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
