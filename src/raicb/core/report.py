"""Report generation in multiple formats."""

import importlib.resources
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from jinja2 import Environment, FileSystemLoader, select_autoescape
import markdown

from ..config.schema import AssessmentReport, Finding, Severity, Status


def generate_report(
    report: AssessmentReport,
    output_dir: Path,
    formats: List[str] = ["md", "html"],
    template_dir: Optional[Path] = None,
) -> List[Path]:
    """
    Generate assessment reports in specified formats.

    Args:
        report: Assessment report data
        output_dir: Output directory for reports
        formats: List of formats to generate (md, html, pdf)
        template_dir: Custom template directory (uses built-in if None)

    Returns:
        List of generated file paths
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    generated_files = []

    # Set up Jinja2 environment
    if template_dir and template_dir.exists():
        env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )
    else:
        # Use built-in templates
        template_path = Path(__file__).parent.parent.parent.parent / "templates"
        env = Environment(
            loader=FileSystemLoader(str(template_path)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    # Add custom filters
    env.filters["severity_color"] = _severity_color
    env.filters["status_icon"] = _status_icon

    # Prepare template context
    context = {
        "report": report,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "findings_by_category": _group_findings_by_category(report.findings),
        "findings_by_severity": _group_findings_by_severity(report.findings),
        "critical_findings": [
            f for f in report.findings
            if f.severity == Severity.CRITICAL and f.status == Status.FAIL
        ],
        "framework_mappings": _get_framework_mappings(),
    }

    # Generate Markdown report
    if "md" in formats:
        md_path = output_dir / f"{report.project_name}_compliance_report.md"
        template = env.get_template("report.md.j2")
        content = template.render(**context)
        md_path.write_text(content, encoding="utf-8")
        generated_files.append(md_path)

    # Generate HTML report
    if "html" in formats:
        html_path = output_dir / f"{report.project_name}_compliance_report.html"
        template = env.get_template("report.html.j2")
        content = template.render(**context)
        html_path.write_text(content, encoding="utf-8")
        generated_files.append(html_path)

    # Generate PDF report (optional, requires weasyprint)
    if "pdf" in formats:
        try:
            from weasyprint import HTML

            html_path = output_dir / f"{report.project_name}_compliance_report.html"

            # Generate HTML first if not already done
            if not html_path.exists():
                template = env.get_template("report.html.j2")
                content = template.render(**context)
                html_path.write_text(content, encoding="utf-8")

            # Convert to PDF
            pdf_path = output_dir / f"{report.project_name}_compliance_report.pdf"
            HTML(html_path).write_pdf(pdf_path)
            generated_files.append(pdf_path)

        except ImportError:
            print("Warning: weasyprint not installed. PDF generation skipped.")
            print("Install with: pip install weasyprint")

        except Exception as e:
            print(f"Warning: PDF generation failed: {e}")

    return generated_files


def _group_findings_by_category(findings: List[Finding]) -> dict:
    """Group findings by category."""
    grouped = {}
    for finding in findings:
        category = finding.category
        if category not in grouped:
            grouped[category] = []
        grouped[category].append(finding)
    return grouped


def _group_findings_by_severity(findings: List[Finding]) -> dict:
    """Group findings by severity."""
    grouped = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": [],
    }

    for finding in findings:
        severity = finding.severity.value
        grouped[severity].append(finding)

    return grouped


def _severity_color(severity: str) -> str:
    """Get color for severity level."""
    colors = {
        "critical": "#dc2626",  # red-600
        "high": "#ea580c",      # orange-600
        "medium": "#d97706",    # amber-600
        "low": "#65a30d",       # lime-600
        "info": "#2563eb",      # blue-600
    }
    return colors.get(severity.lower(), "#6b7280")


def _status_icon(status: str) -> str:
    """Get icon for status."""
    icons = {
        "pass": "✓",
        "fail": "✗",
        "warning": "⚠",
        "skip": "○",
        "error": "⚠",
    }
    return icons.get(status.lower(), "•")


def _get_framework_mappings() -> dict:
    """Get framework mapping tables."""
    from .mapping import OWASP_MAPPING, ISO_MAPPING, generate_mapping_table

    return {
        "owasp": OWASP_MAPPING,
        "iso": ISO_MAPPING,
        "table": generate_mapping_table(),
    }


def generate_sbom(output_path: Path) -> None:
    """
    Generate SBOM (Software Bill of Materials) for Python dependencies.

    Args:
        output_path: Output file path for SBOM
    """
    import json
    import subprocess

    try:
        # Use pipdeptree to generate dependency tree
        result = subprocess.run(
            ["pipdeptree", "--json"],
            capture_output=True,
            text=True,
            check=True,
        )

        dependencies = json.loads(result.stdout)

        # Create simplified SBOM
        sbom = {
            "bomFormat": "custom",
            "specVersion": "1.0",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": ["pipdeptree"],
            },
            "components": [],
        }

        for dep in dependencies:
            component = {
                "name": dep["package"]["package_name"],
                "version": dep["package"]["installed_version"],
                "type": "library",
                "dependencies": [
                    d["package_name"] for d in dep.get("dependencies", [])
                ],
            }
            sbom["components"].append(component)

        # Write SBOM
        with open(output_path, "w") as f:
            json.dump(sbom, f, indent=2)

    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to generate SBOM: {e}")

    except FileNotFoundError:
        raise RuntimeError("pipdeptree not installed. Install with: pip install pipdeptree")
