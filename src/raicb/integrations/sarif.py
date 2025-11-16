"""SARIF (Static Analysis Results Interchange Format) export for GitHub Code Scanning."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..config.schema import AssessmentReport, Finding, Severity, Status
from ..core.logger import get_logger

logger = get_logger(__name__)

# SARIF specification version
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


class SARIFExporter:
    """Export assessment results in SARIF 2.1.0 format."""

    def __init__(
        self,
        tool_name: str = "Responsible AI Compliance Blueprint",
        tool_version: str = "0.1.0",
        organization: str = "RAICB",
    ):
        """
        Initialize SARIF exporter.

        Args:
            tool_name: Name of the tool
            tool_version: Tool version
            organization: Organization name
        """
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.organization = organization

    def export_report(
        self,
        report: AssessmentReport,
        output_path: Path,
        base_uri: Optional[str] = None,
    ) -> bool:
        """
        Export assessment report to SARIF format.

        Args:
            report: Assessment report to export
            output_path: Path to save SARIF file
            base_uri: Base URI for file locations (e.g., "file:///project/")

        Returns:
            True if exported successfully
        """
        try:
            sarif_log = self._build_sarif_log(report, base_uri)

            # Write to file
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(sarif_log, f, indent=2, ensure_ascii=False)

            logger.info(f"SARIF report exported to: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export SARIF report: {e}", exc_info=True)
            return False

    def export_findings(
        self,
        findings: List[Finding],
        output_path: Path,
        base_uri: Optional[str] = None,
        project_name: str = "AI Project",
    ) -> bool:
        """
        Export findings list to SARIF format.

        Args:
            findings: List of findings
            output_path: Path to save SARIF file
            base_uri: Base URI for file locations
            project_name: Project name for context

        Returns:
            True if exported successfully
        """
        try:
            sarif_log = self._build_sarif_from_findings(
                findings, base_uri, project_name
            )

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(sarif_log, f, indent=2, ensure_ascii=False)

            logger.info(f"SARIF findings exported to: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export SARIF findings: {e}", exc_info=True)
            return False

    def _build_sarif_log(
        self, report: AssessmentReport, base_uri: Optional[str] = None
    ) -> Dict[str, Any]:
        """Build complete SARIF log structure."""
        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": self._build_tool_metadata(report),
                    "results": self._build_results(report.findings, base_uri),
                    "taxonomies": self._build_taxonomies(),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": report.timestamp,
                            "properties": {
                                "environment": report.environment,
                                "projectName": report.project_config.project.name,
                                "projectVersion": report.project_config.project.version,
                            },
                        }
                    ],
                    "properties": {
                        "owaspCoverage": len(report.owasp_coverage),
                        "isoCoverage": len(report.iso_coverage),
                    },
                }
            ],
        }

    def _build_sarif_from_findings(
        self, findings: List[Finding], base_uri: Optional[str], project_name: str
    ) -> Dict[str, Any]:
        """Build SARIF log from findings list."""
        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/yourusername/responsible-ai-compliance-blueprint",
                            "organization": self.organization,
                        }
                    },
                    "results": self._build_results(findings, base_uri),
                    "taxonomies": self._build_taxonomies(),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now().isoformat(),
                            "properties": {"projectName": project_name},
                        }
                    ],
                }
            ],
        }

    def _build_tool_metadata(self, report: AssessmentReport) -> Dict[str, Any]:
        """Build tool metadata section."""
        # Collect all unique check IDs to define rules
        rules = []
        seen_checks = set()

        for finding in report.findings:
            if finding.check_id not in seen_checks:
                seen_checks.add(finding.check_id)
                rules.append(self._build_rule(finding))

        return {
            "driver": {
                "name": self.tool_name,
                "version": self.tool_version,
                "informationUri": "https://github.com/yourusername/responsible-ai-compliance-blueprint",
                "organization": self.organization,
                "rules": rules,
            }
        }

    def _build_rule(self, finding: Finding) -> Dict[str, Any]:
        """Build a SARIF rule from a finding."""
        return {
            "id": finding.check_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {
                "text": finding.remediation,
                "markdown": f"**Remediation**\n\n{finding.remediation}",
            },
            "defaultConfiguration": {
                "level": self._severity_to_level(finding.severity)
            },
            "properties": {
                "category": finding.category,
                "tags": self._build_tags(finding),
                "precision": "high",
            },
        }

    def _build_results(
        self, findings: List[Finding], base_uri: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Build results array from findings."""
        results = []

        for finding in findings:
            # Only include failures and errors in SARIF
            # (SARIF is primarily for issues, not successful checks)
            if finding.status in [Status.FAIL, Status.ERROR, Status.WARNING]:
                results.append(self._build_result(finding, base_uri))

        return results

    def _build_result(
        self, finding: Finding, base_uri: Optional[str]
    ) -> Dict[str, Any]:
        """Build a single SARIF result from a finding."""
        result = {
            "ruleId": finding.check_id,
            "level": self._severity_to_level(finding.severity),
            "message": {"text": finding.description},
            "properties": {
                "category": finding.category,
                "status": finding.status.value,
                "evidence": finding.evidence,
                "owaspMapping": finding.owasp_mapping,
                "isoMapping": finding.iso_mapping,
            },
        }

        # Add location if evidence contains file path
        location = self._extract_location_from_evidence(finding.evidence, base_uri)
        if location:
            result["locations"] = [location]

        return result

    def _extract_location_from_evidence(
        self, evidence: str, base_uri: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """
        Try to extract file location from evidence string.

        Looks for patterns like:
        - "Found in: /path/to/file.py"
        - "File: config.yaml"
        - "/path/to/file:line_number"
        """
        # This is a simple heuristic - enhance based on actual evidence formats
        import re

        # Pattern: "Found in: <path>" or "File: <path>"
        match = re.search(r"(?:Found in|File):\s*([^\s]+)", evidence)
        if match:
            file_path = match.group(1)
            return self._build_location(file_path, base_uri)

        # Pattern: "/path/to/file:123" (path with line number)
        match = re.search(r"([^\s]+):(\d+)", evidence)
        if match:
            file_path = match.group(1)
            line_number = int(match.group(2))
            return self._build_location(file_path, base_uri, line_number)

        return None

    def _build_location(
        self, file_path: str, base_uri: Optional[str], line: Optional[int] = None
    ) -> Dict[str, Any]:
        """Build a SARIF location object."""
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": file_path},
            }
        }

        if base_uri:
            location["physicalLocation"]["artifactLocation"]["uriBaseId"] = "%SRCROOT%"

        if line:
            location["physicalLocation"]["region"] = {"startLine": line}

        return location

    def _build_taxonomies(self) -> List[Dict[str, Any]]:
        """Build taxonomy references for OWASP and ISO."""
        return [
            {
                "name": "OWASP Top 10 for LLM Applications",
                "version": "2023",
                "informationUri": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                "organization": "OWASP",
                "shortDescription": {
                    "text": "OWASP Top 10 for Large Language Model Applications"
                },
            },
            {
                "name": "ISO/IEC 42001",
                "version": "2023",
                "informationUri": "https://www.iso.org/standard/81230.html",
                "organization": "ISO/IEC",
                "shortDescription": {
                    "text": "Information technology — Artificial intelligence — Management system"
                },
            },
        ]

    def _build_tags(self, finding: Finding) -> List[str]:
        """Build tags array from finding metadata."""
        tags = [finding.category]

        # Add OWASP tags
        for owasp in finding.owasp_mapping:
            tags.append(f"owasp-{owasp.lower()}")

        # Add ISO tags
        for iso in finding.iso_mapping:
            tags.append(f"iso-{iso.lower().replace('.', '-')}")

        # Add severity tag
        tags.append(f"severity-{finding.severity.value}")

        return tags

    def _severity_to_level(self, severity: Severity) -> str:
        """
        Convert our severity to SARIF level.

        SARIF levels: error, warning, note, none
        """
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "warning",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "warning")


def create_github_code_scanning_workflow(output_path: Path) -> bool:
    """
    Create a GitHub Actions workflow file for Code Scanning integration.

    Args:
        output_path: Path to save workflow file

    Returns:
        True if created successfully
    """
    workflow_content = """name: AI Compliance Code Scanning

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  ai-compliance-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
    - uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'

    - name: Install RAICB
      run: |
        pip install responsible-ai-compliance-blueprint

    - name: Run compliance assessment
      run: |
        raicb run --env production --format sarif --output raicb-results.sarif

    - name: Upload SARIF to GitHub Code Scanning
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: raicb-results.sarif
        category: ai-compliance

    - name: Upload SARIF as artifact
      uses: actions/upload-artifact@v3
      with:
        name: sarif-results
        path: raicb-results.sarif
"""

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(workflow_content)
        logger.info(f"GitHub workflow created: {output_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to create workflow: {e}")
        return False
