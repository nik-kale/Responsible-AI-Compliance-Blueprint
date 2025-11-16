"""Webhook integration for posting assessment results to external systems."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..config.schema import AssessmentReport, Finding, Severity, Status
from ..core.logger import get_logger

logger = get_logger(__name__)


class WebhookIntegration:
    """Post assessment results to webhook endpoints."""

    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        retry_count: int = 3,
    ):
        """
        Initialize webhook integration.

        Args:
            url: Webhook URL to POST to
            headers: Optional custom headers (e.g., authentication)
            timeout: Request timeout in seconds
            retry_count: Number of retries on failure
        """
        self.url = url
        self.headers = headers or {}
        self.timeout = timeout
        self.retry_count = retry_count

        # Set default headers
        if "Content-Type" not in self.headers:
            self.headers["Content-Type"] = "application/json"

        logger.debug(f"Webhook initialized: {url}")

    def post_report(
        self,
        report: AssessmentReport,
        format: str = "summary",
        custom_data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Post assessment report to webhook.

        Args:
            report: Assessment report to post
            format: Payload format (summary, full, custom)
            custom_data: Additional custom data to include

        Returns:
            True if posted successfully, False otherwise
        """
        try:
            # Build payload based on format
            if format == "summary":
                payload = self._build_summary_payload(report)
            elif format == "full":
                payload = self._build_full_payload(report)
            elif format == "custom":
                payload = custom_data or {}
            else:
                logger.error(f"Unknown format: {format}")
                return False

            # Add custom data if provided
            if custom_data and format != "custom":
                payload["custom"] = custom_data

            # Post with retries
            return self._post_with_retry(payload)

        except Exception as e:
            logger.error(f"Failed to post report to webhook: {e}", exc_info=True)
            return False

    def post_findings(
        self,
        findings: List[Finding],
        severity_filter: Optional[List[Severity]] = None,
        status_filter: Optional[List[Status]] = None,
    ) -> bool:
        """
        Post individual findings to webhook.

        Args:
            findings: List of findings to post
            severity_filter: Only post findings with these severities
            status_filter: Only post findings with these statuses

        Returns:
            True if posted successfully, False otherwise
        """
        try:
            # Filter findings
            filtered_findings = findings
            if severity_filter:
                filtered_findings = [
                    f for f in filtered_findings if f.severity in severity_filter
                ]
            if status_filter:
                filtered_findings = [
                    f for f in filtered_findings if f.status in status_filter
                ]

            # Build payload
            payload = {
                "timestamp": datetime.now().isoformat(),
                "finding_count": len(filtered_findings),
                "findings": [
                    {
                        "check_id": f.check_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "status": f.status.value,
                        "category": f.category,
                        "description": f.description,
                        "evidence": f.evidence,
                        "remediation": f.remediation,
                        "owasp_mapping": f.owasp_mapping,
                        "iso_mapping": f.iso_mapping,
                    }
                    for f in filtered_findings
                ],
            }

            return self._post_with_retry(payload)

        except Exception as e:
            logger.error(f"Failed to post findings to webhook: {e}", exc_info=True)
            return False

    def _build_summary_payload(self, report: AssessmentReport) -> Dict[str, Any]:
        """Build summary payload with key metrics."""
        # Count by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        # Count by status
        status_counts = {
            "pass": 0,
            "fail": 0,
            "warning": 0,
            "skip": 0,
            "error": 0,
        }

        for finding in report.findings:
            severity_counts[finding.severity.value] += 1
            status_counts[finding.status.value] += 1

        return {
            "timestamp": report.timestamp,
            "environment": report.environment,
            "project_name": report.project_config.project.name,
            "version": report.project_config.project.version,
            "total_findings": len(report.findings),
            "severity_counts": severity_counts,
            "status_counts": status_counts,
            "frameworks": {
                "owasp_coverage": len(report.owasp_coverage),
                "iso_coverage": len(report.iso_coverage),
            },
        }

    def _build_full_payload(self, report: AssessmentReport) -> Dict[str, Any]:
        """Build full payload with all report data."""
        return {
            "timestamp": report.timestamp,
            "environment": report.environment,
            "project": {
                "name": report.project_config.project.name,
                "version": report.project_config.project.version,
                "description": report.project_config.project.description,
            },
            "findings": [
                {
                    "check_id": f.check_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "category": f.category,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "owasp_mapping": f.owasp_mapping,
                    "iso_mapping": f.iso_mapping,
                }
                for f in report.findings
            ],
            "owasp_coverage": [
                {
                    "id": cov.id,
                    "title": cov.title,
                    "description": cov.description,
                    "related_checks": cov.related_checks,
                }
                for cov in report.owasp_coverage
            ],
            "iso_coverage": [
                {
                    "clause": cov.clause,
                    "title": cov.title,
                    "description": cov.description,
                    "related_checks": cov.related_checks,
                }
                for cov in report.iso_coverage
            ],
        }

    def _post_with_retry(self, payload: Dict[str, Any]) -> bool:
        """
        Post payload with retry logic.

        Args:
            payload: JSON payload to post

        Returns:
            True if posted successfully, False otherwise
        """
        last_error = None

        for attempt in range(self.retry_count):
            try:
                # Prepare request
                data = json.dumps(payload).encode("utf-8")
                request = Request(self.url, data=data, headers=self.headers)

                # Send request
                with urlopen(request, timeout=self.timeout) as response:
                    status_code = response.getcode()

                    if 200 <= status_code < 300:
                        logger.info(
                            f"Webhook posted successfully (status: {status_code})"
                        )
                        return True
                    else:
                        logger.warning(
                            f"Webhook returned non-success status: {status_code}"
                        )
                        last_error = f"HTTP {status_code}"

            except HTTPError as e:
                logger.warning(
                    f"Webhook HTTP error (attempt {attempt + 1}/{self.retry_count}): {e.code}"
                )
                last_error = f"HTTP {e.code}: {e.reason}"

            except URLError as e:
                logger.warning(
                    f"Webhook URL error (attempt {attempt + 1}/{self.retry_count}): {e.reason}"
                )
                last_error = f"URL error: {e.reason}"

            except Exception as e:
                logger.warning(
                    f"Webhook error (attempt {attempt + 1}/{self.retry_count}): {e}"
                )
                last_error = str(e)

        # All retries failed
        logger.error(f"Webhook failed after {self.retry_count} attempts: {last_error}")
        return False


def create_slack_payload(report: AssessmentReport) -> Dict[str, Any]:
    """
    Create Slack-compatible webhook payload.

    Args:
        report: Assessment report

    Returns:
        Slack-formatted payload
    """
    # Count severities
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in report.findings:
        severity_counts[finding.severity.value] += 1

    # Determine color based on critical/high count
    critical_high_count = severity_counts["critical"] + severity_counts["high"]
    if critical_high_count > 0:
        color = "danger"
    elif severity_counts["medium"] > 0:
        color = "warning"
    else:
        color = "good"

    return {
        "text": f"AI Compliance Assessment: {report.project_config.project.name}",
        "attachments": [
            {
                "color": color,
                "fields": [
                    {
                        "title": "Environment",
                        "value": report.environment,
                        "short": True,
                    },
                    {
                        "title": "Version",
                        "value": report.project_config.project.version,
                        "short": True,
                    },
                    {
                        "title": "Critical",
                        "value": str(severity_counts["critical"]),
                        "short": True,
                    },
                    {
                        "title": "High",
                        "value": str(severity_counts["high"]),
                        "short": True,
                    },
                    {
                        "title": "Medium",
                        "value": str(severity_counts["medium"]),
                        "short": True,
                    },
                    {
                        "title": "Low",
                        "value": str(severity_counts["low"]),
                        "short": True,
                    },
                ],
                "footer": "Responsible AI Compliance Blueprint",
                "ts": int(datetime.fromisoformat(report.timestamp).timestamp()),
            }
        ],
    }


def create_pagerduty_payload(
    report: AssessmentReport, routing_key: str, severity_threshold: Severity = Severity.HIGH
) -> Dict[str, Any]:
    """
    Create PagerDuty Events API v2 payload.

    Args:
        report: Assessment report
        routing_key: PagerDuty integration key
        severity_threshold: Only trigger if findings at or above this severity

    Returns:
        PagerDuty-formatted payload
    """
    # Check if we have findings at or above threshold
    critical_findings = [
        f
        for f in report.findings
        if f.severity.value in ["critical", "high"]
        and f.status in [Status.FAIL, Status.ERROR]
    ]

    if not critical_findings:
        # No critical findings, send resolve event
        return {
            "routing_key": routing_key,
            "event_action": "resolve",
            "dedup_key": f"raicb-{report.project_config.project.name}-{report.environment}",
        }

    # Critical findings found, send trigger event
    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": f"raicb-{report.project_config.project.name}-{report.environment}",
        "payload": {
            "summary": f"AI Compliance Issues: {report.project_config.project.name} ({len(critical_findings)} critical)",
            "severity": "error" if any(f.severity == Severity.CRITICAL for f in critical_findings) else "warning",
            "source": report.project_config.project.name,
            "component": report.environment,
            "custom_details": {
                "environment": report.environment,
                "version": report.project_config.project.version,
                "critical_count": sum(1 for f in critical_findings if f.severity == Severity.CRITICAL),
                "high_count": sum(1 for f in critical_findings if f.severity == Severity.HIGH),
                "findings": [
                    {
                        "id": f.check_id,
                        "title": f.title,
                        "severity": f.severity.value,
                    }
                    for f in critical_findings[:5]  # Limit to first 5
                ],
            },
        },
    }
