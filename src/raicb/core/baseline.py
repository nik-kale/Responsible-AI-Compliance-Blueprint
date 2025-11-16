"""Baseline comparison for regression detection in CI/CD."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from ..config.schema import AssessmentReport, Severity, Status
from .logger import get_logger

logger = get_logger(__name__)


class Baseline:
    """Manage compliance baselines for regression detection."""

    def __init__(self, baseline_file: Path):
        """
        Initialize baseline manager.

        Args:
            baseline_file: Path to baseline JSON file
        """
        self.baseline_file = baseline_file
        self.baseline_data: Optional[Dict[str, Any]] = None

    def create(self, report: AssessmentReport) -> None:
        """
        Create baseline from assessment report.

        Args:
            report: Assessment report to use as baseline
        """
        # Count findings by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in report.findings:
            severity_counts[finding.severity.value] += 1

        # Create baseline data
        self.baseline_data = {
            "created_at": datetime.now().isoformat(),
            "project": report.project_name,
            "version": report.version,
            "environment": report.environment,
            "total_checks": report.total_checks,
            "passed_checks": report.passed_checks,
            "failed_checks": report.failed_checks,
            "warnings": report.warnings,
            "severity_counts": severity_counts,
            "check_results": {
                f.check_id: {
                    "status": f.status.value,
                    "severity": f.severity.value,
                    "title": f.title,
                }
                for f in report.findings
            },
        }

        # Save to file
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.baseline_file, "w") as f:
            json.dump(self.baseline_data, f, indent=2)

        logger.info(f"Baseline created: {self.baseline_file}")

    def load(self) -> bool:
        """
        Load baseline from file.

        Returns:
            True if loaded successfully, False otherwise
        """
        if not self.baseline_file.exists():
            logger.warning(f"Baseline file not found: {self.baseline_file}")
            return False

        try:
            with open(self.baseline_file, "r") as f:
                self.baseline_data = json.load(f)
            logger.info(f"Baseline loaded: {self.baseline_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            return False

    def compare(self, report: AssessmentReport) -> Dict[str, Any]:
        """
        Compare current report against baseline.

        Args:
            report: Current assessment report

        Returns:
            Dictionary with comparison results
        """
        if not self.baseline_data:
            if not self.load():
                return {"error": "No baseline available for comparison"}

        # Calculate current severity counts
        current_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in report.findings:
            current_severity[finding.severity.value] += 1

        baseline_severity = self.baseline_data["severity_counts"]

        # Check for regression (more critical/high findings)
        regression = (
            current_severity["critical"] > baseline_severity["critical"]
            or current_severity["high"] > baseline_severity["high"]
        )

        # Check for improvement
        improvement = (
            current_severity["critical"] < baseline_severity["critical"]
            and current_severity["high"] < baseline_severity["high"]
        )

        # Find new failures (checks that passed before but fail now)
        new_failures = []
        baseline_checks = self.baseline_data.get("check_results", {})

        for finding in report.findings:
            if finding.status == Status.FAIL:
                baseline_check = baseline_checks.get(finding.check_id)
                if baseline_check and baseline_check["status"] == "pass":
                    new_failures.append({
                        "check_id": finding.check_id,
                        "title": finding.title,
                        "severity": finding.severity.value,
                    })

        # Find resolved issues (checks that failed before but pass now)
        resolved_issues = []
        current_checks = {f.check_id: f for f in report.findings}

        for check_id, baseline_check in baseline_checks.items():
            if baseline_check["status"] == "fail":
                current_check = current_checks.get(check_id)
                if current_check and current_check.status == Status.PASS:
                    resolved_issues.append({
                        "check_id": check_id,
                        "title": baseline_check["title"],
                    })

        # Calculate metrics delta
        metrics_delta = {
            "total_checks": report.total_checks - self.baseline_data["total_checks"],
            "passed_checks": report.passed_checks - self.baseline_data["passed_checks"],
            "failed_checks": report.failed_checks - self.baseline_data["failed_checks"],
            "warnings": report.warnings - self.baseline_data["warnings"],
        }

        severity_delta = {
            severity: current_severity[severity] - baseline_severity[severity]
            for severity in current_severity.keys()
        }

        return {
            "baseline_date": self.baseline_data["created_at"],
            "baseline_version": self.baseline_data["version"],
            "current_version": report.version,
            "regression": regression,
            "improvement": improvement,
            "new_failures": new_failures,
            "new_failures_count": len(new_failures),
            "resolved_issues": resolved_issues,
            "resolved_count": len(resolved_issues),
            "metrics_delta": metrics_delta,
            "severity_delta": severity_delta,
            "summary": self._generate_summary(
                regression, improvement, new_failures, resolved_issues, severity_delta
            ),
        }

    def _generate_summary(
        self,
        regression: bool,
        improvement: bool,
        new_failures: list,
        resolved_issues: list,
        severity_delta: dict,
    ) -> str:
        """Generate human-readable summary of comparison."""
        if regression:
            return (
                f"⚠️  REGRESSION DETECTED: {len(new_failures)} new failure(s). "
                f"Critical: {severity_delta['critical']:+d}, High: {severity_delta['high']:+d}"
            )
        elif improvement:
            return (
                f"✅ IMPROVEMENT: {len(resolved_issues)} issue(s) resolved. "
                f"Critical: {severity_delta['critical']:+d}, High: {severity_delta['high']:+d}"
            )
        elif len(new_failures) > 0:
            return f"⚠️  {len(new_failures)} new failure(s) detected"
        elif len(resolved_issues) > 0:
            return f"✅ {len(resolved_issues)} issue(s) resolved"
        else:
            return "✓ No significant changes from baseline"

    def should_fail_build(self, comparison: Dict[str, Any], strict: bool = False) -> bool:
        """
        Determine if build should fail based on comparison.

        Args:
            comparison: Comparison result from compare()
            strict: If True, fail on any new failure. If False, only fail on regression.

        Returns:
            True if build should fail
        """
        if comparison.get("error"):
            return False  # Don't fail if no baseline

        if strict:
            return comparison["new_failures_count"] > 0
        else:
            return comparison["regression"]

    def create_from_report_file(self, report_path: Path) -> None:
        """
        Create baseline from JSON report file.

        Args:
            report_path: Path to assessment JSON report

        Raises:
            FileNotFoundError: If report file doesn't exist
            JSONDecodeError: If report file is invalid JSON
        """
        if not report_path.exists():
            raise FileNotFoundError(f"Report file not found: {report_path}")

        try:
            with open(report_path, "r") as f:
                report_data = json.load(f)

            # Reconstruct AssessmentReport from JSON
            from ..config.schema import AssessmentReport
            from pydantic import ValidationError

            try:
                report = AssessmentReport(**report_data)
            except ValidationError as e:
                logger.error(f"Invalid assessment report structure: {e}")
                raise ValueError(f"Report validation failed: {e.errors()[0]['msg']}")

            # Create baseline using the existing method
            self.create(report)

            logger.info(f"Baseline created from {report_path}")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in report file: {e}")
            raise
        except ValueError:
            raise  # Re-raise validation errors as-is
        except Exception as e:
            logger.error(f"Failed to create baseline from file: {e}", exc_info=True)
            raise

    def compare_file(self, report_path: Path) -> Dict[str, Any]:
        """
        Compare assessment report file against baseline.

        Args:
            report_path: Path to current assessment JSON report

        Returns:
            Dictionary with comparison results

        Raises:
            FileNotFoundError: If report file doesn't exist
            JSONDecodeError: If report file is invalid JSON
        """
        if not report_path.exists():
            raise FileNotFoundError(f"Report file not found: {report_path}")

        try:
            with open(report_path, "r") as f:
                report_data = json.load(f)

            # Reconstruct AssessmentReport from JSON
            from ..config.schema import AssessmentReport
            from pydantic import ValidationError

            try:
                report = AssessmentReport(**report_data)
            except ValidationError as e:
                logger.error(f"Invalid assessment report structure: {e}")
                raise ValueError(f"Report validation failed: {e.errors()[0]['msg']}")

            # Compare using the existing method
            return self.compare(report)

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in report file: {e}")
            raise
        except ValueError:
            raise  # Re-raise validation errors as-is
        except Exception as e:
            logger.error(f"Failed to compare with baseline: {e}", exc_info=True)
            raise
