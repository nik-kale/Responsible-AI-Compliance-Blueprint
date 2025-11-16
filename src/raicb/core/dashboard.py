"""Dashboard and trend tracking for compliance assessments over time."""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config.schema import AssessmentReport, Finding, Severity, Status
from .logger import get_logger

logger = get_logger(__name__)


class TrendTracker:
    """Track compliance trends over time using SQLite."""

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize trend tracker.

        Args:
            db_path: Path to SQLite database (default: ~/.raicb/trends.db)
        """
        self.db_path = db_path or (Path.home() / ".raicb" / "trends.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_database()

        logger.debug(f"Trend tracker initialized: {self.db_path}")

    def _init_database(self):
        """Create database tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Assessments table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    project_name TEXT NOT NULL,
                    project_version TEXT,
                    environment TEXT NOT NULL,
                    total_findings INTEGER,
                    critical_count INTEGER,
                    high_count INTEGER,
                    medium_count INTEGER,
                    low_count INTEGER,
                    info_count INTEGER,
                    pass_count INTEGER,
                    fail_count INTEGER,
                    warning_count INTEGER,
                    skip_count INTEGER,
                    error_count INTEGER,
                    owasp_coverage INTEGER,
                    iso_coverage INTEGER,
                    metadata TEXT
                )
            """)

            # Findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id INTEGER NOT NULL,
                    check_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    category TEXT,
                    description TEXT,
                    evidence TEXT,
                    remediation TEXT,
                    owasp_mapping TEXT,
                    iso_mapping TEXT,
                    FOREIGN KEY (assessment_id) REFERENCES assessments (id)
                )
            """)

            # Create indices for faster queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_assessments_timestamp
                ON assessments(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_assessments_project
                ON assessments(project_name, environment)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_assessment
                ON findings(assessment_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_check
                ON findings(check_id)
            """)

            conn.commit()
            logger.debug("Database initialized")

    def record_assessment(self, report: AssessmentReport) -> int:
        """
        Record an assessment in the trend database.

        Args:
            report: Assessment report to record

        Returns:
            Assessment ID
        """
        try:
            # Count findings by severity and status
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }
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

            # Store assessment metadata as JSON
            metadata = {
                "description": report.project_config.project.description,
                "config_path": str(report.project_config.project.name),
            }

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Insert assessment
                cursor.execute(
                    """
                    INSERT INTO assessments (
                        timestamp, project_name, project_version, environment,
                        total_findings, critical_count, high_count, medium_count,
                        low_count, info_count, pass_count, fail_count,
                        warning_count, skip_count, error_count,
                        owasp_coverage, iso_coverage, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report.timestamp,
                        report.project_config.project.name,
                        report.project_config.project.version,
                        report.environment,
                        len(report.findings),
                        severity_counts["critical"],
                        severity_counts["high"],
                        severity_counts["medium"],
                        severity_counts["low"],
                        severity_counts["info"],
                        status_counts["pass"],
                        status_counts["fail"],
                        status_counts["warning"],
                        status_counts["skip"],
                        status_counts["error"],
                        len(report.owasp_coverage),
                        len(report.iso_coverage),
                        json.dumps(metadata),
                    ),
                )

                assessment_id = cursor.lastrowid

                # Insert findings
                for finding in report.findings:
                    cursor.execute(
                        """
                        INSERT INTO findings (
                            assessment_id, check_id, title, severity, status,
                            category, description, evidence, remediation,
                            owasp_mapping, iso_mapping
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            assessment_id,
                            finding.check_id,
                            finding.title,
                            finding.severity.value,
                            finding.status.value,
                            finding.category,
                            finding.description,
                            finding.evidence,
                            finding.remediation,
                            json.dumps(finding.owasp_mapping),
                            json.dumps(finding.iso_mapping),
                        ),
                    )

                conn.commit()

            logger.info(f"Assessment recorded: ID={assessment_id}")
            return assessment_id

        except Exception as e:
            logger.error(f"Failed to record assessment: {e}", exc_info=True)
            return -1

    def get_trend_data(
        self,
        project_name: Optional[str] = None,
        environment: Optional[str] = None,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """
        Get trend data for specified period.

        Args:
            project_name: Filter by project name
            environment: Filter by environment
            days: Number of days to include

        Returns:
            List of assessment summaries
        """
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                # Build query
                query = """
                    SELECT * FROM assessments
                    WHERE timestamp >= ?
                """
                params = [cutoff_date]

                if project_name:
                    query += " AND project_name = ?"
                    params.append(project_name)

                if environment:
                    query += " AND environment = ?"
                    params.append(environment)

                query += " ORDER BY timestamp ASC"

                cursor.execute(query, params)
                rows = cursor.fetchall()

                # Convert to dictionaries
                results = []
                for row in rows:
                    results.append(dict(row))

                logger.debug(f"Retrieved {len(results)} trend data points")
                return results

        except Exception as e:
            logger.error(f"Failed to get trend data: {e}", exc_info=True)
            return []

    def get_severity_trend(
        self,
        project_name: str,
        environment: str,
        days: int = 30,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get severity trend over time.

        Args:
            project_name: Project name
            environment: Environment
            days: Number of days

        Returns:
            Dictionary with trend data for each severity level
        """
        data = self.get_trend_data(project_name, environment, days)

        trend = {
            "timestamps": [],
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }

        for assessment in data:
            trend["timestamps"].append(assessment["timestamp"])
            trend["critical"].append(assessment["critical_count"])
            trend["high"].append(assessment["high_count"])
            trend["medium"].append(assessment["medium_count"])
            trend["low"].append(assessment["low_count"])
            trend["info"].append(assessment["info_count"])

        return trend

    def get_check_history(
        self,
        check_id: str,
        project_name: Optional[str] = None,
        environment: Optional[str] = None,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """
        Get history of a specific check.

        Args:
            check_id: Check identifier
            project_name: Filter by project
            environment: Filter by environment
            days: Number of days

        Returns:
            List of check results over time
        """
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                query = """
                    SELECT a.timestamp, a.project_name, a.environment,
                           f.severity, f.status, f.evidence
                    FROM findings f
                    JOIN assessments a ON f.assessment_id = a.id
                    WHERE f.check_id = ? AND a.timestamp >= ?
                """
                params = [check_id, cutoff_date]

                if project_name:
                    query += " AND a.project_name = ?"
                    params.append(project_name)

                if environment:
                    query += " AND a.environment = ?"
                    params.append(environment)

                query += " ORDER BY a.timestamp ASC"

                cursor.execute(query, params)
                rows = cursor.fetchall()

                return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to get check history: {e}", exc_info=True)
            return []

    def get_statistics(
        self,
        project_name: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get overall statistics.

        Args:
            project_name: Filter by project
            environment: Filter by environment

        Returns:
            Statistics dictionary
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Build query
                query = "SELECT * FROM assessments WHERE 1=1"
                params = []

                if project_name:
                    query += " AND project_name = ?"
                    params.append(project_name)

                if environment:
                    query += " AND environment = ?"
                    params.append(environment)

                cursor.execute(query, params)
                rows = cursor.fetchall()

                if not rows:
                    return {"error": "No assessments found"}

                # Calculate statistics
                total_assessments = len(rows)
                avg_critical = sum(row[5] for row in rows) / total_assessments
                avg_high = sum(row[6] for row in rows) / total_assessments
                avg_medium = sum(row[7] for row in rows) / total_assessments

                # Get latest assessment
                latest = rows[-1]

                return {
                    "total_assessments": total_assessments,
                    "first_assessment": rows[0][1],  # timestamp
                    "latest_assessment": latest[1],
                    "avg_critical": round(avg_critical, 2),
                    "avg_high": round(avg_high, 2),
                    "avg_medium": round(avg_medium, 2),
                    "latest_critical": latest[5],
                    "latest_high": latest[6],
                    "latest_medium": latest[7],
                }

        except Exception as e:
            logger.error(f"Failed to get statistics: {e}", exc_info=True)
            return {"error": str(e)}

    def clear_old_data(self, days: int = 90) -> int:
        """
        Clear data older than specified days.

        Args:
            days: Delete data older than this

        Returns:
            Number of assessments deleted
        """
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Get IDs to delete
                cursor.execute(
                    "SELECT id FROM assessments WHERE timestamp < ?", (cutoff_date,)
                )
                assessment_ids = [row[0] for row in cursor.fetchall()]

                if not assessment_ids:
                    logger.info("No old data to clear")
                    return 0

                # Delete findings first (foreign key constraint)
                cursor.execute(
                    f"DELETE FROM findings WHERE assessment_id IN ({','.join('?' * len(assessment_ids))})",
                    assessment_ids,
                )

                # Delete assessments
                cursor.execute(
                    "DELETE FROM assessments WHERE timestamp < ?", (cutoff_date,)
                )

                conn.commit()

            logger.info(f"Cleared {len(assessment_ids)} old assessments")
            return len(assessment_ids)

        except Exception as e:
            logger.error(f"Failed to clear old data: {e}", exc_info=True)
            return 0

    def export_trends(
        self,
        output_path: Path,
        project_name: Optional[str] = None,
        environment: Optional[str] = None,
        days: int = 30,
    ) -> bool:
        """
        Export trend data to JSON file.

        Args:
            output_path: Output file path
            project_name: Filter by project
            environment: Filter by environment
            days: Number of days

        Returns:
            True if exported successfully
        """
        try:
            data = self.get_trend_data(project_name, environment, days)
            stats = self.get_statistics(project_name, environment)

            export_data = {
                "generated_at": datetime.now().isoformat(),
                "project_name": project_name,
                "environment": environment,
                "days": days,
                "statistics": stats,
                "assessments": data,
            }

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Trends exported to: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export trends: {e}", exc_info=True)
            return False
