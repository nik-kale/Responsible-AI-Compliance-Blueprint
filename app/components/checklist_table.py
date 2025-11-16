"""Checklist table component."""

import pandas as pd
import streamlit as st
from typing import List


def render_checklist_table(findings: List, filters: dict = None):
    """
    Render findings as an interactive table with filtering.

    Args:
        findings: List of Finding objects
        filters: Dictionary of filter options
    """
    if not findings:
        st.info("No findings to display.")
        return

    # Convert findings to DataFrame
    data = []
    for finding in findings:
        data.append(
            {
                "Check ID": finding.check_id,
                "Title": finding.title,
                "Category": finding.category,
                "Severity": finding.severity.value,
                "Status": finding.status.value,
                "Description": finding.description,
                "Evidence": finding.evidence or "N/A",
                "Remediation": finding.remediation or "N/A",
                "OWASP": ", ".join(finding.owasp_mapping) if finding.owasp_mapping else "-",
                "ISO": ", ".join(finding.iso_mapping) if finding.iso_mapping else "-",
            }
        )

    df = pd.DataFrame(data)

    # Apply filters
    if filters:
        if filters.get("category") and filters["category"] != "All":
            df = df[df["Category"] == filters["category"]]

        if filters.get("severity") and filters["severity"] != "All":
            df = df[df["Severity"] == filters["severity"]]

        if filters.get("status") and filters["status"] != "All":
            df = df[df["Status"] == filters["status"]]

    # Display metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Findings", len(df))

    with col2:
        passed = len(df[df["Status"] == "pass"])
        st.metric("Passed", passed, delta=None)

    with col3:
        failed = len(df[df["Status"] == "fail"])
        st.metric("Failed", failed, delta=None)

    with col4:
        warnings = len(df[df["Status"] == "warning"])
        st.metric("Warnings", warnings, delta=None)

    # Severity breakdown
    st.subheader("Severity Distribution")

    severity_counts = df["Severity"].value_counts()
    col1, col2, col3, col4, col5 = st.columns(5)

    severity_order = ["critical", "high", "medium", "low", "info"]
    severity_colors = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "🔵",
    }

    for col, severity in zip([col1, col2, col3, col4, col5], severity_order):
        count = severity_counts.get(severity, 0)
        with col:
            st.metric(
                f"{severity_colors.get(severity, '•')} {severity.title()}",
                count,
            )

    # Display table
    st.subheader("Detailed Findings")

    # Add styling based on severity
    def highlight_severity(row):
        severity = row["Severity"]
        colors = {
            "critical": "background-color: #fee2e2",
            "high": "background-color: #ffedd5",
            "medium": "background-color: #fef3c7",
            "low": "background-color: #ecfccb",
            "info": "background-color: #dbeafe",
        }
        return [colors.get(severity, "")] * len(row)

    # Display with formatting
    st.dataframe(
        df.style.apply(highlight_severity, axis=1),
        use_container_width=True,
        height=400,
    )

    # Expandable details
    st.subheader("Finding Details")

    for idx, row in df.iterrows():
        with st.expander(f"{row['Check ID']}: {row['Title']}"):
            col1, col2 = st.columns(2)

            with col1:
                st.markdown(f"**Category:** {row['Category']}")
                st.markdown(f"**Severity:** {row['Severity']}")
                st.markdown(f"**Status:** {row['Status']}")

            with col2:
                st.markdown(f"**OWASP:** {row['OWASP']}")
                st.markdown(f"**ISO:** {row['ISO']}")

            st.markdown(f"**Description:** {row['Description']}")
            st.markdown(f"**Evidence:** {row['Evidence']}")
            st.markdown(f"**Remediation:** {row['Remediation']}")

    # Download button
    st.download_button(
        label="Download Findings CSV",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name="compliance_findings.csv",
        mime="text/csv",
    )
