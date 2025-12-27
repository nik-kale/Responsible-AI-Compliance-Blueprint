"""Streamlit web UI for Responsible AI Compliance Blueprint."""

import sys
import tempfile
from pathlib import Path
from typing import Optional

# Add parent directory to path to import raicb
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import streamlit as st
from raicb.config.schema import ProjectConfig
from raicb.core.loader import load_config
from raicb.core.evaluator import run_all_checks
from raicb.core.report import generate_report
from raicb.core.mapping import generate_mapping_table, OWASP_MAPPING, ISO_MAPPING

from components import render_risk_matrix, render_checklist_table


def validate_safe_path(user_path: str, base_dir: Optional[Path] = None) -> Optional[Path]:
    """
    Validate that user-provided path is safe and within allowed directory.

    Args:
        user_path: User-provided path string
        base_dir: Base directory to restrict access (default: cwd)

    Returns:
        Validated Path object or None if invalid/unsafe
    """
    if not user_path:
        return None

    try:
        path = Path(user_path).resolve()

        # If base_dir specified, ensure path is within it
        if base_dir:
            base = base_dir.resolve()
            try:
                path.relative_to(base)
            except ValueError:
                # Path is outside base_dir
                st.error(f"⚠️ Path must be within {base_dir}")
                return None

        # Additional safety: prevent accessing system directories
        str_path = str(path)
        dangerous_paths = ['/etc', '/sys', '/proc', 'C:\\Windows', 'C:\\System32']
        for dangerous in dangerous_paths:
            if str_path.startswith(dangerous):
                st.error("⚠️ Access to system directories is not allowed")
                return None

        return path

    except (ValueError, RuntimeError, OSError) as e:
        st.error(f"⚠️ Invalid path: {e}")
        return None


# Page configuration
st.set_page_config(
    page_title="Responsible AI Compliance Blueprint",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1f2937;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.25rem;
        color: #6b7280;
        margin-bottom: 2rem;
    }
    .disclaimer-box {
        background-color: #fef3c7;
        border-left: 4px solid #f59e0b;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 4px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def main():
    """Main Streamlit application."""

    # Header
    st.markdown('<div class="main-header">🔒 Responsible AI Compliance Blueprint</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-header">Self-audit toolkit for AI systems against OWASP AI Security and ISO/IEC 42001</div>',
        unsafe_allow_html=True,
    )

    # Disclaimer
    st.markdown(
        """
        <div class="disclaimer-box">
        <strong>⚠️ DISCLAIMER:</strong> This tool does NOT provide official certification.
        Results are best-effort mappings to help identify security and governance gaps.
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Sidebar
    st.sidebar.title("Configuration")

    # Health Check
    if st.sidebar.button("Check System Health"):
        from raicb.core.health import check_health
        health = check_health()
        if health["status"] == "healthy":
            st.sidebar.success(f"System Status: {health['status']}")
        else:
            st.sidebar.error(f"System Status: {health['status']}")

        st.sidebar.json(health)
        st.sidebar.markdown("---")

    # Project selection mode
    mode = st.sidebar.radio(
        "Select Mode",
        ["Upload Configuration", "Browse Filesystem"],
    )

    config_path = None
    project_root = None

    if mode == "Upload Configuration":
        uploaded_file = st.sidebar.file_uploader(
            "Upload raicb.yaml",
            type=["yaml", "yml"],
            help="Upload your project configuration file",
        )

        if uploaded_file:
            # Save to temp location (cross-platform compatible)
            temp_dir = Path(tempfile.gettempdir()) / "raicb"
            temp_dir.mkdir(parents=True, exist_ok=True)
            config_path = temp_dir / "raicb.yaml"
            config_path.write_bytes(uploaded_file.getvalue())
            project_root = temp_dir

    else:
        # Browse filesystem
        default_path = st.sidebar.text_input(
            "Configuration Path",
            value="./raicb.yaml",
            help="Path to raicb.yaml file",
        )

        if default_path:
            # Validate path for security
            config_path = validate_safe_path(default_path, base_dir=Path.cwd())
            if config_path and config_path.exists():
                project_root = config_path.parent
            elif config_path:
                st.sidebar.error(f"Configuration file not found: {config_path}")
                config_path = None

    # Environment selection
    environment = st.sidebar.selectbox(
        "Environment",
        ["dev", "stage", "prod"],
        index=2,
        help="Select environment to assess",
    )

    # Main content tabs
    if config_path and config_path.exists():
        try:
            # Load configuration
            config = load_config(config_path)

            st.success(f"✓ Loaded configuration: {config.project.name} v{config.project.version}")

            # Create tabs
            tab1, tab2, tab3, tab4, tab5 = st.tabs(
                ["📊 Dashboard", "✅ Checklist", "🎯 Risk Matrix", "📋 Reports", "🗺️ Mappings"]
            )

            # Tab 1: Dashboard
            with tab1:
                st.header("Assessment Dashboard")

                # Run assessment button
                if st.button("🔍 Run Assessment", type="primary", use_container_width=True):
                    with st.spinner("Running compliance checks..."):
                        try:
                            report = run_all_checks(config, project_root, environment, verbose=False)

                            # Store in session state
                            st.session_state.report = report

                            st.success("✓ Assessment complete!")

                        except Exception as e:
                            st.error(f"Error running assessment: {e}")

                # Display results if available
                if "report" in st.session_state:
                    report = st.session_state.report

                    # Metrics
                    col1, col2, col3, col4 = st.columns(4)

                    with col1:
                        st.metric("Total Checks", report.total_checks)

                    with col2:
                        st.metric("Passed", report.passed_checks, delta=None)

                    with col3:
                        st.metric("Failed", report.failed_checks, delta=None, delta_color="inverse")

                    with col4:
                        st.metric("Warnings", report.warnings, delta=None)

                    # Pass rate
                    pass_rate = (report.passed_checks / report.total_checks * 100) if report.total_checks > 0 else 0

                    st.metric("Pass Rate", f"{pass_rate:.1f}%")

                    # Progress bar
                    st.progress(pass_rate / 100)

                    # Severity breakdown
                    st.subheader("Findings by Severity")

                    severity_data = {}
                    for finding in report.findings:
                        severity = finding.severity.value
                        severity_data[severity] = severity_data.get(severity, 0) + 1

                    col1, col2, col3, col4, col5 = st.columns(5)

                    with col1:
                        st.metric("🔴 Critical", severity_data.get("critical", 0))
                    with col2:
                        st.metric("🟠 High", severity_data.get("high", 0))
                    with col3:
                        st.metric("🟡 Medium", severity_data.get("medium", 0))
                    with col4:
                        st.metric("🟢 Low", severity_data.get("low", 0))
                    with col5:
                        st.metric("🔵 Info", severity_data.get("info", 0))

                    # Category breakdown
                    st.subheader("Findings by Category")

                    category_data = {}
                    for finding in report.findings:
                        cat = finding.category
                        category_data[cat] = category_data.get(cat, 0) + 1

                    import pandas as pd

                    df = pd.DataFrame(
                        list(category_data.items()),
                        columns=["Category", "Count"],
                    )

                    st.bar_chart(df.set_index("Category"))

                else:
                    st.info("👆 Click 'Run Assessment' to start compliance checks")

            # Tab 2: Checklist
            with tab2:
                st.header("Compliance Checklist")

                if "report" in st.session_state:
                    report = st.session_state.report

                    # Filters
                    col1, col2, col3 = st.columns(3)

                    with col1:
                        category_filter = st.selectbox(
                            "Filter by Category",
                            ["All"] + list(set(f.category for f in report.findings)),
                        )

                    with col2:
                        severity_filter = st.selectbox(
                            "Filter by Severity",
                            ["All", "critical", "high", "medium", "low", "info"],
                        )

                    with col3:
                        status_filter = st.selectbox(
                            "Filter by Status",
                            ["All", "pass", "fail", "warning", "skip", "error"],
                        )

                    filters = {
                        "category": category_filter,
                        "severity": severity_filter,
                        "status": status_filter,
                    }

                    render_checklist_table(report.findings, filters)

                else:
                    st.info("Run an assessment first to see the checklist")

            # Tab 3: Risk Matrix
            with tab3:
                st.header("Risk Matrix")

                # Convert threats to dict format
                threats = []
                for threat in config.threats:
                    threats.append(
                        {
                            "id": threat.id,
                            "title": threat.title,
                            "likelihood": threat.likelihood.value,
                            "impact": threat.impact.value,
                        }
                    )

                render_risk_matrix(threats)

            # Tab 4: Reports
            with tab4:
                st.header("Generate Reports")

                if "report" in st.session_state:
                    report = st.session_state.report

                    # Report options
                    col1, col2 = st.columns(2)

                    with col1:
                        output_dir = st.text_input(
                            "Output Directory",
                            value="./reports",
                        )

                    with col2:
                        formats = st.multiselect(
                            "Formats",
                            ["md", "html", "pdf"],
                            default=["md", "html"],
                        )

                    if st.button("📄 Generate Reports", type="primary"):
                        with st.spinner("Generating reports..."):
                            try:
                                # Validate output directory for security
                                output_path = validate_safe_path(output_dir, base_dir=Path.cwd())
                                if not output_path:
                                    st.error("Invalid output directory")
                                    raise ValueError("Invalid output directory")

                                generated_files = generate_report(report, output_path, formats)

                                st.success(f"✓ Generated {len(generated_files)} report(s)")

                                for file_path in generated_files:
                                    st.write(f"- {file_path}")

                                    # Provide download link for markdown
                                    if file_path.suffix == ".md":
                                        with open(file_path, "r") as f:
                                            st.download_button(
                                                label=f"Download {file_path.name}",
                                                data=f.read(),
                                                file_name=file_path.name,
                                                mime="text/markdown",
                                            )

                                    # Provide download link for HTML
                                    elif file_path.suffix == ".html":
                                        with open(file_path, "r") as f:
                                            st.download_button(
                                                label=f"Download {file_path.name}",
                                                data=f.read(),
                                                file_name=file_path.name,
                                                mime="text/html",
                                            )

                            except Exception as e:
                                st.error(f"Error generating reports: {e}")

                else:
                    st.info("Run an assessment first to generate reports")

            # Tab 5: Mappings
            with tab5:
                st.header("Framework Mappings")

                # OWASP mapping
                st.subheader("OWASP AI Security Top 10")

                import pandas as pd

                owasp_data = []
                for owasp_id, info in OWASP_MAPPING.items():
                    owasp_data.append(
                        {
                            "ID": owasp_id,
                            "Name": info["name"],
                            "Description": info["description"],
                        }
                    )

                st.dataframe(pd.DataFrame(owasp_data), use_container_width=True)

                # ISO mapping
                st.subheader("ISO/IEC 42001 Clauses")

                iso_data = []
                for iso_id, info in ISO_MAPPING.items():
                    iso_data.append(
                        {
                            "Clause": iso_id,
                            "Name": info["name"],
                            "Description": info["description"],
                        }
                    )

                st.dataframe(pd.DataFrame(iso_data), use_container_width=True)

                # Check mappings
                st.subheader("Check to Framework Mapping")

                mapping_table = generate_mapping_table()
                st.dataframe(pd.DataFrame(mapping_table), use_container_width=True)

        except Exception as e:
            st.error(f"Error loading configuration: {e}")
            st.exception(e)

    else:
        # No configuration loaded
        st.info("👈 Upload or select a configuration file to get started")

        st.markdown("## Quick Start")

        st.markdown(
            """
            1. **Prepare your configuration**: Create a `raicb.yaml` file with project metadata,
               artifacts, policies, threats, and controls
            2. **Upload or select**: Use the sidebar to upload your configuration or browse to it
            3. **Run assessment**: Click 'Run Assessment' to perform compliance checks
            4. **Review findings**: Explore results in the Checklist and Risk Matrix tabs
            5. **Generate reports**: Export findings in Markdown, HTML, or PDF format
            """
        )

        st.markdown("## Example Configuration")

        st.code(
            """
project:
  name: "My AI System"
  version: "1.0.0"
  owners:
    - name: "AI Team"
      email: "ai-team@example.com"

artifacts:
  model_path: "./artifacts/model.pt"
  model_card: "./model_card.yaml"

environments:
  prod:
    tls_required: true
    auth_required: true
    rate_limiting: true

threats:
  - id: "THREAT-001"
    title: "Data Poisoning"
    likelihood: "medium"
    impact: "high"
    controls: ["DATA-HASH"]

controls:
  - id: "DATA-HASH"
    title: "Dataset Hash Verification"
    implemented: true
            """,
            language="yaml",
        )


if __name__ == "__main__":
    main()
