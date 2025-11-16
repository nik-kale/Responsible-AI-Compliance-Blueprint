"""Risk matrix visualization component."""

import plotly.graph_objects as go
import streamlit as st
from typing import List, Dict, Any


def render_risk_matrix(threats: List[Dict[str, Any]]):
    """
    Render interactive risk matrix using Plotly.

    Args:
        threats: List of threat dictionaries
    """
    if not threats:
        st.info("No threats documented yet.")
        return

    # Map likelihood and impact to numeric scores
    likelihood_map = {
        "very_low": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "very_high": 5,
    }

    impact_map = {
        "negligible": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5,
    }

    # Prepare data for plotting
    x_values = []
    y_values = []
    sizes = []
    colors = []
    labels = []

    for threat in threats:
        likelihood = threat.get("likelihood", "medium")
        impact = threat.get("impact", "medium")

        x = likelihood_map.get(likelihood, 3)
        y = impact_map.get(impact, 3)

        risk_score = x * y

        x_values.append(x)
        y_values.append(y)
        sizes.append(risk_score * 5)  # Scale for visibility

        # Color based on risk score
        if risk_score >= 16:
            color = "#dc2626"  # Critical (red)
        elif risk_score >= 12:
            color = "#ea580c"  # High (orange)
        elif risk_score >= 6:
            color = "#d97706"  # Medium (amber)
        else:
            color = "#65a30d"  # Low (green)

        colors.append(color)
        labels.append(
            f"<b>{threat.get('title', 'Unknown')}</b><br>"
            f"ID: {threat.get('id', 'N/A')}<br>"
            f"Likelihood: {likelihood}<br>"
            f"Impact: {impact}<br>"
            f"Risk Score: {risk_score}"
        )

    # Create scatter plot
    fig = go.Figure()

    fig.add_trace(
        go.Scatter(
            x=x_values,
            y=y_values,
            mode="markers",
            marker=dict(
                size=sizes,
                color=colors,
                opacity=0.7,
                line=dict(width=2, color="white"),
            ),
            text=labels,
            hoverinfo="text",
        )
    )

    # Update layout
    fig.update_layout(
        title="Risk Matrix: Likelihood × Impact",
        xaxis=dict(
            title="Likelihood",
            tickmode="array",
            tickvals=[1, 2, 3, 4, 5],
            ticktext=["Very Low", "Low", "Medium", "High", "Very High"],
            range=[0.5, 5.5],
        ),
        yaxis=dict(
            title="Impact",
            tickmode="array",
            tickvals=[1, 2, 3, 4, 5],
            ticktext=["Negligible", "Low", "Medium", "High", "Critical"],
            range=[0.5, 5.5],
        ),
        height=500,
        hovermode="closest",
    )

    # Add background zones
    shapes = []

    # Critical zone (top-right)
    shapes.append(
        dict(
            type="rect",
            x0=3.5,
            y0=3.5,
            x1=5.5,
            y1=5.5,
            fillcolor="#fee2e2",
            opacity=0.3,
            line=dict(width=0),
            layer="below",
        )
    )

    # High zone
    shapes.append(
        dict(
            type="rect",
            x0=2.5,
            y0=3.5,
            x1=3.5,
            y1=5.5,
            fillcolor="#ffedd5",
            opacity=0.3,
            line=dict(width=0),
            layer="below",
        )
    )

    shapes.append(
        dict(
            type="rect",
            x0=3.5,
            y0=2.5,
            x1=5.5,
            y1=3.5,
            fillcolor="#ffedd5",
            opacity=0.3,
            line=dict(width=0),
            layer="below",
        )
    )

    fig.update_layout(shapes=shapes)

    st.plotly_chart(fig, use_container_width=True)

    # Display risk summary
    risk_scores = [x * y for x, y in zip(x_values, y_values)]

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Threats", len(threats))

    with col2:
        critical_count = sum(1 for score in risk_scores if score >= 16)
        st.metric("Critical Risk", critical_count)

    with col3:
        high_count = sum(1 for score in risk_scores if 12 <= score < 16)
        st.metric("High Risk", high_count)

    with col4:
        medium_count = sum(1 for score in risk_scores if 6 <= score < 12)
        st.metric("Medium Risk", medium_count)
