"""Framework mappings for OWASP AI Security and ISO/IEC 42001."""

from typing import Dict, List

# OWASP AI Security Top 10 for LLMs
OWASP_MAPPING: Dict[str, Dict[str, str]] = {
    "LLM01": {
        "name": "Prompt Injection",
        "description": "Manipulating LLM via crafted inputs",
        "checks": ["inference_security", "input_validation"],
    },
    "LLM02": {
        "name": "Insecure Output Handling",
        "description": "Insufficient validation of LLM outputs",
        "checks": ["inference_security", "output_validation"],
    },
    "LLM03": {
        "name": "Training Data Poisoning",
        "description": "Manipulating training data or fine-tuning",
        "checks": ["data_integrity", "supply_chain"],
    },
    "LLM04": {
        "name": "Model Denial of Service",
        "description": "Resource exhaustion attacks",
        "checks": ["inference_security", "rate_limiting"],
    },
    "LLM05": {
        "name": "Supply Chain Vulnerabilities",
        "description": "Compromised components, data, or models",
        "checks": ["supply_chain", "model_artifacts"],
    },
    "LLM06": {
        "name": "Sensitive Information Disclosure",
        "description": "Leaking sensitive data in outputs",
        "checks": ["pii_privacy", "logging_audit"],
    },
    "LLM07": {
        "name": "Insecure Plugin Design",
        "description": "Unsafe plugin/extension handling",
        "checks": ["inference_security", "supply_chain"],
    },
    "LLM08": {
        "name": "Excessive Agency",
        "description": "Unconstrained LLM actions",
        "checks": ["governance", "inference_security"],
    },
    "LLM09": {
        "name": "Overreliance",
        "description": "Excessive trust without oversight",
        "checks": ["governance", "model_artifacts"],
    },
    "LLM10": {
        "name": "Model Theft",
        "description": "Unauthorized access or extraction",
        "checks": ["inference_security", "model_artifacts"],
    },
}

# ISO/IEC 42001 AI Management System
ISO_MAPPING: Dict[str, Dict[str, str]] = {
    "Clause_4": {
        "name": "Context of Organization",
        "description": "Understanding organizational context and stakeholders",
        "checks": ["governance"],
    },
    "Clause_5": {
        "name": "Leadership",
        "description": "Management commitment and roles",
        "checks": ["governance"],
    },
    "Clause_6": {
        "name": "Planning",
        "description": "Risk assessment and treatment",
        "checks": ["governance", "data_integrity", "all"],
    },
    "Clause_6.1": {
        "name": "Risk Assessment",
        "description": "Identifying and analyzing AI risks",
        "checks": ["all"],
    },
    "Clause_7": {
        "name": "Support",
        "description": "Resources, competence, awareness",
        "checks": ["governance", "model_artifacts"],
    },
    "Clause_8": {
        "name": "Operation",
        "description": "AI system lifecycle management",
        "checks": ["model_artifacts", "logging_audit", "data_integrity"],
    },
    "Clause_8.1": {
        "name": "Operational Planning",
        "description": "AI system development and deployment",
        "checks": ["model_artifacts", "governance"],
    },
    "Clause_9": {
        "name": "Performance Evaluation",
        "description": "Monitoring, measurement, analysis",
        "checks": ["logging_audit", "governance"],
    },
    "Clause_10": {
        "name": "Improvement",
        "description": "Continual improvement processes",
        "checks": ["governance", "logging_audit"],
    },
}

# Check category to framework mapping
CHECK_TO_OWASP: Dict[str, List[str]] = {
    "data_integrity": ["LLM03", "LLM05"],
    "model_artifacts": ["LLM05", "LLM09", "LLM10"],
    "supply_chain": ["LLM03", "LLM05", "LLM07"],
    "pii_privacy": ["LLM06"],
    "inference_security": ["LLM01", "LLM02", "LLM04", "LLM07", "LLM08", "LLM10"],
    "logging_audit": ["LLM06"],
    "governance": ["LLM08", "LLM09"],
}

CHECK_TO_ISO: Dict[str, List[str]] = {
    "data_integrity": ["Clause_6.1", "Clause_8"],
    "model_artifacts": ["Clause_7", "Clause_8", "Clause_8.1"],
    "supply_chain": ["Clause_6.1", "Clause_8"],
    "pii_privacy": ["Clause_6.1", "Clause_8"],
    "inference_security": ["Clause_6.1", "Clause_8"],
    "logging_audit": ["Clause_8", "Clause_9"],
    "governance": ["Clause_4", "Clause_5", "Clause_6", "Clause_7", "Clause_9", "Clause_10"],
}


def get_framework_mappings(check_category: str) -> Dict[str, List[str]]:
    """
    Get framework mappings for a check category.

    Args:
        check_category: Check category name

    Returns:
        Dictionary with 'owasp' and 'iso' keys
    """
    return {
        "owasp": CHECK_TO_OWASP.get(check_category, []),
        "iso": CHECK_TO_ISO.get(check_category, []),
    }


def get_owasp_description(owasp_id: str) -> str:
    """Get description for OWASP ID."""
    mapping = OWASP_MAPPING.get(owasp_id, {})
    return f"{mapping.get('name', owasp_id)}: {mapping.get('description', 'N/A')}"


def get_iso_description(iso_id: str) -> str:
    """Get description for ISO clause."""
    mapping = ISO_MAPPING.get(iso_id, {})
    return f"{mapping.get('name', iso_id)}: {mapping.get('description', 'N/A')}"


def generate_mapping_table() -> List[Dict[str, str]]:
    """
    Generate a table of all check-to-framework mappings.

    Returns:
        List of mapping dictionaries
    """
    table = []

    for check_category in CHECK_TO_OWASP.keys():
        mappings = get_framework_mappings(check_category)
        table.append(
            {
                "check_category": check_category,
                "owasp": ", ".join(mappings["owasp"]),
                "iso": ", ".join(mappings["iso"]),
            }
        )

    return table
