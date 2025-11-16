"""Inference security checks for runtime protection."""

from pathlib import Path
from typing import List

from ..config.schema import ProjectConfig, Finding, Severity, Status


def run_checks(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """
    Run inference security checks.

    Args:
        config: Project configuration
        project_root: Project root directory
        env: Environment name

    Returns:
        List of findings
    """
    findings: List[Finding] = []

    # Get environment config
    env_config = config.environments.get(env)

    if not env_config:
        findings.append(
            Finding(
                check_id="INFER-000",
                title=f"Environment Not Configured: {env}",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="inference_security",
                description=f"Environment '{env}' is not configured",
                evidence=f"Available environments: {', '.join(config.environments.keys())}",
                remediation=f"Add '{env}' to environments section in config",
                owasp_mapping=["LLM01", "LLM02", "LLM04"],
                iso_mapping=["Clause_8"],
            )
        )
        return findings

    # Check 1: TLS/SSL requirement
    findings.extend(_check_tls(env_config, env))

    # Check 2: Authentication requirement
    findings.extend(_check_authentication(env_config, env))

    # Check 3: Rate limiting
    findings.extend(_check_rate_limiting(env_config, env))

    # Check 4: Input validation
    findings.extend(_check_input_validation(env_config, env))

    # Check 5: Prompt injection mitigations
    findings.extend(_check_prompt_injection_mitigations(env_config, env))

    # Check 6: Resource limits
    findings.extend(_check_resource_limits(env_config, env))

    return findings


def _check_tls(env_config, env: str) -> List[Finding]:
    """Check TLS/SSL configuration."""
    findings = []

    if env in ["prod", "production"]:
        if not env_config.tls_required:
            findings.append(
                Finding(
                    check_id="INFER-001",
                    title="TLS Not Required in Production",
                    severity=Severity.CRITICAL,
                    status=Status.FAIL,
                    category="inference_security",
                    description="TLS/SSL is not required in production environment",
                    evidence=f"Environment: {env}, tls_required: false",
                    remediation="Enable TLS for production environments",
                    owasp_mapping=["LLM06", "LLM10"],
                    iso_mapping=["Clause_8"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="INFER-001",
                    title="TLS Required",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="inference_security",
                    description="TLS/SSL is required",
                    evidence=f"Environment: {env}",
                    remediation="N/A",
                    owasp_mapping=["LLM06", "LLM10"],
                    iso_mapping=["Clause_8"],
                )
            )
    else:
        # For dev/test, TLS is recommended but not critical
        if env_config.tls_required:
            findings.append(
                Finding(
                    check_id="INFER-001",
                    title="TLS Enabled",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    category="inference_security",
                    description=f"TLS is enabled for {env} environment",
                    evidence=f"Environment: {env}",
                    remediation="N/A",
                    owasp_mapping=["LLM06", "LLM10"],
                    iso_mapping=["Clause_8"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="INFER-001",
                    title="TLS Not Enabled",
                    severity=Severity.LOW,
                    status=Status.WARNING,
                    category="inference_security",
                    description=f"TLS is not enabled for {env} environment",
                    evidence=f"Environment: {env}",
                    remediation="Consider enabling TLS even in non-production",
                    owasp_mapping=["LLM06", "LLM10"],
                    iso_mapping=["Clause_8"],
                )
            )

    return findings


def _check_authentication(env_config, env: str) -> List[Finding]:
    """Check authentication configuration."""
    findings = []

    if not env_config.auth_required:
        severity = Severity.CRITICAL if env in ["prod", "production"] else Severity.MEDIUM
        findings.append(
            Finding(
                check_id="INFER-002",
                title="Authentication Not Required",
                severity=severity,
                status=Status.FAIL,
                category="inference_security",
                description="Authentication is not required for API access",
                evidence=f"Environment: {env}, auth_required: false",
                remediation="Enable authentication to prevent unauthorized access",
                owasp_mapping=["LLM01", "LLM10"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="INFER-002",
                title="Authentication Required",
                severity=Severity.INFO,
                status=Status.PASS,
                category="inference_security",
                description="Authentication is required for API access",
                evidence=f"Environment: {env}",
                remediation="N/A",
                owasp_mapping=["LLM01", "LLM10"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_rate_limiting(env_config, env: str) -> List[Finding]:
    """Check rate limiting configuration."""
    findings = []

    if not env_config.rate_limiting:
        findings.append(
            Finding(
                check_id="INFER-003",
                title="Rate Limiting Not Enabled",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="inference_security",
                description="Rate limiting is not enabled - vulnerable to DoS",
                evidence=f"Environment: {env}, rate_limiting: false",
                remediation="Enable rate limiting to prevent resource exhaustion attacks",
                owasp_mapping=["LLM04"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="INFER-003",
                title="Rate Limiting Enabled",
                severity=Severity.INFO,
                status=Status.PASS,
                category="inference_security",
                description="Rate limiting is enabled",
                evidence=f"Environment: {env}",
                remediation="N/A",
                owasp_mapping=["LLM04"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_input_validation(env_config, env: str) -> List[Finding]:
    """Check input validation configuration."""
    findings = []

    if not env_config.input_validation:
        findings.append(
            Finding(
                check_id="INFER-004",
                title="Input Validation Not Enabled",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="inference_security",
                description="Input validation is not enabled",
                evidence=f"Environment: {env}, input_validation: false",
                remediation="Enable input validation to prevent injection attacks",
                owasp_mapping=["LLM01", "LLM02"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="INFER-004",
                title="Input Validation Enabled",
                severity=Severity.INFO,
                status=Status.PASS,
                category="inference_security",
                description="Input validation is enabled",
                evidence=f"Environment: {env}",
                remediation="Ensure validation rules are comprehensive",
                owasp_mapping=["LLM01", "LLM02"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_prompt_injection_mitigations(env_config, env: str) -> List[Finding]:
    """Check for prompt injection mitigations."""
    findings = []

    # This is a heuristic check based on configuration
    mitigations = []

    if env_config.input_validation:
        mitigations.append("input validation")

    if env_config.max_input_size:
        mitigations.append(f"input size limit ({env_config.max_input_size} bytes)")

    if env_config.max_tokens:
        mitigations.append(f"token limit ({env_config.max_tokens} tokens)")

    if mitigations:
        findings.append(
            Finding(
                check_id="INFER-005",
                title="Prompt Injection Mitigations Present",
                severity=Severity.INFO,
                status=Status.PASS,
                category="inference_security",
                description=f"Found {len(mitigations)} mitigation(s) for prompt injection",
                evidence=f"Mitigations: {', '.join(mitigations)}",
                remediation="Consider additional mitigations: prompt templates, output filtering",
                owasp_mapping=["LLM01"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="INFER-005",
                title="Limited Prompt Injection Mitigations",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="inference_security",
                description="Few configured mitigations for prompt injection attacks",
                evidence=f"Environment: {env}",
                remediation="Implement: input validation, size limits, prompt templates, output filtering",
                owasp_mapping=["LLM01"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_resource_limits(env_config, env: str) -> List[Finding]:
    """Check resource limit configuration."""
    findings = []

    limits_configured = []

    if env_config.max_input_size:
        limits_configured.append(f"max_input_size: {env_config.max_input_size}")

    if env_config.max_tokens:
        limits_configured.append(f"max_tokens: {env_config.max_tokens}")

    if env_config.timeout_seconds:
        limits_configured.append(f"timeout: {env_config.timeout_seconds}s")

    if not limits_configured:
        findings.append(
            Finding(
                check_id="INFER-006",
                title="No Resource Limits Configured",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="inference_security",
                description="No resource limits configured for inference",
                evidence=f"Environment: {env}",
                remediation="Configure max_input_size, max_tokens, and timeout_seconds",
                owasp_mapping=["LLM04"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="INFER-006",
                title="Resource Limits Configured",
                severity=Severity.INFO,
                status=Status.PASS,
                category="inference_security",
                description=f"Resource limits configured: {', '.join(limits_configured)}",
                evidence=f"Environment: {env}",
                remediation="N/A",
                owasp_mapping=["LLM04"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings
