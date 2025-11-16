"""Inference security checks for runtime protection."""

from pathlib import Path
from typing import List

from ..config.schema import ProjectConfig, Finding, Severity, Status
from ..core.logger import get_logger

logger = get_logger(__name__)


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

    # Check 7: Output validation (LLM02 - Insecure Output Handling)
    findings.extend(_check_output_validation(env_config, env))

    # Check 8: Output encoding/sanitization
    findings.extend(_check_output_encoding(env_config, env))

    # Check 9: Dangerous content filtering
    findings.extend(_check_dangerous_content_filtering(env_config, env))

    # Check 10: Code execution prevention
    findings.extend(_check_code_execution_prevention(env_config, env))

    # Check 11: XSS/injection prevention
    findings.extend(_check_xss_prevention(env_config, env))

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


def _check_output_validation(env_config, env: str) -> List[Finding]:
    """Check if output validation is enabled (LLM02 - Insecure Output Handling)."""
    findings = []

    # Check if output_validation is configured
    output_validation = getattr(env_config, "output_validation", False)

    if not output_validation:
        severity = Severity.CRITICAL if env in ["prod", "production"] else Severity.HIGH
        findings.append(
            Finding(
                check_id="INFER-007",
                title="Output Validation Not Enabled",
                severity=severity,
                status=Status.FAIL,
                category="inference_security",
                description="Output validation is not enabled. LLM outputs can contain harmful content, code injection, or XSS payloads.",
                evidence=f"Environment: {env}, output_validation: false",
                remediation="Enable output validation to:\n"
                           "1. Validate LLM responses before returning to users\n"
                           "2. Detect and block dangerous patterns (SQL, code, scripts)\n"
                           "3. Sanitize outputs based on context (HTML, JSON, plaintext)\n"
                           "4. Log suspicious outputs for security review\n"
                           "5. Implement content safety filters",
                owasp_mapping=["LLM02"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="INFER-007",
                title="Output Validation Enabled",
                severity=Severity.INFO,
                status=Status.PASS,
                category="inference_security",
                description="Output validation is enabled to detect and prevent insecure outputs.",
                evidence=f"Environment: {env}, output_validation: true",
                remediation="N/A",
                owasp_mapping=["LLM02"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_output_encoding(env_config, env: str) -> List[Finding]:
    """Check if output encoding/sanitization is configured."""
    findings = []

    output_encoding = getattr(env_config, "output_encoding", None)

    if not output_encoding:
        severity = Severity.HIGH if env in ["prod", "production"] else Severity.MEDIUM
        findings.append(
            Finding(
                check_id="INFER-008",
                title="Output Encoding Not Configured",
                severity=severity,
                status=Status.FAIL,
                category="inference_security",
                description="Output encoding/sanitization is not configured. Outputs may contain unescaped content leading to XSS or injection vulnerabilities.",
                evidence=f"Environment: {env}, output_encoding: not set",
                remediation="Configure output encoding:\n"
                           "1. Set output_encoding to match output context (html, json, xml, plaintext)\n"
                           "2. Use context-aware escaping (HTML entity encoding, JSON escaping, etc.)\n"
                           "3. Never directly inject LLM outputs into HTML/JavaScript/SQL\n"
                           "4. Use templating engines with auto-escaping\n"
                           "5. Apply Content Security Policy (CSP) headers",
                owasp_mapping=["LLM02"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="INFER-008",
                title="Output Encoding Configured",
                severity=Severity.INFO,
                status=Status.PASS,
                category="inference_security",
                description=f"Output encoding is configured: {output_encoding}",
                evidence=f"Environment: {env}, output_encoding: {output_encoding}",
                remediation="Verify encoding is appropriate for all output contexts",
                owasp_mapping=["LLM02"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_dangerous_content_filtering(env_config, env: str) -> List[Finding]:
    """Check if dangerous content filtering is enabled."""
    findings = []

    content_filtering = getattr(env_config, "content_filtering", False)

    if not content_filtering:
        severity = Severity.HIGH if env in ["prod", "production"] else Severity.MEDIUM
        findings.append(
            Finding(
                check_id="INFER-009",
                title="Dangerous Content Filtering Not Enabled",
                severity=severity,
                status=Status.FAIL,
                category="inference_security",
                description="Dangerous content filtering is not enabled. LLM outputs may contain harmful instructions, malicious code, or unsafe content.",
                evidence=f"Environment: {env}, content_filtering: false",
                remediation="Enable content filtering to:\n"
                           "1. Detect and block malicious code patterns (scripts, SQL, shell commands)\n"
                           "2. Filter harmful instructions (violence, illegal activities, self-harm)\n"
                           "3. Detect PII/sensitive data in outputs\n"
                           "4. Block prompt leak attempts\n"
                           "5. Use content moderation APIs (OpenAI Moderation, Azure Content Safety, etc.)",
                owasp_mapping=["LLM02", "LLM06"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="INFER-009",
                title="Content Filtering Enabled",
                severity=Severity.INFO,
                status=Status.PASS,
                category="inference_security",
                description="Dangerous content filtering is enabled.",
                evidence=f"Environment: {env}, content_filtering: true",
                remediation="Regularly update filtering rules and review blocked content logs",
                owasp_mapping=["LLM02", "LLM06"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_code_execution_prevention(env_config, env: str) -> List[Finding]:
    """Check if code execution prevention measures are in place."""
    findings = []

    prevent_code_execution = getattr(env_config, "prevent_code_execution", False)

    if not prevent_code_execution:
        severity = Severity.CRITICAL if env in ["prod", "production"] else Severity.HIGH
        findings.append(
            Finding(
                check_id="INFER-010",
                title="Code Execution Prevention Not Configured",
                severity=severity,
                status=Status.FAIL,
                category="inference_security",
                description="No measures to prevent code execution from LLM outputs. Attackers could inject code that gets executed server-side or client-side.",
                evidence=f"Environment: {env}, prevent_code_execution: false",
                remediation="Implement code execution prevention:\n"
                           "1. Never use eval(), exec(), or similar functions on LLM outputs\n"
                           "2. Disable dynamic code execution features\n"
                           "3. Use sandboxing if code execution is required\n"
                           "4. Validate all outputs against code execution patterns\n"
                           "5. Implement strict CSP headers to prevent client-side execution\n"
                           "6. Use static code analysis on any LLM-generated code",
                owasp_mapping=["LLM02"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="INFER-010",
                title="Code Execution Prevention Enabled",
                severity=Severity.INFO,
                status=Status.PASS,
                category="inference_security",
                description="Code execution prevention measures are in place.",
                evidence=f"Environment: {env}, prevent_code_execution: true",
                remediation="N/A",
                owasp_mapping=["LLM02"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings


def _check_xss_prevention(env_config, env: str) -> List[Finding]:
    """Check if XSS prevention measures are configured."""
    findings = []

    xss_prevention = getattr(env_config, "xss_prevention", False)

    if not xss_prevention:
        severity = Severity.HIGH if env in ["prod", "production"] else Severity.MEDIUM
        findings.append(
            Finding(
                check_id="INFER-011",
                title="XSS Prevention Not Configured",
                severity=severity,
                status=Status.FAIL,
                category="inference_security",
                description="XSS prevention not configured for LLM outputs. Malicious outputs could inject scripts into user browsers.",
                evidence=f"Environment: {env}, xss_prevention: false",
                remediation="Implement XSS prevention:\n"
                           "1. HTML-escape all LLM outputs before rendering in browsers\n"
                           "2. Use Content Security Policy (CSP) headers\n"
                           "3. Set X-XSS-Protection header\n"
                           "4. Validate outputs against XSS patterns (<script>, onerror=, javascript:, etc.)\n"
                           "5. Use frameworks with auto-escaping (React, Vue with proper settings)\n"
                           "6. Never use dangerouslySetInnerHTML or v-html with LLM outputs\n"
                           "7. Implement output sanitization libraries (DOMPurify, bleach, etc.)",
                owasp_mapping=["LLM02"],
                iso_mapping=["Clause_8"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="INFER-011",
                title="XSS Prevention Configured",
                severity=Severity.INFO,
                status=Status.PASS,
                category="inference_security",
                description="XSS prevention measures are configured.",
                evidence=f"Environment: {env}, xss_prevention: true",
                remediation="Test XSS prevention regularly with known XSS payloads",
                owasp_mapping=["LLM02"],
                iso_mapping=["Clause_8"],
            )
        )

    return findings
