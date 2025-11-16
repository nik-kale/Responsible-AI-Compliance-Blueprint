"""Plugin security checks for LLM07 - Insecure Plugin Design."""

from pathlib import Path
from typing import List
import ast
import re

from ..config.schema import ProjectConfig, Finding, Severity, Status
from ..core.logger import get_logger

logger = get_logger(__name__)


def run_checks(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """
    Run plugin security checks.

    Covers:
    - OWASP LLM07: Insecure Plugin Design
    - Plugin permission models
    - Sandboxing validation
    - API security
    - Input/output validation

    Args:
        config: Project configuration
        project_root: Root directory of the project
        env: Environment (dev/staging/prod)

    Returns:
        List of findings from plugin security checks
    """
    logger.info("Running plugin security checks")

    findings = []

    # PLUGIN-001: Plugin permission model
    findings.extend(_check_plugin_permissions(config, project_root))

    # PLUGIN-002: Plugin sandboxing
    findings.extend(_check_plugin_sandboxing(config, project_root))

    # PLUGIN-003: Plugin API security
    findings.extend(_check_plugin_api_security(config, project_root))

    # PLUGIN-004: Plugin input/output validation
    findings.extend(_check_plugin_io_validation(config, project_root))

    # PLUGIN-005: Plugin authentication
    findings.extend(_check_plugin_authentication(config, project_root))

    # PLUGIN-006: Plugin authorization
    findings.extend(_check_plugin_authorization(config, project_root))

    # PLUGIN-007: Plugin dependency validation
    findings.extend(_check_plugin_dependencies(config, project_root))

    # PLUGIN-008: Plugin rate limiting
    findings.extend(_check_plugin_rate_limiting(config, project_root))

    logger.info(f"Plugin security checks complete: {len(findings)} findings")
    return findings


def _check_plugin_permissions(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if plugin permission model is defined and enforced."""
    permission_files = [
        "plugin_permissions.json",
        "plugins/permissions.json",
        "config/plugin_permissions.yaml",
        "PLUGIN_PERMISSIONS.md",
    ]

    permission_exists = any((project_root / f).exists() for f in permission_files)

    if not permission_exists:
        return [
            Finding(
                check_id="PLUGIN-001",
                title="Missing Plugin Permission Model",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="Plugin Security",
                description="No plugin permission model found. Plugins may have unrestricted access to system resources.",
                evidence=f"Checked for: {', '.join(permission_files)}",
                remediation="Implement plugin permission model:\n"
                           "1. Define permission levels (read-only, limited, full-access)\n"
                           "2. Require plugins to declare needed permissions\n"
                           "3. Implement least-privilege principle\n"
                           "4. Use allowlists for permitted operations\n"
                           "5. Restrict file system access to specific directories\n"
                           "6. Limit network access to approved endpoints\n"
                           "7. Document permission requirements in plugin manifest",
                owasp_mapping=["LLM07"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="PLUGIN-001",
            title="Plugin Permission Model Defined",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Plugin Security",
            description="Plugin permission model documentation found.",
            evidence="Permission model defined",
            remediation="Regularly review and audit plugin permissions",
            owasp_mapping=["LLM07"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_plugin_sandboxing(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if plugin sandboxing is implemented."""
    # Look for sandboxing implementation
    sandbox_indicators = [
        "sandbox",
        "isolate",
        "container",
        "jail",
        "restrict",
    ]

    plugin_dirs = [
        project_root / "plugins",
        project_root / "src" / "plugins",
        project_root / "app" / "plugins",
    ]

    sandbox_found = False
    evidence = []

    for plugin_dir in plugin_dirs:
        if not plugin_dir.exists():
            continue

        # Check Python files for sandboxing code
        for py_file in plugin_dir.rglob("*.py"):
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")

                # Look for sandboxing patterns
                if any(indicator in content.lower() for indicator in sandbox_indicators):
                    sandbox_found = True
                    evidence.append(str(py_file.relative_to(project_root)))

                # Look for dangerous operations
                dangerous_patterns = [
                    r'\bexec\s*\(',
                    r'\beval\s*\(',
                    r'\b__import__\s*\(',
                    r'\bopen\s*\([^)]*["\']w',  # Write mode
                    r'\bos\.system\s*\(',
                    r'\bsubprocess\.',
                ]

                for pattern in dangerous_patterns:
                    if re.search(pattern, content):
                        return [
                            Finding(
                                check_id="PLUGIN-002",
                                title="Dangerous Operations in Plugin Code",
                                severity=Severity.CRITICAL,
                                status=Status.FAIL,
                                category="Plugin Security",
                                description=f"Plugin code contains dangerous operations without sandboxing: {py_file.relative_to(project_root)}",
                                evidence=f"Found pattern: {pattern}",
                                remediation="Implement plugin sandboxing:\n"
                                           "1. Use RestrictedPython or similar sandboxing library\n"
                                           "2. Run plugins in separate processes/containers\n"
                                           "3. Use seccomp/AppArmor/SELinux for system-level sandboxing\n"
                                           "4. Restrict dangerous built-ins (exec, eval, __import__)\n"
                                           "5. Limit file system and network access\n"
                                           "6. Monitor plugin resource usage\n"
                                           "7. Implement plugin timeout mechanisms",
                                owasp_mapping=["LLM07"],
                                iso_mapping=["Clause_8"],
                            )
                        ]
            except Exception as e:
                logger.warning(f"Error reading plugin file {py_file}: {e}")

    if not sandbox_found:
        return [
            Finding(
                check_id="PLUGIN-002",
                title="Plugin Sandboxing Not Implemented",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="Plugin Security",
                description="No evidence of plugin sandboxing found. Plugins may execute arbitrary code.",
                evidence="No sandboxing indicators found in plugin code",
                remediation="Implement plugin sandboxing:\n"
                           "1. Use RestrictedPython or similar sandboxing library\n"
                           "2. Run plugins in separate processes/containers\n"
                           "3. Use Docker/Kubernetes for plugin isolation\n"
                           "4. Restrict dangerous built-ins and modules\n"
                           "5. Implement resource limits (CPU, memory, disk)\n"
                           "6. Use allowlists for permitted operations",
                owasp_mapping=["LLM07"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="PLUGIN-002",
            title="Plugin Sandboxing Indicators Found",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Plugin Security",
            description=f"Found sandboxing indicators in {len(evidence)} plugin files.",
            evidence=f"Files: {', '.join(evidence[:3])}...",
            remediation="Regularly test sandboxing effectiveness",
            owasp_mapping=["LLM07"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_plugin_api_security(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if plugin API has security controls."""
    api_security_docs = [
        "docs/plugin_api_security.md",
        "PLUGIN_API.md",
        "docs/plugin_development.md",
    ]

    api_docs_exist = any((project_root / f).exists() for f in api_security_docs)

    # Check for API authentication requirements
    env_config = config.environments.get("prod", None)
    plugin_api_auth = getattr(env_config, "plugin_api_auth", False) if env_config else False

    if not plugin_api_auth and not api_docs_exist:
        return [
            Finding(
                check_id="PLUGIN-003",
                title="Plugin API Security Not Configured",
                severity=Severity.HIGH,
                status=Status.FAIL,
                category="Plugin Security",
                description="Plugin API lacks security controls. Plugins may bypass authentication and authorization.",
                evidence="No plugin API authentication configured, no security documentation",
                remediation="Implement plugin API security:\n"
                           "1. Require API authentication for plugin calls\n"
                           "2. Use API keys or OAuth tokens for plugins\n"
                           "3. Implement rate limiting per plugin\n"
                           "4. Validate all plugin API inputs\n"
                           "5. Log all plugin API calls\n"
                           "6. Implement plugin API versioning\n"
                           "7. Document security requirements for plugin developers",
                owasp_mapping=["LLM07", "LLM01"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="PLUGIN-003",
            title="Plugin API Security Configured",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Plugin Security",
            description="Plugin API has security controls or documentation.",
            evidence="API security configured or documented",
            remediation="Regularly audit plugin API security logs",
            owasp_mapping=["LLM07"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_plugin_io_validation(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if plugin input/output validation is implemented."""
    # Look for validation code in plugin infrastructure
    validation_files = [
        "plugins/validator.py",
        "src/plugins/validation.py",
        "plugin_validator.py",
    ]

    validation_exists = any((project_root / f).exists() for f in validation_files)

    if not validation_exists:
        # Check if core plugin system has validation
        plugin_system_files = [
            project_root / "src" / "raicb" / "core" / "plugin.py",
            project_root / "plugins" / "__init__.py",
        ]

        has_validation = False
        for file in plugin_system_files:
            if file.exists():
                content = file.read_text(encoding="utf-8", errors="ignore")
                if "validat" in content.lower() and "input" in content.lower():
                    has_validation = True
                    break

        if not has_validation:
            return [
                Finding(
                    check_id="PLUGIN-004",
                    title="Plugin I/O Validation Not Implemented",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    category="Plugin Security",
                    description="No plugin input/output validation found. Plugins may receive/send malicious data.",
                    evidence=f"Checked for: {', '.join(validation_files)}",
                    remediation="Implement plugin I/O validation:\n"
                               "1. Validate all plugin inputs before processing\n"
                               "2. Sanitize plugin outputs before returning to users\n"
                               "3. Define strict input/output schemas (JSON Schema, Pydantic)\n"
                               "4. Reject invalid inputs early\n"
                               "5. Escape/encode plugin outputs based on context\n"
                               "6. Implement size limits for plugin I/O\n"
                               "7. Log validation failures for security review",
                    owasp_mapping=["LLM07", "LLM02"],
                    iso_mapping=["Clause_8"],
                )
            ]

    return [
        Finding(
            check_id="PLUGIN-004",
            title="Plugin I/O Validation Implemented",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Plugin Security",
            description="Plugin input/output validation found.",
            evidence="Validation code exists",
            remediation="Test validation with malformed inputs",
            owasp_mapping=["LLM07"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_plugin_authentication(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if plugin authentication is required."""
    # Check configuration
    env_configs = config.environments

    plugin_auth_required = False
    for env_name, env_config in env_configs.items():
        if getattr(env_config, "plugin_auth_required", False):
            plugin_auth_required = True
            break

    if not plugin_auth_required:
        severity = Severity.HIGH
        return [
            Finding(
                check_id="PLUGIN-005",
                title="Plugin Authentication Not Required",
                severity=severity,
                status=Status.FAIL,
                category="Plugin Security",
                description="Plugin authentication is not enforced. Unauthorized plugins may be loaded and executed.",
                evidence="plugin_auth_required: false in all environments",
                remediation="Implement plugin authentication:\n"
                           "1. Require plugins to be signed with trusted keys\n"
                           "2. Verify plugin signatures before loading\n"
                           "3. Maintain allowlist of trusted plugin sources\n"
                           "4. Use checksum/hash verification for plugin files\n"
                           "5. Implement plugin marketplace with vetting process\n"
                           "6. Log all plugin load attempts\n"
                           "7. Reject unsigned or unverified plugins",
                owasp_mapping=["LLM07", "LLM03"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="PLUGIN-005",
            title="Plugin Authentication Required",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Plugin Security",
            description="Plugin authentication is enforced.",
            evidence="plugin_auth_required: true",
            remediation="Regularly rotate plugin signing keys",
            owasp_mapping=["LLM07"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_plugin_authorization(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if plugin authorization is implemented."""
    # Check for authorization configuration
    authz_files = [
        "plugin_roles.json",
        "plugin_acl.json",
        "config/plugin_authorization.yaml",
    ]

    authz_exists = any((project_root / f).exists() for f in authz_files)

    if not authz_exists:
        return [
            Finding(
                check_id="PLUGIN-006",
                title="Plugin Authorization Not Configured",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="Plugin Security",
                description="No plugin authorization model found. All authenticated plugins may have full access.",
                evidence=f"Checked for: {', '.join(authz_files)}",
                remediation="Implement plugin authorization:\n"
                           "1. Define roles for plugins (viewer, editor, admin)\n"
                           "2. Implement RBAC or ABAC for plugin actions\n"
                           "3. Restrict sensitive operations to trusted plugins\n"
                           "4. Use principle of least privilege\n"
                           "5. Document plugin capabilities and restrictions\n"
                           "6. Audit plugin authorization decisions",
                owasp_mapping=["LLM07", "LLM08"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="PLUGIN-006",
            title="Plugin Authorization Configured",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Plugin Security",
            description="Plugin authorization model found.",
            evidence="Authorization configuration exists",
            remediation="Regularly review plugin access logs",
            owasp_mapping=["LLM07"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_plugin_dependencies(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if plugin dependencies are validated."""
    # Look for dependency validation
    plugin_dirs = [
        project_root / "plugins",
        project_root / "src" / "plugins",
    ]

    dependency_checks = []

    for plugin_dir in plugin_dirs:
        if not plugin_dir.exists():
            continue

        # Check for requirements files
        for req_file in plugin_dir.rglob("requirements.txt"):
            dependency_checks.append(str(req_file.relative_to(project_root)))

    if not dependency_checks:
        return [
            Finding(
                check_id="PLUGIN-007",
                title="Plugin Dependency Validation Missing",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="Plugin Security",
                description="No plugin dependency validation found. Plugins may introduce vulnerable dependencies.",
                evidence="No plugin dependency management found",
                remediation="Implement plugin dependency validation:\n"
                           "1. Scan plugin dependencies for known vulnerabilities\n"
                           "2. Use dependency pinning for plugins\n"
                           "3. Maintain allowlist of approved dependencies\n"
                           "4. Reject plugins with vulnerable dependencies\n"
                           "5. Regularly update plugin dependencies\n"
                           "6. Use tools like pip-audit, safety, or Snyk",
                owasp_mapping=["LLM07", "LLM03"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="PLUGIN-007",
            title="Plugin Dependency Management Found",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Plugin Security",
            description=f"Found dependency management in {len(dependency_checks)} plugins.",
            evidence=f"Files: {', '.join(dependency_checks[:3])}",
            remediation="Regularly scan plugin dependencies for vulnerabilities",
            owasp_mapping=["LLM07"],
            iso_mapping=["Clause_8"],
        )
    ]


def _check_plugin_rate_limiting(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check if plugin rate limiting is configured."""
    # Check environment configuration
    env_configs = config.environments

    plugin_rate_limiting = False
    for env_name, env_config in env_configs.items():
        if getattr(env_config, "plugin_rate_limiting", False):
            plugin_rate_limiting = True
            break

    if not plugin_rate_limiting:
        return [
            Finding(
                check_id="PLUGIN-008",
                title="Plugin Rate Limiting Not Configured",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                category="Plugin Security",
                description="Plugin rate limiting is not configured. Plugins may cause DoS through excessive API calls.",
                evidence="plugin_rate_limiting: false in all environments",
                remediation="Implement plugin rate limiting:\n"
                           "1. Set rate limits per plugin (requests/minute)\n"
                           "2. Track plugin API call frequency\n"
                           "3. Implement backoff for rate-limited plugins\n"
                           "4. Log rate limit violations\n"
                           "5. Automatically disable abusive plugins\n"
                           "6. Use token bucket or leaky bucket algorithms",
                owasp_mapping=["LLM07", "LLM04"],
                iso_mapping=["Clause_8"],
            )
        ]

    return [
        Finding(
            check_id="PLUGIN-008",
            title="Plugin Rate Limiting Configured",
            severity=Severity.INFO,
            status=Status.PASS,
            category="Plugin Security",
            description="Plugin rate limiting is configured.",
            evidence="plugin_rate_limiting: true",
            remediation="Monitor plugin rate limit violations",
            owasp_mapping=["LLM07"],
            iso_mapping=["Clause_8"],
        )
    ]
