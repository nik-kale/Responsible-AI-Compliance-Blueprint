"""Advanced security and vulnerability scanning checks.

This module provides enterprise-grade security scanning including:
- Secrets detection (API keys, tokens, credentials)
- Cryptographic best practices validation
- AI-specific vulnerability detection
- CVE database integration for ML libraries
- Code security analysis
- Authentication/authorization validation
"""

from pathlib import Path
from typing import List, Dict, Set
import re
import json
import hashlib
import subprocess

from ..config.schema import ProjectConfig, Finding, Severity, Status
from ..core.logger import get_logger

logger = get_logger(__name__)

# Patterns for secrets detection
SECRETS_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "GitHub OAuth": r"gho_[0-9a-zA-Z]{36}",
    "Generic API Key": r"(?i)(api[_-]?key|apikey)[\s]*[=:]+[\s]*['\"]?[0-9a-zA-Z]{20,}['\"]?",
    "Generic Secret": r"(?i)(secret|password|passwd|pwd)[\s]*[=:]+[\s]*['\"]?[0-9a-zA-Z!@#$%^&*()_+=-]{8,}['\"]?",
    "Private Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Azure Client Secret": r"(?i)azure(.{0,20})?['\"][0-9a-zA-Z]{32,}['\"]",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Stripe API Key": r"(?i)sk_live_[0-9a-zA-Z]{24,}",
    "OpenAI API Key": r"sk-[a-zA-Z0-9]{48}",
    "Anthropic API Key": r"sk-ant-[a-zA-Z0-9-]{95}",
}

# AI/ML libraries with known CVEs
VULNERABLE_ML_LIBRARIES = {
    "tensorflow": {
        "2.10.0": ["CVE-2022-35934", "CVE-2022-35935"],
        "2.9.0": ["CVE-2022-29216", "CVE-2022-29207"],
        "2.8.0": ["CVE-2022-23592", "CVE-2022-21725"],
    },
    "torch": {
        "1.12.0": ["CVE-2022-45907"],
        "1.11.0": ["CVE-2022-45198"],
    },
    "transformers": {
        "4.20.0": ["Arbitrary code execution via pickled models"],
        "4.18.0": ["Model deserialization vulnerability"],
    },
    "scikit-learn": {
        "1.0.2": ["CVE-2022-29221"],
    },
}

# AI-specific vulnerability patterns
AI_VULNERABILITY_PATTERNS = {
    "prompt_injection": [
        r"(?i)(ignore\s+(previous|above)\s+instructions?)",
        r"(?i)(system\s*:\s*you\s+are)",
        r"(?i)(forget\s+your\s+instructions?)",
        r"(?i)(disregard\s+your\s+programming)",
    ],
    "adversarial_input": [
        r"(?i)(adversarial|perturbation|epsilon|pgd|fgsm)",
        r"(?i)(foolbox|cleverhans|art\.attacks)",
    ],
    "model_extraction": [
        r"(?i)(model\.extract|steal.*model|copy.*weights)",
        r"(?i)(query.*excessive|scrape.*api)",
    ],
    "data_poisoning": [
        r"(?i)(poison|backdoor|trigger.*pattern)",
        r"(?i)(malicious.*sample|corrupt.*training)",
    ],
    "model_inversion": [
        r"(?i)(model\.invert|membership.*inference)",
        r"(?i)(privacy.*attack|extract.*training.*data)",
    ],
}

# Weak cryptographic algorithms
WEAK_CRYPTO_PATTERNS = {
    "MD5": r"(?i)(hashlib\.md5|md5\(|Md5)",
    "SHA1": r"(?i)(hashlib\.sha1|sha1\(|Sha1)",
    "DES": r"(?i)(des\.new|DES\(|triple.*des)",
    "RC4": r"(?i)(arc4|rc4)",
    "ECB Mode": r"(?i)(mode.*ecb|MODE_ECB)",
}


def run_checks(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """
    Run advanced security and vulnerability checks.

    Covers:
    - SEC-001: Secrets detection (API keys, tokens, credentials)
    - SEC-002: Private key detection
    - SEC-003: Weak cryptographic algorithms
    - SEC-004: TLS/SSL configuration
    - SEC-005: AI-specific vulnerabilities (prompt injection, adversarial)
    - SEC-006: CVE scanning for ML libraries
    - SEC-007: Input sanitization validation
    - SEC-008: Authentication security
    - SEC-009: SQL injection patterns
    - SEC-010: XSS vulnerability patterns
    - SEC-011: Command injection patterns
    - SEC-012: Path traversal vulnerabilities
    - SEC-013: Hardcoded credentials
    - SEC-014: Insecure deserialization
    - SEC-015: CORS misconfiguration

    Args:
        config: Project configuration
        project_root: Root directory of the project
        env: Environment (dev/staging/prod)

    Returns:
        List of findings from advanced security checks
    """
    logger.info("Running advanced security checks")

    findings = []

    # SEC-001: Secrets detection
    findings.extend(_check_secrets_exposure(project_root))

    # SEC-002: Private key detection
    findings.extend(_check_private_keys(project_root))

    # SEC-003: Weak cryptographic algorithms
    findings.extend(_check_weak_crypto(project_root))

    # SEC-004: TLS/SSL configuration
    findings.extend(_check_tls_config(config, project_root))

    # SEC-005: AI-specific vulnerabilities
    findings.extend(_check_ai_vulnerabilities(project_root))

    # SEC-006: CVE scanning for ML libraries
    findings.extend(_check_ml_library_cves(project_root))

    # SEC-007: Input sanitization
    findings.extend(_check_input_sanitization(project_root))

    # SEC-008: Authentication security
    findings.extend(_check_authentication_security(config, project_root))

    # SEC-009: SQL injection patterns
    findings.extend(_check_sql_injection_patterns(project_root))

    # SEC-010: XSS vulnerability patterns
    findings.extend(_check_xss_patterns(project_root))

    # SEC-011: Command injection patterns
    findings.extend(_check_command_injection(project_root))

    # SEC-012: Path traversal vulnerabilities
    findings.extend(_check_path_traversal(project_root))

    # SEC-013: Hardcoded credentials
    findings.extend(_check_hardcoded_credentials(project_root))

    # SEC-014: Insecure deserialization
    findings.extend(_check_insecure_deserialization(project_root))

    # SEC-015: CORS misconfiguration
    findings.extend(_check_cors_config(project_root))

    logger.info(f"Advanced security checks complete: {len(findings)} findings")
    return findings


def _check_secrets_exposure(project_root: Path) -> List[Finding]:
    """Check for exposed secrets (API keys, tokens, etc.)."""
    findings = []
    secrets_found = {}

    # Files to scan
    extensions = [".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".yaml", ".yml", ".json", ".txt", ".sh"]

    # Skip certain directories
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", "build", "dist"}

    for file_path in project_root.rglob("*"):
        if file_path.is_file() and file_path.suffix in extensions:
            # Skip if in excluded directory
            if any(skip_dir in file_path.parts for skip_dir in skip_dirs):
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")

                for secret_type, pattern in SECRETS_PATTERNS.items():
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        # Skip if it's a comment or example
                        line_start = content.rfind('\n', 0, match.start()) + 1
                        line = content[line_start:content.find('\n', match.start())]

                        if any(skip in line.lower() for skip in ["example", "sample", "todo", "placeholder", "xxx"]):
                            continue

                        if secret_type not in secrets_found:
                            secrets_found[secret_type] = []
                        secrets_found[secret_type].append(str(file_path.relative_to(project_root)))

            except Exception as e:
                logger.debug(f"Error scanning {file_path}: {e}")

    if secrets_found:
        details = "Potential secrets detected:\n"
        for secret_type, files in secrets_found.items():
            details += f"\n{secret_type}:\n"
            for file in set(files):
                details += f"  - {file}\n"

        findings.append(Finding(
            check_id="SEC-001",
            title="Secrets Exposure Detected",
            description=f"Found {len(secrets_found)} types of potential secrets in code",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            details=details,
            remediation="Remove hardcoded secrets immediately. Use environment variables, secret managers (AWS Secrets Manager, HashiCorp Vault), or encrypted configuration.",
            references=["OWASP A02:2021 - Cryptographic Failures", "CWE-798: Use of Hard-coded Credentials"],
            framework_mappings={
                "OWASP": ["A02:2021"],
                "CWE": ["CWE-798"],
                "ISO42001": ["8.1"],
            },
        ))
    else:
        findings.append(Finding(
            check_id="SEC-001",
            title="No Secrets Detected",
            description="No hardcoded secrets found in scanned files",
            severity=Severity.INFO,
            status=Status.PASS,
            details="Scanned code for common secret patterns (API keys, tokens, credentials)",
        ))

    return findings


def _check_private_keys(project_root: Path) -> List[Finding]:
    """Check for exposed private keys."""
    private_key_files = []

    for file_path in project_root.rglob("*"):
        if file_path.is_file():
            try:
                # Check by file extension
                if file_path.suffix in [".pem", ".key", ".p12", ".pfx", ".pkcs12"]:
                    private_key_files.append(str(file_path.relative_to(project_root)))
                    continue

                # Check by content
                if file_path.suffix in [".txt", ".crt", ""]:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    if "BEGIN PRIVATE KEY" in content or "BEGIN RSA PRIVATE KEY" in content:
                        private_key_files.append(str(file_path.relative_to(project_root)))

            except Exception as e:
                logger.debug(f"Error scanning {file_path}: {e}")

    if private_key_files:
        return [Finding(
            check_id="SEC-002",
            title="Private Keys Detected",
            description=f"Found {len(private_key_files)} private key files in repository",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            details=f"Private keys found:\n" + "\n".join(f"  - {f}" for f in private_key_files),
            remediation="Remove private keys from repository. Add to .gitignore. Rotate compromised keys. Use secret management systems.",
            references=["OWASP A02:2021", "CWE-321: Use of Hard-coded Cryptographic Key"],
            framework_mappings={"OWASP": ["A02:2021"], "CWE": ["CWE-321"]},
        )]

    return [Finding(
        check_id="SEC-002",
        title="No Private Keys Detected",
        description="No private key files found in repository",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_weak_crypto(project_root: Path) -> List[Finding]:
    """Check for weak cryptographic algorithms."""
    weak_crypto_found = {}

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")

            for algo, pattern in WEAK_CRYPTO_PATTERNS.items():
                if re.search(pattern, content):
                    if algo not in weak_crypto_found:
                        weak_crypto_found[algo] = []
                    weak_crypto_found[algo].append(str(py_file.relative_to(project_root)))

        except Exception as e:
            logger.debug(f"Error scanning {py_file}: {e}")

    if weak_crypto_found:
        details = "Weak cryptographic algorithms detected:\n"
        for algo, files in weak_crypto_found.items():
            details += f"\n{algo}:\n"
            for file in set(files):
                details += f"  - {file}\n"

        return [Finding(
            check_id="SEC-003",
            title="Weak Cryptographic Algorithms",
            description=f"Found usage of {len(weak_crypto_found)} weak cryptographic algorithms",
            severity=Severity.HIGH,
            status=Status.FAIL,
            details=details,
            remediation="Replace weak algorithms:\n- MD5/SHA1 → SHA256/SHA3\n- DES/3DES → AES-256\n- RC4 → ChaCha20\n- ECB mode → GCM/CBC mode",
            references=["OWASP A02:2021", "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"],
            framework_mappings={"OWASP": ["A02:2021"], "CWE": ["CWE-327"]},
        )]

    return [Finding(
        check_id="SEC-003",
        title="Strong Cryptography",
        description="No weak cryptographic algorithms detected",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_tls_config(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check TLS/SSL configuration."""
    tls_config_files = [
        "nginx.conf",
        "apache2.conf",
        "ssl.conf",
        "tls.conf",
        ".ssl",
    ]

    tls_configured = any((project_root / f).exists() for f in tls_config_files)

    # Check for TLS in code
    tls_in_code = False
    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            if any(pattern in content.lower() for pattern in ["ssl", "tls", "https", "certifi"]):
                tls_in_code = True
                break
        except Exception:
            pass

    if not tls_configured and not tls_in_code:
        return [Finding(
            check_id="SEC-004",
            title="TLS/SSL Configuration Missing",
            description="No TLS/SSL configuration detected",
            severity=Severity.HIGH,
            status=Status.FAIL,
            details="Production systems should enforce TLS 1.2+ for all communications",
            remediation="Configure TLS 1.2+ with strong cipher suites. Disable SSLv3, TLS 1.0, TLS 1.1.",
            references=["OWASP A02:2021", "CWE-319: Cleartext Transmission"],
            framework_mappings={"OWASP": ["A02:2021"], "CWE": ["CWE-319"]},
        )]

    return [Finding(
        check_id="SEC-004",
        title="TLS/SSL Configuration Found",
        description="TLS/SSL configuration detected in project",
        severity=Severity.INFO,
        status=Status.PASS,
        details="Verify TLS 1.2+ is enforced with strong cipher suites",
    )]


def _check_ai_vulnerabilities(project_root: Path) -> List[Finding]:
    """Check for AI-specific vulnerabilities."""
    findings = []
    vulnerabilities_found = {}

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")

            for vuln_type, patterns in AI_VULNERABILITY_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content):
                        if vuln_type not in vulnerabilities_found:
                            vulnerabilities_found[vuln_type] = []
                        vulnerabilities_found[vuln_type].append(str(py_file.relative_to(project_root)))
                        break

        except Exception as e:
            logger.debug(f"Error scanning {py_file}: {e}")

    if vulnerabilities_found:
        details = "AI-specific vulnerability patterns detected:\n"
        for vuln_type, files in vulnerabilities_found.items():
            details += f"\n{vuln_type}:\n"
            for file in set(files):
                details += f"  - {file}\n"

        findings.append(Finding(
            check_id="SEC-005",
            title="AI-Specific Vulnerabilities Detected",
            description=f"Found {len(vulnerabilities_found)} types of AI vulnerability patterns",
            severity=Severity.HIGH,
            status=Status.WARNING,
            details=details,
            remediation="Review and validate:\n- Prompt injection defenses\n- Adversarial robustness testing\n- Model extraction protection\n- Data poisoning detection\n- Model inversion safeguards",
            references=["OWASP LLM01-LLM10", "NIST AI RMF"],
            framework_mappings={"OWASP_LLM": ["LLM01", "LLM03", "LLM10"], "ISO42001": ["8.1"]},
        ))
    else:
        findings.append(Finding(
            check_id="SEC-005",
            title="No AI Vulnerability Patterns Detected",
            description="No obvious AI-specific vulnerability patterns found",
            severity=Severity.INFO,
            status=Status.PASS,
            details="Consider implementing: prompt filtering, adversarial testing, rate limiting",
        ))

    return findings


def _check_ml_library_cves(project_root: Path) -> List[Finding]:
    """Check for known CVEs in ML libraries."""
    findings = []

    # Check requirements.txt
    requirements_file = project_root / "requirements.txt"
    if not requirements_file.exists():
        return [Finding(
            check_id="SEC-006",
            title="No requirements.txt Found",
            description="Cannot scan for ML library CVEs without requirements.txt",
            severity=Severity.LOW,
            status=Status.WARNING,
            details="Create requirements.txt to enable CVE scanning",
        )]

    try:
        content = requirements_file.read_text()
        vulnerable_libraries = {}

        for lib, versions in VULNERABLE_ML_LIBRARIES.items():
            if lib in content.lower():
                # Extract version if specified
                match = re.search(rf"{lib}[>=<]*(\d+\.\d+\.\d+)", content, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    if version in versions:
                        vulnerable_libraries[lib] = {
                            "version": version,
                            "cves": versions[version]
                        }
                else:
                    vulnerable_libraries[lib] = {
                        "version": "unknown",
                        "cves": ["Version not pinned - cannot determine CVEs"]
                    }

        if vulnerable_libraries:
            details = "Vulnerable ML libraries detected:\n"
            for lib, info in vulnerable_libraries.items():
                details += f"\n{lib} {info['version']}:\n"
                for cve in info['cves']:
                    details += f"  - {cve}\n"

            findings.append(Finding(
                check_id="SEC-006",
                title="Vulnerable ML Libraries Detected",
                description=f"Found {len(vulnerable_libraries)} ML libraries with known CVEs",
                severity=Severity.HIGH,
                status=Status.FAIL,
                details=details,
                remediation="Update vulnerable libraries to latest patched versions. Run 'pip-audit' or 'safety check' regularly.",
                references=["CVE Database", "GitHub Security Advisories"],
                framework_mappings={"OWASP": ["A06:2021"], "ISO42001": ["8.2"]},
            ))
        else:
            findings.append(Finding(
                check_id="SEC-006",
                title="No Known CVEs in ML Libraries",
                description="ML libraries appear up-to-date (limited CVE database)",
                severity=Severity.INFO,
                status=Status.PASS,
                details="Consider using pip-audit or safety for comprehensive CVE scanning",
            ))

    except Exception as e:
        logger.error(f"Error scanning requirements.txt: {e}")
        findings.append(Finding(
            check_id="SEC-006",
            title="Error Scanning Dependencies",
            description=f"Could not scan requirements.txt: {e}",
            severity=Severity.LOW,
            status=Status.WARNING,
        ))

    return findings


def _check_input_sanitization(project_root: Path) -> List[Finding]:
    """Check for input sanitization patterns."""
    sanitization_patterns = [
        r"bleach\.clean",
        r"html\.escape",
        r"re\.escape",
        r"sanitize",
        r"validate_input",
        r"clean_input",
        r"filter_input",
    ]

    sanitization_found = False
    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            if any(re.search(pattern, content) for pattern in sanitization_patterns):
                sanitization_found = True
                break
        except Exception:
            pass

    if not sanitization_found:
        return [Finding(
            check_id="SEC-007",
            title="Input Sanitization Not Detected",
            description="No obvious input sanitization patterns found",
            severity=Severity.MEDIUM,
            status=Status.WARNING,
            details="User input should be validated and sanitized",
            remediation="Implement input validation:\n- Whitelist allowed characters\n- Escape HTML/SQL/shell metacharacters\n- Validate data types and ranges\n- Use parameterized queries",
            references=["OWASP A03:2021", "CWE-20: Improper Input Validation"],
            framework_mappings={"OWASP": ["A03:2021"], "CWE": ["CWE-20"]},
        )]

    return [Finding(
        check_id="SEC-007",
        title="Input Sanitization Detected",
        description="Input sanitization patterns found in code",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_authentication_security(config: ProjectConfig, project_root: Path) -> List[Finding]:
    """Check for secure authentication practices."""
    auth_patterns = [
        "jwt",
        "oauth",
        "openid",
        "saml",
        "passport",
        "authenticate",
        "authorization",
    ]

    auth_found = False
    weak_auth_patterns = [
        r"password\s*==",
        r"auth\s*==\s*['\"]",
        r"if.*user.*==",
    ]

    weak_auth_found = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")

            if any(pattern in content.lower() for pattern in auth_patterns):
                auth_found = True

            for pattern in weak_auth_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    weak_auth_found.append(str(py_file.relative_to(project_root)))

        except Exception:
            pass

    if weak_auth_found:
        return [Finding(
            check_id="SEC-008",
            title="Weak Authentication Patterns",
            description=f"Potential weak authentication in {len(set(weak_auth_found))} files",
            severity=Severity.HIGH,
            status=Status.FAIL,
            details="Files with potential issues:\n" + "\n".join(f"  - {f}" for f in set(weak_auth_found)),
            remediation="Use secure authentication:\n- bcrypt/argon2 for passwords\n- JWT/OAuth for APIs\n- Multi-factor authentication\n- Session management",
            references=["OWASP A07:2021", "CWE-287: Improper Authentication"],
            framework_mappings={"OWASP": ["A07:2021"], "CWE": ["CWE-287"]},
        )]

    if not auth_found:
        return [Finding(
            check_id="SEC-008",
            title="No Authentication System Detected",
            description="No authentication system found",
            severity=Severity.LOW,
            status=Status.WARNING,
            details="If authentication is required, implement secure auth",
        )]

    return [Finding(
        check_id="SEC-008",
        title="Authentication System Detected",
        description="Authentication system found in project",
        severity=Severity.INFO,
        status=Status.PASS,
        details="Verify: strong password policies, MFA, secure session management",
    )]


def _check_sql_injection_patterns(project_root: Path) -> List[Finding]:
    """Check for SQL injection vulnerabilities."""
    sql_injection_patterns = [
        r"execute\(['\"].*%s.*['\"].*%",
        r"\.format\(.*\).*execute",
        r"f['\"].*SELECT.*{.*}.*['\"]",
        r"\+.*WHERE",
    ]

    vulnerable_files = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")

            for pattern in sql_injection_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    vulnerable_files.append(str(py_file.relative_to(project_root)))
                    break

        except Exception:
            pass

    if vulnerable_files:
        return [Finding(
            check_id="SEC-009",
            title="Potential SQL Injection Vulnerabilities",
            description=f"Found potential SQL injection patterns in {len(vulnerable_files)} files",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            details="Files with potential SQL injection:\n" + "\n".join(f"  - {f}" for f in vulnerable_files),
            remediation="Use parameterized queries:\n- SQLAlchemy ORM\n- Prepared statements\n- Never concatenate user input into SQL",
            references=["OWASP A03:2021", "CWE-89: SQL Injection"],
            framework_mappings={"OWASP": ["A03:2021"], "CWE": ["CWE-89"]},
        )]

    return [Finding(
        check_id="SEC-009",
        title="No SQL Injection Patterns Detected",
        description="No obvious SQL injection vulnerabilities found",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_xss_patterns(project_root: Path) -> List[Finding]:
    """Check for XSS vulnerability patterns."""
    xss_patterns = [
        r"innerHTML\s*=",
        r"\.html\(",
        r"render_template_string\(",
        r"safe\s*=\s*True",
    ]

    vulnerable_files = []

    for file_path in project_root.rglob("*"):
        if file_path.suffix in [".py", ".js", ".jsx", ".tsx", ".html"]:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")

                for pattern in xss_patterns:
                    if re.search(pattern, content):
                        vulnerable_files.append(str(file_path.relative_to(project_root)))
                        break

            except Exception:
                pass

    if vulnerable_files:
        return [Finding(
            check_id="SEC-010",
            title="Potential XSS Vulnerabilities",
            description=f"Found potential XSS patterns in {len(vulnerable_files)} files",
            severity=Severity.HIGH,
            status=Status.FAIL,
            details="Files with potential XSS:\n" + "\n".join(f"  - {f}" for f in vulnerable_files),
            remediation="Prevent XSS:\n- Escape all user input\n- Use Content Security Policy\n- Avoid innerHTML, use textContent\n- Validate and sanitize",
            references=["OWASP A03:2021", "CWE-79: Cross-site Scripting"],
            framework_mappings={"OWASP": ["A03:2021"], "CWE": ["CWE-79"]},
        )]

    return [Finding(
        check_id="SEC-010",
        title="No XSS Patterns Detected",
        description="No obvious XSS vulnerabilities found",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_command_injection(project_root: Path) -> List[Finding]:
    """Check for command injection vulnerabilities."""
    command_injection_patterns = [
        r"os\.system\(",
        r"subprocess\.(call|run|Popen).*shell\s*=\s*True",
        r"eval\(",
        r"exec\(",
    ]

    vulnerable_files = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")

            for pattern in command_injection_patterns:
                if re.search(pattern, content):
                    vulnerable_files.append(str(py_file.relative_to(project_root)))
                    break

        except Exception:
            pass

    if vulnerable_files:
        return [Finding(
            check_id="SEC-011",
            title="Potential Command Injection Vulnerabilities",
            description=f"Found potential command injection in {len(vulnerable_files)} files",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            details="Files with potential command injection:\n" + "\n".join(f"  - {f}" for f in vulnerable_files),
            remediation="Avoid command injection:\n- Use subprocess with shell=False\n- Validate and whitelist commands\n- Avoid eval() and exec()\n- Use safe alternatives",
            references=["OWASP A03:2021", "CWE-78: OS Command Injection"],
            framework_mappings={"OWASP": ["A03:2021"], "CWE": ["CWE-78"]},
        )]

    return [Finding(
        check_id="SEC-011",
        title="No Command Injection Patterns Detected",
        description="No obvious command injection vulnerabilities found",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_path_traversal(project_root: Path) -> List[Finding]:
    """Check for path traversal vulnerabilities."""
    path_traversal_patterns = [
        r"open\(.*\+",
        r"Path\(.*\+",
        r"os\.path\.join\(.*request",
        r"\.\.\/",
    ]

    vulnerable_files = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")

            for pattern in path_traversal_patterns:
                if re.search(pattern, content):
                    vulnerable_files.append(str(py_file.relative_to(project_root)))
                    break

        except Exception:
            pass

    if vulnerable_files:
        return [Finding(
            check_id="SEC-012",
            title="Potential Path Traversal Vulnerabilities",
            description=f"Found potential path traversal in {len(vulnerable_files)} files",
            severity=Severity.HIGH,
            status=Status.FAIL,
            details="Files with potential path traversal:\n" + "\n".join(f"  - {f}" for f in vulnerable_files),
            remediation="Prevent path traversal:\n- Validate file paths\n- Use absolute paths\n- Whitelist allowed directories\n- Reject '../' patterns",
            references=["OWASP A01:2021", "CWE-22: Path Traversal"],
            framework_mappings={"OWASP": ["A01:2021"], "CWE": ["CWE-22"]},
        )]

    return [Finding(
        check_id="SEC-012",
        title="No Path Traversal Patterns Detected",
        description="No obvious path traversal vulnerabilities found",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_hardcoded_credentials(project_root: Path) -> List[Finding]:
    """Check for hardcoded credentials."""
    credential_patterns = [
        r"password\s*=\s*['\"][^'\"]{3,}['\"]",
        r"passwd\s*=\s*['\"][^'\"]{3,}['\"]",
        r"pwd\s*=\s*['\"][^'\"]{3,}['\"]",
        r"secret\s*=\s*['\"][^'\"]{8,}['\"]",
        r"token\s*=\s*['\"][^'\"]{8,}['\"]",
    ]

    files_with_credentials = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")

            for pattern in credential_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Skip if looks like example/placeholder
                    matched_text = match.group(0).lower()
                    if any(skip in matched_text for skip in ["example", "your_", "changeme", "xxx", "***"]):
                        continue

                    files_with_credentials.append(str(py_file.relative_to(project_root)))
                    break

        except Exception:
            pass

    if files_with_credentials:
        return [Finding(
            check_id="SEC-013",
            title="Hardcoded Credentials Detected",
            description=f"Found hardcoded credentials in {len(files_with_credentials)} files",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            details="Files with hardcoded credentials:\n" + "\n".join(f"  - {f}" for f in files_with_credentials),
            remediation="Remove hardcoded credentials:\n- Use environment variables\n- Use secret management (Vault, AWS Secrets)\n- Use configuration files (gitignored)\n- Rotate exposed credentials",
            references=["OWASP A07:2021", "CWE-798: Hard-coded Credentials"],
            framework_mappings={"OWASP": ["A07:2021"], "CWE": ["CWE-798"]},
        )]

    return [Finding(
        check_id="SEC-013",
        title="No Hardcoded Credentials Detected",
        description="No hardcoded credentials found",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_insecure_deserialization(project_root: Path) -> List[Finding]:
    """Check for insecure deserialization."""
    deserialization_patterns = [
        r"pickle\.loads?\(",
        r"yaml\.load\(",
        r"jsonpickle",
        r"marshal\.loads?\(",
    ]

    vulnerable_files = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")

            for pattern in deserialization_patterns:
                if re.search(pattern, content):
                    vulnerable_files.append(str(py_file.relative_to(project_root)))
                    break

        except Exception:
            pass

    if vulnerable_files:
        return [Finding(
            check_id="SEC-014",
            title="Potential Insecure Deserialization",
            description=f"Found insecure deserialization in {len(vulnerable_files)} files",
            severity=Severity.HIGH,
            status=Status.WARNING,
            details="Files using potentially unsafe deserialization:\n" + "\n".join(f"  - {f}" for f in vulnerable_files),
            remediation="Secure deserialization:\n- Use yaml.safe_load() instead of yaml.load()\n- Avoid pickle for untrusted data\n- Validate deserialized data\n- Use JSON when possible",
            references=["OWASP A08:2021", "CWE-502: Deserialization of Untrusted Data"],
            framework_mappings={"OWASP": ["A08:2021"], "CWE": ["CWE-502"]},
        )]

    return [Finding(
        check_id="SEC-014",
        title="No Insecure Deserialization Detected",
        description="No insecure deserialization patterns found",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_cors_config(project_root: Path) -> List[Finding]:
    """Check for CORS misconfiguration."""
    permissive_cors_patterns = [
        r"Access-Control-Allow-Origin.*\*",
        r"CORS.*origins.*\[\s*['\"]?\*['\"]?\s*\]",
        r"cors\(.*origin.*=.*True",
    ]

    misconfigured_files = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")

            for pattern in permissive_cors_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    misconfigured_files.append(str(py_file.relative_to(project_root)))
                    break

        except Exception:
            pass

    if misconfigured_files:
        return [Finding(
            check_id="SEC-015",
            title="CORS Misconfiguration Detected",
            description=f"Found permissive CORS in {len(misconfigured_files)} files",
            severity=Severity.MEDIUM,
            status=Status.WARNING,
            details="Files with permissive CORS:\n" + "\n".join(f"  - {f}" for f in misconfigured_files),
            remediation="Configure CORS properly:\n- Whitelist specific origins\n- Avoid Access-Control-Allow-Origin: *\n- Use credentials carefully\n- Validate Origin header",
            references=["OWASP A05:2021", "CWE-942: Permissive CORS Policy"],
            framework_mappings={"OWASP": ["A05:2021"], "CWE": ["CWE-942"]},
        )]

    return [Finding(
        check_id="SEC-015",
        title="No CORS Misconfiguration Detected",
        description="No permissive CORS configuration found",
        severity=Severity.INFO,
        status=Status.PASS,
    )]
