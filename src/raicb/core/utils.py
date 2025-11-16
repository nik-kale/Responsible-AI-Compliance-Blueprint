"""Utility functions for compliance checking."""

import hashlib
import re
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from .logger import get_logger

# Security limits
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB max file size for reading
MAX_LINE_LENGTH = 10000  # Max characters per line to prevent memory issues

logger = get_logger(__name__)


def safe_check(func: Callable) -> Callable:
    """
    Decorator to safely execute check functions with error handling.

    Catches exceptions and converts them to ERROR findings instead of crashing.

    Args:
        func: Check function to wrap

    Returns:
        Wrapped function that handles errors gracefully
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e}", exc_info=True)

            # Import here to avoid circular imports
            from ..config.schema import Finding, Severity, Status

            return [
                Finding(
                    check_id=f"ERROR-{func.__module__}.{func.__name__}",
                    title=f"Check Error: {func.__name__}",
                    severity=Severity.HIGH,
                    status=Status.ERROR,
                    category="system",
                    description=f"Error executing check function: {func.__name__}",
                    evidence=f"Exception: {type(e).__name__}: {str(e)}",
                    remediation="Check logs for details. This may indicate a bug or configuration issue.",
                    owasp_mapping=[],
                    iso_mapping=[],
                )
            ]

    return wrapper


def compute_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """
    Compute cryptographic hash of a file.

    Args:
        file_path: Path to file
        algorithm: Hash algorithm (sha256, sha512, etc.)

    Returns:
        Hex digest of file hash

    Raises:
        FileNotFoundError: If file doesn't exist
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    hash_func = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)

    return hash_func.hexdigest()


def verify_file_hash(file_path: Path, expected_hash: str, algorithm: str = "sha256") -> bool:
    """
    Verify file hash matches expected value.

    Args:
        file_path: Path to file
        expected_hash: Expected hash value
        algorithm: Hash algorithm

    Returns:
        True if hash matches, False otherwise
    """
    try:
        actual_hash = compute_file_hash(file_path, algorithm)
        return actual_hash.lower() == expected_hash.lower()
    except Exception:
        return False


def scan_for_pii(
    text: str,
    patterns: Optional[List[str]] = None,
    redact: bool = False,
) -> Dict[str, List[str]]:
    """
    Scan text for potential PII using regex patterns.

    Args:
        text: Text to scan
        patterns: List of regex patterns (uses defaults if None)
        redact: If True, return redacted matches

    Returns:
        Dictionary mapping pattern type to list of matches
    """
    if patterns is None:
        patterns = [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"\b\d{16}\b",  # Credit card (naive)
            r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",  # Phone number
        ]

    results: Dict[str, List[str]] = {
        "emails": [],
        "ssns": [],
        "credit_cards": [],
        "phone_numbers": [],
    }

    pattern_names = ["emails", "ssns", "credit_cards", "phone_numbers"]

    for i, pattern in enumerate(patterns[:4]):  # Limit to known patterns
        matches = re.findall(pattern, text)
        if matches:
            if redact:
                results[pattern_names[i]] = ["[REDACTED]"] * len(matches)
            else:
                results[pattern_names[i]] = matches

    return results


def scan_file_for_pii(
    file_path: Path,
    max_lines: int = 100,
    patterns: Optional[List[str]] = None,
    redact: bool = True,
) -> Dict[str, Any]:
    """
    Scan a file for PII (sampling approach).

    Args:
        file_path: Path to file
        max_lines: Maximum lines to scan
        patterns: PII patterns
        redact: Whether to redact findings

    Returns:
        Dictionary with findings
    """
    if not file_path.exists():
        return {"error": f"File not found: {file_path}"}

    # Check file size to prevent DoS
    file_size = file_path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        return {
            "error": f"File too large: {file_size} bytes (max: {MAX_FILE_SIZE})",
            "file": str(file_path),
            "file_size": file_size,
        }

    findings: Dict[str, Any] = {
        "file": str(file_path),
        "lines_scanned": 0,
        "pii_found": False,
        "details": {},
    }

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = []
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                # Also limit individual line length
                if len(line) > MAX_LINE_LENGTH:
                    line = line[:MAX_LINE_LENGTH] + "...[truncated]"
                lines.append(line)

            findings["lines_scanned"] = len(lines)
            text = "\n".join(lines)
            pii_results = scan_for_pii(text, patterns, redact)

            # Check if any PII found
            for category, matches in pii_results.items():
                if matches:
                    findings["pii_found"] = True
                    findings["details"][category] = len(matches)

    except Exception as e:
        findings["error"] = str(e)

    return findings


def get_project_root(start_path: Optional[Path] = None) -> Path:
    """
    Find project root by looking for raicb.yaml.

    Args:
        start_path: Starting directory (uses cwd if None)

    Returns:
        Project root path

    Raises:
        FileNotFoundError: If raicb.yaml not found
    """
    current = start_path or Path.cwd()

    # Search up to 5 levels
    for _ in range(5):
        if (current / "raicb.yaml").exists():
            return current
        if current.parent == current:  # Reached filesystem root
            break
        current = current.parent

    raise FileNotFoundError("Could not find raicb.yaml in current directory or parents")


def load_checksums(checksums_file: Path) -> Dict[str, str]:
    """
    Load checksums from file.

    Expected format:
        <hash> <filename>

    Args:
        checksums_file: Path to checksums file

    Returns:
        Dictionary mapping filename to hash
    """
    checksums = {}

    if not checksums_file.exists():
        return checksums

    with open(checksums_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(None, 1)
            if len(parts) == 2:
                hash_value, filename = parts
                checksums[filename] = hash_value

    return checksums


def check_dangerous_patterns(file_path: Path) -> List[Dict[str, str]]:
    """
    Check for dangerous patterns in code/config files.

    Args:
        file_path: File to check

    Returns:
        List of findings
    """
    dangerous_patterns = [
        # Match secrets with or without quotes, but not in comments
        (r"^\s*[^#]*password\s*[:=]\s*['\"]?[^\s'\"#]+['\"]?", "Hardcoded password"),
        (r"^\s*[^#]*api[_-]?key\s*[:=]\s*['\"]?[^\s'\"#]+['\"]?", "Hardcoded API key"),
        (r"^\s*[^#]*secret\s*[:=]\s*['\"]?[^\s'\"#]+['\"]?", "Hardcoded secret"),
        (r"^\s*[^#]*token\s*[:=]\s*['\"]?[^\s'\"#]+['\"]?", "Hardcoded token"),
        # Specific secret patterns
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"(?:r|s)k_live_[0-9a-zA-Z]{24,}", "Stripe API Key"),
        (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
        (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token"),
        # Unsafe operations (not in comments)
        (r"^\s*[^#]*pickle\.load", "Unsafe pickle deserialization"),
        (r"^\s*[^#]*\beval\s*\(", "Dangerous eval usage"),
        (r"^\s*[^#]*\bexec\s*\(", "Dangerous exec usage"),
        (r"^\s*[^#]*shell\s*=\s*True", "Unsafe shell=True in subprocess"),
    ]

    findings = []

    # Check file size to prevent DoS
    try:
        file_size = file_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            findings.append({
                "error": f"File too large: {file_size} bytes",
                "file": str(file_path),
            })
            return findings
    except Exception as e:
        findings.append({"error": str(e), "file": str(file_path)})
        return findings

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

            for pattern, description in dangerous_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Find line number
                    line_num = content[: match.start()].count("\n") + 1
                    findings.append(
                        {
                            "pattern": description,
                            "line": line_num,
                            "file": str(file_path),
                        }
                    )

    except Exception as e:
        findings.append({"error": str(e), "file": str(file_path)})

    return findings


def validate_yaml_structure(data: dict, required_keys: Set[str]) -> List[str]:
    """
    Validate that YAML data contains required keys.

    Args:
        data: Parsed YAML data
        required_keys: Set of required keys

    Returns:
        List of missing keys
    """
    missing = []
    for key in required_keys:
        if key not in data:
            missing.append(key)
    return missing


def sanitize_for_display(text: str, max_length: int = 100) -> str:
    """
    Sanitize text for display in reports.

    Args:
        text: Text to sanitize
        max_length: Maximum length

    Returns:
        Sanitized text
    """
    # Remove control characters
    text = "".join(char for char in text if ord(char) >= 32 or char in "\n\t")

    # Truncate if too long
    if len(text) > max_length:
        text = text[:max_length] + "..."

    return text
