"""Utility functions for compliance checking."""

import hashlib
import re
from pathlib import Path
from typing import Dict, List, Optional, Set


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
    from typing import Any

    if not file_path.exists():
        return {"error": f"File not found: {file_path}"}

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
        (r"password\s*=\s*['\"].*['\"]", "Hardcoded password"),
        (r"api[_-]?key\s*=\s*['\"].*['\"]", "Hardcoded API key"),
        (r"secret\s*=\s*['\"].*['\"]", "Hardcoded secret"),
        (r"token\s*=\s*['\"].*['\"]", "Hardcoded token"),
        (r"pickle\.load", "Unsafe pickle deserialization"),
        (r"eval\(", "Dangerous eval usage"),
        (r"exec\(", "Dangerous exec usage"),
    ]

    findings = []

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
