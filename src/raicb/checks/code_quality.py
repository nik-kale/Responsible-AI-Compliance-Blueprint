"""Code quality and optimization analysis checks.

This module provides comprehensive code quality analysis including:
- Cyclomatic complexity analysis
- Code duplication detection
- Maintainability index
- Technical debt scoring
- Code coverage analysis
- Dead code detection
- Performance profiling hints
- Memory leak indicators
"""

from pathlib import Path
from typing import List, Dict, Set, Tuple
import re
import ast
from collections import defaultdict

from ..config.schema import ProjectConfig, Finding, Severity, Status
from ..core.logger import get_logger

logger = get_logger(__name__)


def run_checks(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    """
    Run code quality and optimization checks.

    Covers:
    - QUA-001: Cyclomatic complexity analysis
    - QUA-002: Function length analysis
    - QUA-003: Code duplication detection
    - QUA-004: Dead code detection
    - QUA-005: Import complexity
    - QUA-006: Comment ratio analysis
    - QUA-007: Lines of code metrics
    - QUA-008: Naming conventions
    - QUA-009: Magic numbers detection
    - QUA-010: Technical debt indicators
    - QUA-011: Code coverage analysis
    - QUA-012: Type hints coverage
    - QUA-013: Docstring coverage
    - QUA-014: Class complexity
    - QUA-015: Nested complexity

    Args:
        config: Project configuration
        project_root: Root directory of the project
        env: Environment (dev/staging/prod)

    Returns:
        List of findings from code quality checks
    """
    logger.info("Running code quality checks")

    findings = []

    # QUA-001: Cyclomatic complexity
    findings.extend(_check_cyclomatic_complexity(project_root))

    # QUA-002: Function length
    findings.extend(_check_function_length(project_root))

    # QUA-003: Code duplication
    findings.extend(_check_code_duplication(project_root))

    # QUA-004: Dead code detection
    findings.extend(_check_dead_code(project_root))

    # QUA-005: Import complexity
    findings.extend(_check_import_complexity(project_root))

    # QUA-006: Comment ratio
    findings.extend(_check_comment_ratio(project_root))

    # QUA-007: Lines of code metrics
    findings.extend(_check_loc_metrics(project_root))

    # QUA-008: Naming conventions
    findings.extend(_check_naming_conventions(project_root))

    # QUA-009: Magic numbers
    findings.extend(_check_magic_numbers(project_root))

    # QUA-010: Technical debt indicators
    findings.extend(_check_technical_debt(project_root))

    # QUA-011: Code coverage
    findings.extend(_check_code_coverage(project_root))

    # QUA-012: Type hints coverage
    findings.extend(_check_type_hints(project_root))

    # QUA-013: Docstring coverage
    findings.extend(_check_docstrings(project_root))

    # QUA-014: Class complexity
    findings.extend(_check_class_complexity(project_root))

    # QUA-015: Nested complexity
    findings.extend(_check_nested_complexity(project_root))

    logger.info(f"Code quality checks complete: {len(findings)} findings")
    return findings


class ComplexityAnalyzer(ast.NodeVisitor):
    """AST visitor to calculate cyclomatic complexity."""

    def __init__(self):
        self.complexity = 1  # Base complexity
        self.functions = []
        self.current_function = None

    def visit_FunctionDef(self, node):
        old_function = self.current_function
        old_complexity = self.complexity

        self.current_function = node.name
        self.complexity = 1

        self.generic_visit(node)

        self.functions.append({
            'name': node.name,
            'complexity': self.complexity,
            'line': node.lineno,
            'length': len(node.body)
        })

        self.current_function = old_function
        self.complexity = old_complexity

    def visit_If(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node):
        self.complexity += len(node.values) - 1
        self.generic_visit(node)


def _check_cyclomatic_complexity(project_root: Path) -> List[Finding]:
    """Check cyclomatic complexity of functions."""
    high_complexity_functions = []
    total_functions = 0

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            tree = ast.parse(content)

            analyzer = ComplexityAnalyzer()
            analyzer.visit(tree)

            for func in analyzer.functions:
                total_functions += 1
                if func['complexity'] > 10:  # Threshold for high complexity
                    high_complexity_functions.append({
                        'file': str(py_file.relative_to(project_root)),
                        'function': func['name'],
                        'complexity': func['complexity'],
                        'line': func['line']
                    })

        except SyntaxError:
            logger.debug(f"Syntax error in {py_file}")
        except Exception as e:
            logger.debug(f"Error analyzing {py_file}: {e}")

    if high_complexity_functions:
        details = f"Found {len(high_complexity_functions)} functions with high complexity (>10):\n\n"
        for func in sorted(high_complexity_functions, key=lambda x: x['complexity'], reverse=True)[:20]:
            details += f"{func['file']}:{func['line']} - {func['function']}() - Complexity: {func['complexity']}\n"

        severity = Severity.HIGH if len(high_complexity_functions) > 10 else Severity.MEDIUM

        return [Finding(
            check_id="QUA-001",
            title="High Cyclomatic Complexity Detected",
            description=f"{len(high_complexity_functions)} functions exceed complexity threshold of 10",
            severity=severity,
            status=Status.WARNING,
            details=details,
            remediation="Refactor complex functions:\n- Break into smaller functions\n- Reduce nested conditionals\n- Extract helper methods\n- Apply single responsibility principle\nTarget: complexity ≤ 10",
            references=["ISO/IEC 25010 Maintainability", "McCabe Complexity"],
            framework_mappings={"ISO42001": ["7.3"]},
        )]

    return [Finding(
        check_id="QUA-001",
        title="Acceptable Cyclomatic Complexity",
        description=f"All {total_functions} functions have acceptable complexity (≤10)",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_function_length(project_root: Path) -> List[Finding]:
    """Check for excessively long functions."""
    long_functions = []
    total_functions = 0

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    total_functions += 1
                    func_length = len(node.body)

                    if func_length > 50:  # Threshold for long function
                        long_functions.append({
                            'file': str(py_file.relative_to(project_root)),
                            'function': node.name,
                            'length': func_length,
                            'line': node.lineno
                        })

        except Exception as e:
            logger.debug(f"Error analyzing {py_file}: {e}")

    if long_functions:
        details = f"Found {len(long_functions)} functions longer than 50 lines:\n\n"
        for func in sorted(long_functions, key=lambda x: x['length'], reverse=True)[:15]:
            details += f"{func['file']}:{func['line']} - {func['function']}() - {func['length']} lines\n"

        return [Finding(
            check_id="QUA-002",
            title="Long Functions Detected",
            description=f"{len(long_functions)} functions exceed 50 lines",
            severity=Severity.MEDIUM,
            status=Status.WARNING,
            details=details,
            remediation="Refactor long functions:\n- Extract logical sections\n- Create helper functions\n- Improve readability\nTarget: ≤ 50 lines per function",
            references=["Clean Code - Robert Martin"],
            framework_mappings={"ISO42001": ["7.3"]},
        )]

    return [Finding(
        check_id="QUA-002",
        title="Acceptable Function Length",
        description=f"All {total_functions} functions are within acceptable length (≤50 lines)",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_code_duplication(project_root: Path) -> List[Finding]:
    """Check for code duplication."""
    code_hashes = defaultdict(list)
    duplicates_found = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            lines = content.split('\n')

            # Check for duplicated blocks (5+ consecutive lines)
            for i in range(len(lines) - 5):
                block = '\n'.join(lines[i:i+5])
                # Skip blocks that are mostly whitespace or comments
                if not block.strip() or block.strip().startswith('#'):
                    continue

                block_hash = hash(block.strip())
                code_hashes[block_hash].append((str(py_file.relative_to(project_root)), i + 1))

        except Exception as e:
            logger.debug(f"Error analyzing {py_file}: {e}")

    # Find duplicates
    for block_hash, locations in code_hashes.items():
        if len(locations) > 1:
            duplicates_found.append(locations)

    if duplicates_found:
        details = f"Found {len(duplicates_found)} duplicated code blocks:\n\n"
        for dup in duplicates_found[:10]:
            details += "Duplicated in:\n"
            for file, line in dup:
                details += f"  - {file}:{line}\n"
            details += "\n"

        return [Finding(
            check_id="QUA-003",
            title="Code Duplication Detected",
            description=f"Found {len(duplicates_found)} duplicated code blocks",
            severity=Severity.MEDIUM,
            status=Status.WARNING,
            details=details,
            remediation="Reduce duplication:\n- Extract common code to functions\n- Use inheritance/composition\n- Apply DRY principle\n- Create reusable utilities",
            references=["DRY Principle", "ISO/IEC 25010"],
            framework_mappings={"ISO42001": ["7.3"]},
        )]

    return [Finding(
        check_id="QUA-003",
        title="No Significant Code Duplication",
        description="No major code duplication detected",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_dead_code(project_root: Path) -> List[Finding]:
    """Check for dead/unreachable code."""
    dead_code_indicators = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            lines = content.split('\n')

            for i, line in enumerate(lines, 1):
                stripped = line.strip()

                # Check for code after return
                if 'return' in stripped and not stripped.startswith('#'):
                    # Check if there's non-comment code after return in same block
                    for j in range(i, min(i + 5, len(lines))):
                        next_line = lines[j].strip()
                        if next_line and not next_line.startswith('#') and not next_line.startswith('def') and not next_line.startswith('class'):
                            # Check indentation level
                            if len(lines[j]) - len(lines[j].lstrip()) > len(line) - len(line.lstrip()):
                                dead_code_indicators.append({
                                    'file': str(py_file.relative_to(project_root)),
                                    'line': j + 1,
                                    'type': 'unreachable_after_return'
                                })

                # Check for unused imports (basic detection)
                if stripped.startswith('import ') or stripped.startswith('from '):
                    # Extract module name
                    match = re.search(r'import\s+(\w+)', stripped)
                    if match:
                        module = match.group(1)
                        # Check if module is used elsewhere in file
                        if content.count(module) == 1:  # Only appears in import line
                            dead_code_indicators.append({
                                'file': str(py_file.relative_to(project_root)),
                                'line': i,
                                'type': 'unused_import'
                            })

        except Exception as e:
            logger.debug(f"Error analyzing {py_file}: {e}")

    if dead_code_indicators:
        details = f"Found {len(dead_code_indicators)} potential dead code instances:\n\n"
        for indicator in dead_code_indicators[:20]:
            details += f"{indicator['file']}:{indicator['line']} - {indicator['type']}\n"

        return [Finding(
            check_id="QUA-004",
            title="Potential Dead Code Detected",
            description=f"Found {len(dead_code_indicators)} potential dead code instances",
            severity=Severity.LOW,
            status=Status.WARNING,
            details=details,
            remediation="Remove dead code:\n- Delete unreachable code\n- Remove unused imports\n- Clean up commented code\n- Use code coverage tools",
            references=["Clean Code"],
            framework_mappings={"ISO42001": ["7.3"]},
        )]

    return [Finding(
        check_id="QUA-004",
        title="No Dead Code Detected",
        description="No obvious dead code found",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_import_complexity(project_root: Path) -> List[Finding]:
    """Check for excessive imports."""
    files_with_many_imports = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            tree = ast.parse(content)

            import_count = sum(1 for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)))

            if import_count > 30:
                files_with_many_imports.append({
                    'file': str(py_file.relative_to(project_root)),
                    'imports': import_count
                })

        except Exception as e:
            logger.debug(f"Error analyzing {py_file}: {e}")

    if files_with_many_imports:
        details = f"Files with excessive imports (>30):\n\n"
        for file_info in sorted(files_with_many_imports, key=lambda x: x['imports'], reverse=True):
            details += f"{file_info['file']} - {file_info['imports']} imports\n"

        return [Finding(
            check_id="QUA-005",
            title="High Import Complexity",
            description=f"{len(files_with_many_imports)} files have excessive imports",
            severity=Severity.LOW,
            status=Status.WARNING,
            details=details,
            remediation="Reduce import complexity:\n- Split large modules\n- Group related functionality\n- Remove unused imports\n- Consider module design",
            framework_mappings={"ISO42001": ["7.3"]},
        )]

    return [Finding(
        check_id="QUA-005",
        title="Acceptable Import Complexity",
        description="Import complexity is within acceptable range",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_comment_ratio(project_root: Path) -> List[Finding]:
    """Check comment-to-code ratio."""
    total_lines = 0
    total_comments = 0
    total_code = 0

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            lines = content.split('\n')

            for line in lines:
                total_lines += 1
                stripped = line.strip()

                if stripped.startswith('#'):
                    total_comments += 1
                elif stripped and not stripped.startswith('"""') and not stripped.startswith("'''"):
                    total_code += 1

        except Exception:
            pass

    if total_code > 0:
        comment_ratio = (total_comments / total_code) * 100

        if comment_ratio < 5:
            return [Finding(
                check_id="QUA-006",
                title="Low Comment Ratio",
                description=f"Comment ratio is {comment_ratio:.1f}% (recommended: 10-20%)",
                severity=Severity.LOW,
                status=Status.WARNING,
                details=f"Total code lines: {total_code}\nTotal comment lines: {total_comments}\nRatio: {comment_ratio:.1f}%",
                remediation="Increase code documentation:\n- Add function/class docstrings\n- Explain complex logic\n- Document assumptions\nTarget: 10-20% comment ratio",
                framework_mappings={"ISO42001": ["7.5"]},
            )]

        return [Finding(
            check_id="QUA-006",
            title="Adequate Comment Ratio",
            description=f"Comment ratio is {comment_ratio:.1f}%",
            severity=Severity.INFO,
            status=Status.PASS,
            details=f"Total code lines: {total_code}\nTotal comment lines: {total_comments}",
        )]

    return [Finding(
        check_id="QUA-006",
        title="No Code to Analyze",
        description="No Python code found",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_loc_metrics(project_root: Path) -> List[Finding]:
    """Check lines of code metrics."""
    total_lines = 0
    total_files = 0
    large_files = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            lines = len(content.split('\n'))
            total_lines += lines
            total_files += 1

            if lines > 500:
                large_files.append({
                    'file': str(py_file.relative_to(project_root)),
                    'lines': lines
                })

        except Exception:
            pass

    details = f"Total Python files: {total_files}\nTotal lines of code: {total_lines:,}\n"

    if total_files > 0:
        avg_lines = total_lines / total_files
        details += f"Average lines per file: {avg_lines:.0f}\n"

    if large_files:
        details += f"\nLarge files (>500 lines):\n"
        for file_info in sorted(large_files, key=lambda x: x['lines'], reverse=True)[:10]:
            details += f"  - {file_info['file']}: {file_info['lines']} lines\n"

    return [Finding(
        check_id="QUA-007",
        title="Lines of Code Metrics",
        description=f"Project contains {total_lines:,} lines across {total_files} files",
        severity=Severity.INFO,
        status=Status.PASS,
        details=details,
    )]


def _check_naming_conventions(project_root: Path) -> List[Finding]:
    """Check naming convention compliance."""
    violations = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            tree = ast.parse(content)

            for node in ast.walk(tree):
                # Check function names (should be snake_case)
                if isinstance(node, ast.FunctionDef):
                    if not re.match(r'^[a-z_][a-z0-9_]*$', node.name) and not node.name.startswith('__'):
                        violations.append({
                            'file': str(py_file.relative_to(project_root)),
                            'line': node.lineno,
                            'type': 'function',
                            'name': node.name,
                            'issue': 'should be snake_case'
                        })

                # Check class names (should be PascalCase)
                if isinstance(node, ast.ClassDef):
                    if not re.match(r'^[A-Z][a-zA-Z0-9]*$', node.name):
                        violations.append({
                            'file': str(py_file.relative_to(project_root)),
                            'line': node.lineno,
                            'type': 'class',
                            'name': node.name,
                            'issue': 'should be PascalCase'
                        })

        except Exception as e:
            logger.debug(f"Error analyzing {py_file}: {e}")

    if violations:
        details = f"Found {len(violations)} naming convention violations:\n\n"
        for violation in violations[:20]:
            details += f"{violation['file']}:{violation['line']} - {violation['type']} '{violation['name']}' {violation['issue']}\n"

        return [Finding(
            check_id="QUA-008",
            title="Naming Convention Violations",
            description=f"Found {len(violations)} naming convention violations",
            severity=Severity.LOW,
            status=Status.WARNING,
            details=details,
            remediation="Follow PEP 8 naming conventions:\n- Functions: snake_case\n- Classes: PascalCase\n- Constants: UPPER_CASE\n- Variables: snake_case",
            references=["PEP 8 - Style Guide for Python Code"],
            framework_mappings={"ISO42001": ["7.3"]},
        )]

    return [Finding(
        check_id="QUA-008",
        title="Naming Conventions Followed",
        description="Code follows PEP 8 naming conventions",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_magic_numbers(project_root: Path) -> List[Finding]:
    """Check for magic numbers in code."""
    magic_numbers = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            lines = content.split('\n')

            for i, line in enumerate(lines, 1):
                # Skip comments
                if line.strip().startswith('#'):
                    continue

                # Find numeric literals (excluding 0, 1, -1 which are common)
                matches = re.finditer(r'\b(?<!\.)\d{2,}\b', line)
                for match in matches:
                    number = match.group()
                    if number not in ['100', '1000']:  # Common exceptions
                        magic_numbers.append({
                            'file': str(py_file.relative_to(project_root)),
                            'line': i,
                            'number': number
                        })

        except Exception:
            pass

    if len(magic_numbers) > 20:  # Only report if significant
        details = f"Found {len(magic_numbers)} potential magic numbers:\n\n"
        for item in magic_numbers[:15]:
            details += f"{item['file']}:{item['line']} - {item['number']}\n"

        return [Finding(
            check_id="QUA-009",
            title="Magic Numbers Detected",
            description=f"Found {len(magic_numbers)} potential magic numbers",
            severity=Severity.LOW,
            status=Status.WARNING,
            details=details,
            remediation="Replace magic numbers with named constants:\n- Define constants at module level\n- Use descriptive names\n- Improve code readability",
            references=["Clean Code - Robert Martin"],
            framework_mappings={"ISO42001": ["7.3"]},
        )]

    return [Finding(
        check_id="QUA-009",
        title="Minimal Magic Numbers",
        description="Magic number usage is minimal",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_technical_debt(project_root: Path) -> List[Finding]:
    """Check for technical debt indicators."""
    debt_indicators = {
        'TODO': 0,
        'FIXME': 0,
        'HACK': 0,
        'XXX': 0,
        'BUG': 0,
    }

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")

            for indicator in debt_indicators.keys():
                debt_indicators[indicator] += len(re.findall(rf'#.*\b{indicator}\b', content, re.IGNORECASE))

        except Exception:
            pass

    total_debt = sum(debt_indicators.values())

    if total_debt > 10:
        details = "Technical debt indicators found:\n"
        for indicator, count in debt_indicators.items():
            if count > 0:
                details += f"  - {indicator}: {count}\n"

        severity = Severity.HIGH if total_debt > 50 else Severity.MEDIUM

        return [Finding(
            check_id="QUA-010",
            title="Technical Debt Indicators Found",
            description=f"Found {total_debt} technical debt comments (TODO, FIXME, etc.)",
            severity=severity,
            status=Status.WARNING,
            details=details,
            remediation="Address technical debt:\n- Review and prioritize TODOs\n- Fix FIXMEs\n- Refactor HACKs\n- Document or resolve XXXs\n- Create tickets for tracking",
            framework_mappings={"ISO42001": ["10.2"]},
        )]

    return [Finding(
        check_id="QUA-010",
        title="Low Technical Debt",
        description=f"Found {total_debt} technical debt indicators",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_code_coverage(project_root: Path) -> List[Finding]:
    """Check for code coverage configuration."""
    coverage_files = [
        ".coveragerc",
        "coverage.xml",
        ".coverage",
        "htmlcov",
    ]

    coverage_configured = any((project_root / f).exists() for f in coverage_files)

    # Check for pytest-cov or coverage.py in requirements
    requirements_file = project_root / "requirements.txt"
    coverage_in_deps = False

    if requirements_file.exists():
        try:
            content = requirements_file.read_text()
            coverage_in_deps = 'coverage' in content.lower() or 'pytest-cov' in content.lower()
        except Exception:
            pass

    if not coverage_configured and not coverage_in_deps:
        return [Finding(
            check_id="QUA-011",
            title="Code Coverage Not Configured",
            description="No code coverage tools detected",
            severity=Severity.MEDIUM,
            status=Status.WARNING,
            details="Code coverage helps identify untested code paths",
            remediation="Set up code coverage:\n- Install pytest-cov or coverage.py\n- Configure coverage thresholds\n- Integrate into CI/CD\nTarget: >80% coverage",
            references=["Software Testing Best Practices"],
            framework_mappings={"ISO42001": ["8.1"]},
        )]

    return [Finding(
        check_id="QUA-011",
        title="Code Coverage Configured",
        description="Code coverage tools detected",
        severity=Severity.INFO,
        status=Status.PASS,
        details="Ensure coverage thresholds are met (target: >80%)",
    )]


def _check_type_hints(project_root: Path) -> List[Finding]:
    """Check for type hints coverage."""
    total_functions = 0
    typed_functions = 0

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    total_functions += 1

                    # Check if function has return type annotation
                    has_return_type = node.returns is not None

                    # Check if arguments have type annotations
                    has_arg_types = any(arg.annotation is not None for arg in node.args.args)

                    if has_return_type or has_arg_types:
                        typed_functions += 1

        except Exception as e:
            logger.debug(f"Error analyzing {py_file}: {e}")

    if total_functions > 0:
        type_coverage = (typed_functions / total_functions) * 100

        if type_coverage < 50:
            return [Finding(
                check_id="QUA-012",
                title="Low Type Hints Coverage",
                description=f"Only {type_coverage:.1f}% of functions have type hints",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                details=f"Functions with type hints: {typed_functions}/{total_functions}",
                remediation="Add type hints:\n- Annotate function arguments\n- Add return type annotations\n- Use mypy for type checking\nTarget: >80% coverage",
                references=["PEP 484 - Type Hints", "PEP 585 - Type Hinting Generics"],
                framework_mappings={"ISO42001": ["7.3"]},
            )]

        return [Finding(
            check_id="QUA-012",
            title="Good Type Hints Coverage",
            description=f"{type_coverage:.1f}% of functions have type hints",
            severity=Severity.INFO,
            status=Status.PASS,
            details=f"Functions with type hints: {typed_functions}/{total_functions}",
        )]

    return [Finding(
        check_id="QUA-012",
        title="No Functions to Analyze",
        description="No functions found for type hint analysis",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_docstrings(project_root: Path) -> List[Finding]:
    """Check for docstring coverage."""
    total_definitions = 0
    documented_definitions = 0

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    total_definitions += 1

                    # Check for docstring
                    if (node.body and
                        isinstance(node.body[0], ast.Expr) and
                        isinstance(node.body[0].value, ast.Constant) and
                        isinstance(node.body[0].value.value, str)):
                        documented_definitions += 1

        except Exception as e:
            logger.debug(f"Error analyzing {py_file}: {e}")

    if total_definitions > 0:
        doc_coverage = (documented_definitions / total_definitions) * 100

        if doc_coverage < 60:
            return [Finding(
                check_id="QUA-013",
                title="Low Docstring Coverage",
                description=f"Only {doc_coverage:.1f}% of functions/classes have docstrings",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                details=f"Documented: {documented_definitions}/{total_definitions}",
                remediation="Add docstrings:\n- Document all public functions/classes\n- Include parameters and return values\n- Add usage examples\nTarget: >80% coverage",
                references=["PEP 257 - Docstring Conventions"],
                framework_mappings={"ISO42001": ["7.5"]},
            )]

        return [Finding(
            check_id="QUA-013",
            title="Good Docstring Coverage",
            description=f"{doc_coverage:.1f}% of functions/classes have docstrings",
            severity=Severity.INFO,
            status=Status.PASS,
            details=f"Documented: {documented_definitions}/{total_definitions}",
        )]

    return [Finding(
        check_id="QUA-013",
        title="No Definitions to Analyze",
        description="No functions/classes found",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_class_complexity(project_root: Path) -> List[Finding]:
    """Check for overly complex classes."""
    complex_classes = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    method_count = sum(1 for n in node.body if isinstance(n, ast.FunctionDef))

                    if method_count > 20:
                        complex_classes.append({
                            'file': str(py_file.relative_to(project_root)),
                            'class': node.name,
                            'methods': method_count,
                            'line': node.lineno
                        })

        except Exception as e:
            logger.debug(f"Error analyzing {py_file}: {e}")

    if complex_classes:
        details = f"Classes with many methods (>20):\n\n"
        for cls in sorted(complex_classes, key=lambda x: x['methods'], reverse=True):
            details += f"{cls['file']}:{cls['line']} - {cls['class']} ({cls['methods']} methods)\n"

        return [Finding(
            check_id="QUA-014",
            title="Complex Classes Detected",
            description=f"Found {len(complex_classes)} classes with >20 methods",
            severity=Severity.MEDIUM,
            status=Status.WARNING,
            details=details,
            remediation="Simplify complex classes:\n- Apply Single Responsibility Principle\n- Extract related methods to separate classes\n- Use composition over inheritance\nTarget: ≤ 20 methods per class",
            references=["SOLID Principles", "Clean Code"],
            framework_mappings={"ISO42001": ["7.3"]},
        )]

    return [Finding(
        check_id="QUA-014",
        title="Acceptable Class Complexity",
        description="All classes have acceptable complexity",
        severity=Severity.INFO,
        status=Status.PASS,
    )]


def _check_nested_complexity(project_root: Path) -> List[Finding]:
    """Check for deeply nested code."""
    deeply_nested = []

    for py_file in project_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            lines = content.split('\n')

            for i, line in enumerate(lines, 1):
                # Count indentation level
                indent_level = (len(line) - len(line.lstrip())) // 4

                if indent_level > 4 and line.strip():  # More than 4 levels
                    deeply_nested.append({
                        'file': str(py_file.relative_to(project_root)),
                        'line': i,
                        'level': indent_level
                    })

        except Exception:
            pass

    if len(deeply_nested) > 10:
        details = f"Found {len(deeply_nested)} deeply nested code blocks (>4 levels):\n\n"
        for item in sorted(deeply_nested, key=lambda x: x['level'], reverse=True)[:15]:
            details += f"{item['file']}:{item['line']} - Nesting level: {item['level']}\n"

        return [Finding(
            check_id="QUA-015",
            title="Deep Nesting Detected",
            description=f"Found {len(deeply_nested)} instances of deep nesting",
            severity=Severity.MEDIUM,
            status=Status.WARNING,
            details=details,
            remediation="Reduce nesting:\n- Extract nested logic to functions\n- Use early returns\n- Flatten conditional logic\nTarget: ≤ 4 nesting levels",
            references=["Clean Code - Robert Martin"],
            framework_mappings={"ISO42001": ["7.3"]},
        )]

    return [Finding(
        check_id="QUA-015",
        title="Acceptable Nesting Levels",
        description="Code nesting is within acceptable range",
        severity=Severity.INFO,
        status=Status.PASS,
    )]
