# Contributing to Responsible AI Compliance Blueprint

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

Please be respectful and constructive in all interactions. We are committed to providing a welcoming and inclusive environment.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce**
- **Expected vs actual behavior**
- **Environment** (OS, Python version, etc.)
- **Error messages and logs**

### Suggesting Enhancements

Enhancement suggestions are welcome! Please provide:

- **Clear use case** - explain why this would be useful
- **Proposed solution** - if you have ideas on implementation
- **Alternatives considered**

### Pull Requests

1. **Fork the repository** and create a feature branch
   ```bash
   git checkout -b feature/amazing-feature
   ```

2. **Make your changes** following our coding standards

3. **Add tests** for new functionality

4. **Update documentation** if needed

5. **Run tests and linting**
   ```bash
   pytest
   ruff check src/ tests/
   black src/ tests/
   ```

6. **Commit with clear messages**
   ```bash
   git commit -m "Add amazing feature"
   ```

7. **Push to your fork**
   ```bash
   git push origin feature/amazing-feature
   ```

8. **Open a Pull Request** with a clear description

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/responsible-ai-compliance-blueprint.git
   cd responsible-ai-compliance-blueprint
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

4. Install pre-commit hooks (optional):
   ```bash
   pre-commit install
   ```

## Coding Standards

### Python Style
- Follow **PEP 8** guidelines
- Use **type hints** where applicable
- Maximum line length: **100 characters**
- Use **black** for formatting
- Use **ruff** for linting

### Documentation
- Add **docstrings** to all public functions and classes
- Use **Google-style** docstrings
- Update **README.md** for user-facing changes
- Add **inline comments** for complex logic

### Testing
- Write **pytest** tests for new features
- Maintain **>80% code coverage**
- Include both **unit and integration** tests
- Test edge cases and error conditions

## Project Structure

```
src/raicb/
  ├── checks/          # Security check modules
  ├── config/          # Configuration schemas
  ├── core/            # Core functionality
  └── cli.py           # CLI entrypoint

app/
  ├── components/      # Streamlit UI components
  └── streamlit_app.py # Main Streamlit app

tests/               # Test suite
templates/           # Jinja2 report templates
examples/            # Sample projects
```

## Adding New Checks

To add a new compliance check:

1. Create a new module in `src/raicb/checks/`
2. Implement `run_checks()` function that returns `List[Finding]`
3. Update `src/raicb/core/mapping.py` with framework mappings
4. Add tests in `tests/test_checks.py`
5. Update documentation

Example:
```python
# src/raicb/checks/my_check.py

def run_checks(config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
    findings = []

    # Your check logic here
    findings.append(
        Finding(
            check_id="MYCHECK-001",
            title="My Check",
            severity=Severity.MEDIUM,
            status=Status.PASS,
            category="my_category",
            description="Check description",
            evidence="Evidence",
            remediation="How to fix",
            owasp_mapping=["LLM01"],
            iso_mapping=["Clause_8"],
        )
    )

    return findings
```

## Adding Framework Mappings

Update `src/raicb/core/mapping.py`:

```python
CHECK_TO_OWASP = {
    "my_category": ["LLM01", "LLM03"],
}

CHECK_TO_ISO = {
    "my_category": ["Clause_8", "Clause_6.1"],
}
```

## Release Process

1. Update version in `src/raicb/__init__.py` and `pyproject.toml`
2. Update `CHANGELOG.md`
3. Create a git tag: `git tag v0.x.0`
4. Push tag: `git push origin v0.x.0`
5. GitHub Actions will build and publish

## Questions?

- Open an issue for questions
- Check existing documentation
- Review example projects in `examples/`

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
