# Responsible AI Compliance Blueprint

A portable, open-source toolkit for self-auditing AI systems against **OWASP AI Security** and **ISO/IEC 42001** concepts.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## ⚠️ Important Disclaimer

**This tool does NOT provide official certification or compliance guarantees.**

It is a best-effort mapping and assessment tool designed to help practitioners:
- Identify security and governance gaps in AI systems
- Map implemented controls to recognized frameworks
- Generate evidence-based audit reports

Always consult with qualified compliance professionals for official certifications.

---

## Features

- **🔍 Comprehensive Checks**: Data integrity, model artifacts, supply chain, PII/privacy, inference security, logging, and governance
- **📊 Framework Mapping**: Maps findings to OWASP AI Security categories and ISO/IEC 42001 themes
- **🖥️ Dual Interface**: CLI (Typer) and Web UI (Streamlit)
- **📝 Multi-Format Reports**: Markdown, HTML, and optional PDF output
- **🎯 Risk Matrix**: Visual risk assessment with likelihood × impact scoring
- **🔐 Privacy-First**: All processing happens locally; no data uploads
- **🐳 Docker Support**: Run as CLI or web server in containers
- **🧩 Pluggable Architecture**: Easy to extend with custom checks

---

## Quick Start

### Installation

Using `pip`:
```bash
pip install -e .
```

Using `pipx` (recommended for CLI tools):
```bash
pipx install .
```

With optional PDF support:
```bash
pip install -e ".[pdf]"
```

For development:
```bash
pip install -e ".[dev]"
pre-commit install  # Optional: set up git hooks
```

### Basic Usage

#### 1. Initialize a New Project

```bash
raicb init
```

This scaffolds a sample project structure with:
- `raicb.yaml` - Main configuration and risk register
- `model_card.yaml` - Model documentation
- `artifacts/` - Model files directory
- `logs/` - Log files directory
- `governance/` - Policy documents

#### 2. Validate Configuration

```bash
raicb validate --config raicb.yaml
```

#### 3. Run Compliance Checks

```bash
raicb run --config raicb.yaml --env prod --out ./reports --format md,html
```

Options:
- `--config`: Path to configuration file (default: `raicb.yaml`)
- `--env`: Environment to check (`dev`, `stage`, `prod`)
- `--out`: Output directory for reports
- `--format`: Report formats (comma-separated: `md`, `html`, `pdf`)

#### 4. View Framework Mappings

```bash
raicb map --config raicb.yaml
```

#### 5. Generate SBOM

```bash
raicb sbom --output sbom.json
```

---

## Streamlit Web UI

Launch the interactive web interface:

```bash
streamlit run app/streamlit_app.py
```

Then open http://localhost:8501 in your browser.

Features:
- Upload or select project configuration
- Interactive checklist tables with filtering
- Visual risk matrix
- One-click report generation
- Download reports in multiple formats

---

## Docker Usage

Build the image:
```bash
docker build -t raicb -f docker/Dockerfile .
```

### Run as CLI
```bash
docker run -v $(pwd)/examples/sample_project:/workspace raicb \
  raicb run --config /workspace/raicb.yaml --out /workspace/reports
```

### Run as Web UI
```bash
docker run -e MODE=ui -p 8501:8501 raicb
```

---

## Configuration

### Main Configuration File (`raicb.yaml`)

```yaml
project:
  name: "My AI System"
  version: "1.0.0"
  owners:
    - name: "AI Team"
      email: "ai-team@example.com"

artifacts:
  model_path: "./artifacts/model.pt"
  model_card: "./model_card.yaml"
  tokenizer: "./artifacts/tokenizer.json"

policies:
  risk_management: "./governance/risk_policy.md"
  incident_response: "./governance/incident_response.md"

threats:
  - id: "THREAT-001"
    title: "Data Poisoning Attack"
    description: "Adversary manipulates training data"
    likelihood: "medium"
    impact: "high"
    controls: ["DATA-HASH", "DATA-PROVENANCE"]

controls:
  - id: "DATA-HASH"
    title: "Dataset Integrity Checks"
    implemented: true
    evidence: "./logs/data_validation.log"

environments:
  prod:
    tls_required: true
    auth_required: true
    rate_limiting: true
```

See `examples/sample_project/raicb.yaml` for a complete example.

---

## Check Categories

### 1. Data Integrity (`data_integrity.py`)
- Dataset hash verification
- Schema consistency validation
- Signed digest checks

### 2. Model Artifacts (`model_artifacts.py`)
- Model card presence and completeness
- Reproducible build hashes
- Secret detection in artifacts
- Serialization safety warnings

### 3. Supply Chain (`supply_chain.py`)
- Dependency SBOM generation
- Known vulnerability scanning (via `pip-audit`)
- License compliance checks
- Model provenance verification

### 4. PII/Privacy (`pii_privacy.py`)
- PII handling configuration review
- Log sampling for PII detection (opt-in)
- Data minimization checks

### 5. Inference Security (`inference_security.py`)
- TLS/auth requirements
- Rate limiting configuration
- Input validation and size bounds
- Prompt injection mitigation checklist

### 6. Logging & Audit (`logging_audit.py`)
- Audit trail presence
- Log rotation policies
- Tamper-evident logging options

### 7. Governance (`governance.py`)
- Policy documentation checks
- Role assignment verification
- Change control evidence
- Model lifecycle tracking

---

## Framework Mappings

### OWASP AI Security
- LLM01: Prompt Injection → Inference Security checks
- LLM02: Insecure Output Handling → Inference Security
- LLM03: Training Data Poisoning → Data Integrity
- LLM04: Model Denial of Service → Inference Security
- LLM05: Supply Chain Vulnerabilities → Supply Chain
- LLM06: Sensitive Information Disclosure → PII/Privacy
- LLM07: Insecure Plugin Design → (extensible)
- LLM08: Excessive Agency → Governance
- LLM09: Overreliance → Model Artifacts (documentation)
- LLM10: Model Theft → Inference Security

### ISO/IEC 42001
- **Clause 4**: Context of Organization → Governance
- **Clause 5**: Leadership → Governance (role assignments)
- **Clause 6**: Planning (Risk Management) → Risk Register + All Checks
- **Clause 7**: Support (Resources, Competence) → Governance
- **Clause 8**: Operation (AI Lifecycle) → Model Artifacts, Logging
- **Clause 9**: Performance Evaluation → Logging & Audit
- **Clause 10**: Improvement → Governance (change control)

*Note: These are high-level thematic mappings, not compliance certifications.*

---

## Extending with Custom Checks

Create a new check module in `src/raicb/checks/`:

```python
# src/raicb/checks/custom_check.py
from typing import List, Dict, Any
from ..config.schema import ProjectConfig

def run_custom_check(config: ProjectConfig, env: str) -> List[Dict[str, Any]]:
    """
    Custom security check.

    Returns:
        List of findings with structure:
        {
            "check_id": "CUSTOM-001",
            "title": "Check Title",
            "severity": "high|medium|low|info",
            "status": "pass|fail|warning",
            "evidence": "Evidence string",
            "remediation": "How to fix this",
            "owasp_mapping": ["LLM01"],
            "iso_mapping": ["Clause 6.1"]
        }
    """
    findings = []

    # Your check logic here
    findings.append({
        "check_id": "CUSTOM-001",
        "title": "My Custom Check",
        "severity": "medium",
        "status": "pass",
        "evidence": "Check passed successfully",
        "remediation": "N/A",
        "owasp_mapping": ["LLM03"],
        "iso_mapping": ["Clause 8.1"]
    })

    return findings
```

Register in `src/raicb/core/evaluator.py`:
```python
from ..checks import custom_check

# Add to check registry
CHECKS.append(custom_check.run_custom_check)
```

---

## Development

### Running Tests

```bash
pytest
```

With coverage:
```bash
pytest --cov=raicb --cov-report=html
```

### Linting and Formatting

```bash
ruff check src/ tests/
black src/ tests/
```

Auto-fix issues:
```bash
ruff check --fix src/ tests/
black src/ tests/
```

### Type Checking

```bash
mypy src/
```

---

## CI/CD

GitHub Actions workflow is provided in `.github/workflows/ci.yml`:
- Runs tests on Python 3.10, 3.11, 3.12
- Checks code formatting with `ruff` and `black`
- Generates coverage reports
- Builds Docker image

---

## Security

This tool is designed to help identify security issues in AI systems. If you discover a security vulnerability in **this toolkit itself**, please report it responsibly:

1. **Do NOT** open a public issue
2. Email: security@example.com (replace with actual contact)
3. Include detailed steps to reproduce
4. Allow 90 days for response before public disclosure

See [SECURITY.md](SECURITY.md) for our security policy.

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-check`)
3. Run tests and ensure they pass
4. Submit a Pull Request

---

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **OWASP AI Security**: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **ISO/IEC 42001**: Information technology — Artificial intelligence — Management system
- **NIST AI RMF**: AI Risk Management Framework

---

## Roadmap

- [ ] Additional checks for federated learning
- [ ] Integration with ML experiment tracking tools
- [ ] SBOM export in CycloneDX format
- [ ] Automated remediation suggestions
- [ ] Integration with CI/CD platforms (GitHub Actions, GitLab CI)
- [ ] REST API for programmatic access
- [ ] Plugin marketplace for community checks

---

## FAQ

**Q: Does this tool certify my AI system for ISO/IEC 42001?**
A: No. This tool provides a best-effort mapping to help you prepare for audits. Official certification requires accredited auditors.

**Q: Will this upload my model or data anywhere?**
A: No. All processing is local. No data leaves your machine.

**Q: Can I use this in CI/CD pipelines?**
A: Yes! Use the CLI in your build scripts. Exit codes indicate pass/fail status.

**Q: How do I add custom checks?**
A: See the "Extending with Custom Checks" section above.

**Q: What Python versions are supported?**
A: Python 3.10, 3.11, and 3.12.

---

**Built with ❤️ for responsible AI development**
