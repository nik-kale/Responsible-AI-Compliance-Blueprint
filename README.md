# Responsible AI Compliance Blueprint

> **Version 5.0** - Enterprise-Grade AI Compliance Toolkit with 144 Checks, Advanced Security Scanning, Code Quality Analysis, and Complete ISO/IEC 42001 Coverage

A portable, open-source toolkit for self-auditing AI systems against **OWASP AI Security Top 10**, **ISO/IEC 42001**, and **CWE** standards.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-5.0.0-green.svg)](CHANGELOG.md)
[![Checks](https://img.shields.io/badge/checks-144-blue.svg)](CHANGELOG.md)

---

## ✨ What's New in Version 5.0

### 🔐 Advanced Security & Vulnerability Detection (15 NEW Checks)
- **Secrets Detection** - Scan for API keys, tokens, credentials (AWS, GitHub, OpenAI, Anthropic, Stripe, etc.)
- **AI-Specific Vulnerabilities** - Prompt injection, adversarial inputs, model extraction, data poisoning patterns
- **CVE Scanning** - Built-in vulnerability database for TensorFlow, PyTorch, Transformers, scikit-learn
- **OWASP Top 10 Coverage** - SQL injection, XSS, command injection, path traversal detection
- **Cryptography Validation** - Detect weak algorithms (MD5, SHA1, DES, RC4), TLS/SSL misconfiguration
- **CWE Mappings** - 12+ Common Weakness Enumerations for standardized vulnerability reporting

### 💎 Code Quality & Optimization Analysis (15 NEW Checks)
- **Cyclomatic Complexity** - AST-based analysis with function-level complexity scoring
- **Code Duplication Detection** - Identify duplicated blocks for DRY principle
- **Technical Debt Tracking** - TODO, FIXME, HACK, XXX, BUG indicator counting
- **Type Hints Coverage** - PEP 484/585 compliance analysis
- **Docstring Coverage** - PEP 257 documentation completeness
- **PEP 8 Compliance** - Naming conventions, function length, class complexity validation
- **Maintainability Metrics** - Nested complexity, dead code, magic numbers detection

### 📊 Total Security Arsenal
- **144 Total Checks** (was 114) - +30 new checks (+26% increase)
- **53 Security Checks** (was 38) - 40% increase in security coverage
- **12 Check Modules** - New: Advanced Security + Code Quality
- **60+ Framework Mappings** - OWASP, ISO42001, CWE, GDPR, SOX, HIPAA

### 🚀 Maintained from Version 4
- **3-5x Faster Execution** - Parallel check execution (maintained)
- **100% ISO/IEC 42001 Coverage** - Complete compliance framework
- **CI/CD Integration** - GitHub Actions + GitLab CI pipelines
- **Auto-Fix Templates** - 5 production-ready configurations

See [CHANGELOG.md](CHANGELOG.md) for complete Version 5 details.

---

## ⚠️ Important Disclaimer

**This tool does NOT provide official certification or compliance guarantees.**

It is a best-effort mapping and assessment tool designed to help practitioners:
- Identify security and governance gaps in AI systems
- Map implemented controls to recognized frameworks
- Generate evidence-based audit reports

Always consult with qualified compliance professionals for official certifications.

---

## 🎯 Features

### Core Capabilities
- **🔍 144 Comprehensive Checks** - Data integrity, model artifacts, supply chain, PII/privacy, inference security, logging (12 checks), governance (25 checks), impact assessment, plugin security, model security, **advanced security (15 checks)**, **code quality (15 checks)**
- **⚡ 3-5x Faster** - Parallel execution with ThreadPoolExecutor (5 concurrent workers)
- **📊 Complete Framework Coverage** - 100% OWASP AI Top 10, ISO/IEC 42001, plus CWE mappings
- **🖥️ Dual Interface** - CLI (Typer) and Web UI (Streamlit)
- **📝 Multi-Format Reports** - Markdown, HTML, JSON, SARIF, and optional PDF
- **🎯 Risk Matrix** - Visual risk assessment with likelihood × impact scoring
- **🔐 Privacy-First** - All processing happens locally; no data uploads
- **🐳 Docker Support** - Run as CLI or web server in containers
- **🧩 Pluggable Architecture** - Easy to extend with custom checks

### Version 5 Security Features (NEW)
- **🔑 Secrets Detection** - 13+ secret types across multiple file formats
- **🛡️ Vulnerability Scanning** - CVE database for ML libraries
- **⚠️ AI Vulnerability Patterns** - Prompt injection, model extraction, adversarial detection
- **🔒 OWASP Top 10** - SQL injection, XSS, command injection, path traversal
- **🔐 Crypto Validation** - Weak algorithm detection, TLS/SSL configuration
- **📋 CWE Mappings** - Standardized vulnerability classification

### Version 5 Quality Features (NEW)
- **📊 Complexity Analysis** - Cyclomatic complexity with AST parsing
- **🔍 Code Duplication** - DRY principle validation
- **📝 Documentation Coverage** - Type hints and docstring analysis
- **🎯 PEP 8 Compliance** - Naming conventions and style validation
- **⚙️ Technical Debt** - TODO/FIXME tracking and metrics

### Advanced Features (v4+)
- **🔄 Baseline Comparison** - Regression detection for CI/CD pipelines
- **📈 Trend Tracking** - Historical compliance analytics with SQLite storage
- **🤖 Auto-Remediation** - Interactive wizard with 6 auto-fixable issues
- **🔗 Webhook Integration** - POST results to Slack, PagerDuty, or custom endpoints
- **🔍 SARIF Export** - Native GitHub/GitLab Security Dashboard integration
- **💾 Smart Caching** - 90% faster on repeated runs (SHA256-based cache)
- **📦 SBOM Generation** - Software Bill of Materials for supply chain security
- **🎨 Enterprise Templates** - 5 production-ready configuration templates

---

## 📊 Framework Coverage

| Framework | Coverage | Checks | Version 5 Enhancement |
|-----------|----------|--------|----------------------|
| **OWASP AI Security Top 10** | ✅ 100% | All 10 categories covered | ✨ +AI vulnerability patterns |
| **OWASP Top 10 2021** | ✅ 85% | A01, A02, A03, A05, A06, A07, A08 | ✨ NEW in v5.0 |
| **ISO/IEC 42001** | ✅ 100% | Clauses 4, 5, 6, 7, 8, 9, 10 | - |
| **CWE (Common Weakness Enum)** | ✅ 12 CWEs | Top security weaknesses | ✨ NEW in v5.0 |
| **GDPR** | ✅ 95% | PII, privacy, retention, rights | - |
| **SOX** | ✅ 85% | Audit trails, controls, change mgmt | - |
| **HIPAA** | ✅ 75% | Log security, access controls | - |

---

## 🚀 Quick Start

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

#### 3. Run Compliance Checks (with Performance Boost!)

```bash
# Basic run
raicb run --config raicb.yaml --env prod --out ./reports --format md,html

# With caching for 90% speedup on repeated runs
raicb run --config raicb.yaml --env prod --cache --verbose

# With SARIF export for GitHub Security
raicb run --format sarif --out ./reports

# With trend tracking
raicb run --track --cache
```

**New in v4:** Runs 3-5x faster with parallel execution!

Options:
- `--config`: Path to configuration file (default: `raicb.yaml`)
- `--env`: Environment to check (`dev`, `stage`, `prod`)
- `--out`: Output directory for reports
- `--format`: Report formats (comma-separated: `md`, `html`, `json`, `sarif`, `pdf`)
- `--cache`: Enable caching for faster runs (NEW in v4)
- `--track`: Record assessment in trends database (NEW)
- `--webhook`: POST results to webhook URL (NEW)
- `--fail-on`: Exit with error on severity (`critical`, `high`, `medium`, `any`)

#### 4. Advanced Commands (Version 4)

```bash
# Baseline comparison for regression detection
raicb baseline-create reports/assessment.json --output baseline.json
raicb baseline-compare reports/assessment.json --baseline baseline.json

# Trend analysis
raicb trends --days 90 --export trends.json

# Cache management
raicb cache-stats
raicb cache-clear --older-than 7

# Auto-remediation wizard
raicb fix --report reports/assessment.json

# View framework mappings
raicb map --framework all

# Generate SBOM
raicb sbom --output sbom.json
```

---

## 🏗️ CI/CD Integration

### GitHub Actions

Copy `.github/workflows/compliance-check.yml` to your repository:

```yaml
name: AI Compliance Check
on: [push, pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run compliance checks
        run: |
          pip install -e .
          raicb run --format sarif --cache --fail-on high

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: reports/raicb-*.sarif
```

**Features:**
- Automated checks on every push/PR
- SARIF upload to GitHub Security tab
- Baseline comparison for regression detection
- PR comments with assessment summary
- Scheduled daily runs

See [.github/workflows/compliance-check.yml](.github/workflows/compliance-check.yml) for complete workflow.

### GitLab CI/CD

Copy `.gitlab-ci.yml` to your repository:

```yaml
compliance:
  script:
    - pip install -e .
    - raicb run --format sarif --cache --fail-on high
  artifacts:
    reports:
      sast: reports/raicb-*.sarif
```

**Features:**
- Multi-environment assessment (dev/stage/prod)
- GitLab Security Dashboard integration
- SBOM generation
- Baseline comparison
- Webhook notifications

See [.gitlab-ci.yml](.gitlab-ci.yml) for complete pipeline.

---

## 📋 Check Categories (114 Total Checks)

### 1. Data Integrity (9 checks)
- Dataset hash verification
- Schema consistency validation
- Signed digest checks
- Training data provenance
- Data lineage tracking

### 2. Model Artifacts (8 checks)
- Model card presence and completeness
- Reproducible build hashes
- Secret detection in artifacts
- Serialization safety warnings
- Model versioning

### 3. Supply Chain (12 checks)
- Dependency SBOM generation
- Known vulnerability scanning (via `pip-audit`)
- License compliance checks
- Model provenance verification
- Supply chain attack detection
- Dependency update policies
- **NEW:** Third-party risk assessment
- **NEW:** Procurement controls

### 4. PII/Privacy (14 checks)
- PII handling configuration review
- Log sampling for PII detection (opt-in)
- Data minimization checks
- GDPR compliance (11 comprehensive checks)
- Right to be forgotten implementation
- Data retention policies
- Privacy by design validation

### 5. Inference Security (11 checks)
- TLS/auth requirements
- Rate limiting configuration
- Input validation and size bounds
- Prompt injection mitigation
- Output sanitization
- DDoS protection

### 6. **Logging & Audit (12 checks - 3x expansion!)**
- Audit trail presence and completeness (6 critical event types)
- Log rotation policies
- Tamper-evident logging options
- **NEW:** SIEM integration detection (Splunk, ELK, Datadog)
- **NEW:** Prediction/inference logging
- **NEW:** Security event logging
- **NEW:** Log retention compliance (GDPR, SOX, HIPAA)
- **NEW:** Centralized logging configuration
- **NEW:** Log access controls and permissions
- **NEW:** Audit trail immutability (WORM, Merkle trees)

### 7. **Governance (25 checks - 2.5x expansion!)**
- Policy documentation checks
- Role assignment verification
- Risk management framework
- Change control evidence
- Model lifecycle tracking
- **NEW:** AI objectives documentation (ISO 6.2)
- **NEW:** Objectives measurability with KPIs
- **NEW:** Continuous improvement process (ISO 10)
- **NEW:** Corrective actions tracking
- **NEW:** Nonconformity tracking
- **NEW:** Performance monitoring (ISO 9)
- **NEW:** Internal audit program
- **NEW:** Management review process
- **NEW:** Stakeholder communication plan
- **NEW:** Competence and training documentation
- **NEW:** Documentation control (version control)
- **NEW:** Third-party risk management
- **NEW:** Procurement controls
- **NEW:** AI system decommissioning plan
- **NEW:** Incident learning and postmortems

### 8. Impact Assessment (12 checks)
- Algorithmic impact assessment
- Fairness and bias evaluation
- Environmental impact
- Societal impact documentation
- Stakeholder impact analysis

### 9. Plugin Security (10 checks)
- Plugin validation and sandboxing
- Plugin permission controls
- Plugin update verification
- Malicious plugin detection

### 10. Model Security (9 checks)
- Model poisoning detection
- Adversarial robustness
- Model watermarking
- Intellectual property protection
- Model monitoring and drift detection

---

## 🗺️ Framework Mappings

### OWASP AI Security Top 10 (100% Coverage)
| ID | Category | Mapped Checks |
|----|----------|---------------|
| LLM01 | Prompt Injection | Inference Security, Input Validation |
| LLM02 | Insecure Output Handling | Inference Security, Output Sanitization |
| LLM03 | Training Data Poisoning | Data Integrity, Provenance |
| LLM04 | Model Denial of Service | Inference Security, Rate Limiting |
| LLM05 | Supply Chain Vulnerabilities | Supply Chain (all 12 checks) |
| LLM06 | Sensitive Information Disclosure | PII/Privacy (all 14 checks) |
| LLM07 | Insecure Plugin Design | Plugin Security (all 10 checks) |
| LLM08 | Excessive Agency | Governance, Access Controls |
| LLM09 | Overreliance | Model Artifacts, Documentation |
| LLM10 | Model Theft | Model Security, Access Controls |

### ISO/IEC 42001 (100% Coverage)
| Clause | Title | Mapped Checks |
|--------|-------|---------------|
| **Clause 4** | Context of Organization | Governance (stakeholder analysis) |
| **Clause 5** | Leadership | Governance (role assignments, owners) |
| **Clause 6** | Planning | Risk Management, AI Objectives (**NEW**) |
| **Clause 6.2** | AI Objectives | Objectives documentation, measurability (**NEW**) |
| **Clause 7** | Support | Documentation, Training, Communication (**NEW**) |
| **Clause 7.2** | Competence | Training and competence documentation (**NEW**) |
| **Clause 7.4** | Communication | Stakeholder communication plan (**NEW**) |
| **Clause 7.5** | Documented Information | Documentation control (**NEW**) |
| **Clause 8** | Operation | Model Lifecycle, Logging, Procurement (**NEW**) |
| **Clause 8.2** | Third-party Management | Vendor risk, procurement controls (**NEW**) |
| **Clause 8.3** | Decommissioning | System retirement planning (**NEW**) |
| **Clause 9** | Performance Evaluation | Logging, Audit, Monitoring (**NEW**) |
| **Clause 9.1** | Monitoring | Performance monitoring (**NEW**) |
| **Clause 9.2** | Internal Audit | Audit program (**NEW**) |
| **Clause 9.3** | Management Review | Review processes (**NEW**) |
| **Clause 10** | Improvement | Change Control, Continuous Improvement (**NEW**) |
| **Clause 10.2** | Corrective Action | Corrective actions, incident learning (**NEW**) |

*Note: These are thematic mappings to help prepare for audits, not compliance certifications.*

---

## 🎨 Auto-Fix Templates (NEW in v4)

Generate production-ready configurations with one command:

### 1. AI Objectives Template
```bash
# Generates docs/ai_objectives.md with:
# - Business objectives with measurable KPIs
# - Performance targets (accuracy, latency, throughput)
# - Fairness and bias mitigation objectives
# - Safety and security requirements
```

### 2. Logging Configuration
```bash
# Generates logging_config.yml with:
# - JSON structured logging for SIEM
# - Separate handlers for audit/security/inference/errors
# - Rotating file handlers with retention
# - Complete critical event logging guide
```

### 3. SIEM Integration (Filebeat)
```bash
# Generates filebeat.yml with:
# - Elasticsearch/Logstash output configuration
# - Multi-input for all log types
# - Log enrichment processors
# - ILM and monitoring setup
```

### 4. Continuous Improvement Process
```bash
# Generates docs/continuous_improvement.md with:
# - PDCA cycle implementation
# - Feedback collection mechanisms
# - Improvement prioritization framework
# - KPI tracking and reporting
```

### 5. Performance Monitoring (Prometheus)
```bash
# Generates prometheus.yml with:
# - AI-specific metrics (inference, confidence, errors)
# - Alert rules for critical conditions
# - Python instrumentation examples
```

See [templates/](templates/) directory for all templates.

---

## 🐳 Docker Usage

Build the image:
```bash
docker build -t raicb -f docker/Dockerfile .
```

### Run as CLI
```bash
docker run -v $(pwd)/examples/sample_project:/workspace raicb \
  raicb run --config /workspace/raicb.yaml --out /workspace/reports --cache
```

### Run as Web UI
```bash
docker run -e MODE=ui -p 8501:8501 raicb
```

---

## 🌐 Streamlit Web UI

Launch the interactive web interface:

```bash
streamlit run app/streamlit_app.py
```

Then open http://localhost:8501 in your browser.

**Features:**
- Upload or select project configuration
- Interactive checklist tables with filtering
- Visual risk matrix
- One-click report generation
- Download reports in multiple formats
- Real-time assessment progress

---

## 📚 Configuration

### Main Configuration File (`raicb.yaml`)

```yaml
project:
  name: "My AI System"
  version: "1.0.0"
  owners:
    - name: "AI Team"
      email: "ai-team@example.com"
  contacts:
    - name: "On-Call Engineer"
      email: "oncall@example.com"

artifacts:
  model_path: "./artifacts/model.pt"
  model_card: "./model_card.yaml"
  tokenizer: "./artifacts/tokenizer.json"

policies:
  risk_management: "./governance/risk_policy.md"
  incident_response: "./governance/incident_response.md"
  privacy: "./governance/privacy_policy.md"
  security: "./governance/security_policy.md"
  change_control: "./governance/change_control.md"

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
    monitoring_enabled: true
```

See `examples/sample_project/raicb.yaml` for a complete example.

---

## 🔧 Extending with Custom Checks

### Using the Plugin System

Create a plugin in `plugins/` directory:

```python
# plugins/custom_check.py
from pathlib import Path
from typing import List
from raicb.config.schema import ProjectConfig, Finding

class CustomComplianceCheck:
    """Custom check plugin."""

    name = "custom-check"
    version = "1.0.0"

    def run_checks(
        self,
        config: ProjectConfig,
        project_root: Path,
        env: str
    ) -> List[Finding]:
        findings = []

        # Your custom check logic here
        findings.append(
            Finding(
                check_id="CUSTOM-001",
                title="My Custom Check",
                severity="medium",
                status="pass",
                category="custom",
                description="Custom security check",
                evidence="Check passed",
                remediation="N/A",
                owasp_mapping=["LLM03"],
                iso_mapping=["Clause_8"]
            )
        )

        return findings
```

Run with plugins:
```bash
raicb run --config raicb.yaml
# Automatically discovers and runs plugins in ./plugins/
```

List available plugins:
```bash
raicb plugins --dir ./plugins
```

---

## 🧪 Development

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

### Performance Benchmarking

```bash
# Benchmark parallel vs sequential execution
time raicb run --config raicb.yaml --cache

# Clear cache and run fresh
raicb cache-clear
time raicb run --config raicb.yaml
```

**Expected Results (v4):**
- Cached run: ~0.5 seconds
- Fresh run: ~3-5 seconds (was 10-15 seconds in v3)
- Speedup: 3-5x improvement

---

## 🔒 Security

This tool is designed to help identify security issues in AI systems. If you discover a security vulnerability in **this toolkit itself**, please report it responsibly:

1. **Do NOT** open a public issue
2. Email: security@example.com (replace with actual contact)
3. Include detailed steps to reproduce
4. Allow 90 days for response before public disclosure

See [SECURITY.md](SECURITY.md) for our security policy.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-check`)
3. Run tests and ensure they pass (`pytest`)
4. Run linters (`ruff check --fix`, `black`)
5. Submit a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 📜 License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **OWASP AI Security**: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **ISO/IEC 42001**: Information technology — Artificial intelligence — Management system
- **NIST AI RMF**: AI Risk Management Framework
- **GDPR**: General Data Protection Regulation
- **SOX**: Sarbanes-Oxley Act
- **HIPAA**: Health Insurance Portability and Accountability Act

---

## 🗺️ Roadmap

### ✅ Completed (Version 4)
- ✅ Parallel execution for 3-5x performance boost
- ✅ Complete ISO/IEC 42001 coverage (100%)
- ✅ Enterprise logging & audit (12 comprehensive checks)
- ✅ SIEM integration detection
- ✅ Baseline comparison for regression detection
- ✅ Trend tracking and analytics
- ✅ Auto-remediation wizard
- ✅ GitHub Actions & GitLab CI/CD templates
- ✅ SARIF export for security dashboards
- ✅ Smart caching for faster runs
- ✅ 5 auto-fix configuration templates

### 🔮 Future (Version 5+)
- [ ] GPU acceleration for ML model checks
- [ ] Distributed execution (multi-node)
- [ ] Real-time monitoring dashboard (web UI)
- [ ] Auto-remediation for all check failures
- [ ] ML-based anomaly detection in logs
- [ ] Cloud security integrations (AWS Security Hub, Azure Security Center)
- [ ] Kubernetes/container security checks
- [ ] Zero-trust architecture validation
- [ ] REST API for programmatic access
- [ ] Plugin marketplace for community checks
- [ ] SBOM export in CycloneDX format
- [ ] Integration with ML experiment tracking tools (MLflow, Weights & Biases)
- [ ] Federated learning compliance checks
- [ ] EU AI Act compliance mapping

---

## 📊 Statistics

| Metric | Version 3 | Version 4 | Improvement |
|--------|-----------|-----------|-------------|
| **Total Checks** | 99 | **114** | +23 (+23%) |
| **Logging Checks** | 4 | **12** | +8 (3x) |
| **Governance Checks** | 10 | **25** | +15 (2.5x) |
| **Execution Time** | 10-15s | **3-5s** | **3-5x faster** |
| **ISO Coverage** | 80% | **100%** | +20% |
| **OWASP Coverage** | 100% | **100%** | Maintained |
| **Framework Clauses** | 12 | **17** | +5 |
| **Auto-Fix Templates** | 0 | **5** | New |
| **CI/CD Integrations** | 1 | **2** | +1 |

---

## ❓ FAQ

**Q: Does this tool certify my AI system for ISO/IEC 42001?**
A: No. This tool provides a best-effort mapping to help you prepare for audits. Official certification requires accredited auditors.

**Q: Will this upload my model or data anywhere?**
A: No. All processing is 100% local. No data leaves your machine. Privacy-first design.

**Q: Can I use this in CI/CD pipelines?**
A: Yes! We provide turnkey GitHub Actions and GitLab CI templates. Exit codes indicate pass/fail status. See [CI/CD Integration](#-cicd-integration) section.

**Q: How do I add custom checks?**
A: Use the plugin system. See the "Extending with Custom Checks" section above. Drop plugins in `./plugins/` directory.

**Q: What Python versions are supported?**
A: Python 3.10, 3.11, and 3.12.

**Q: How fast is Version 4?**
A: 3-5x faster than Version 3 thanks to parallel execution. Typical run: 3-5 seconds. With caching: ~0.5 seconds.

**Q: What's the difference between findings and checks?**
A: A check is a validation rule. A finding is the result (pass/fail/warning). One check can generate multiple findings.

**Q: Can I export results to my SIEM?**
A: Yes! Use webhook integration (`--webhook URL`) or export SARIF format for security dashboards.

**Q: How do I track compliance over time?**
A: Use trend tracking: `raicb run --track` stores results in SQLite. View with `raicb trends --days 90`.

**Q: What's included in the auto-fix templates?**
A: 5 production-ready templates: AI objectives, logging config, SIEM integration (Filebeat), continuous improvement process, and Prometheus monitoring. See [templates/](templates/).

---

## 📖 Documentation

- [VERSION_4_IMPLEMENTATION.md](VERSION_4_IMPLEMENTATION.md) - Complete Version 4 implementation details
- [FINAL_IMPLEMENTATION_SUMMARY.md](FINAL_IMPLEMENTATION_SUMMARY.md) - Version 2 summary
- [VERSION_2_IMPLEMENTATION.md](VERSION_2_IMPLEMENTATION.md) - Version 2 details
- [SECURITY.md](SECURITY.md) - Security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [LICENSE](LICENSE) - Apache 2.0 license

---

**Built with ❤️ for Responsible AI development**

**Status:** ✅ Production Ready - Enterprise Grade - Version 4.0.0

*Autonomous development powered by continuous improvement and innovation*
