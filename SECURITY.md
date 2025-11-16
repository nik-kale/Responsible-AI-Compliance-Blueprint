# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them responsibly by emailing security@example.com (replace with actual contact).

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report more quickly.

## Disclosure Policy

We follow the principle of Coordinated Vulnerability Disclosure:

1. **Reporter submits vulnerability** via email
2. **We acknowledge receipt** within 48 hours
3. **We investigate and validate** the issue (typically 7-14 days)
4. **We develop and test a fix** (timeline varies by severity)
5. **We release the fix** and credit the reporter (if desired)
6. **Public disclosure** occurs after the fix is released or after 90 days, whichever comes first

## Security Best Practices for Users

When using this toolkit:

1. **Never commit sensitive data** to your configuration files
2. **Use environment variables** for secrets and credentials
3. **Enable PII scanning** carefully - be aware it processes your data locally
4. **Review generated reports** before sharing - they may contain sensitive evidence
5. **Keep dependencies updated** - run `pip-audit` regularly
6. **Run in sandboxed environments** when assessing untrusted projects
7. **Validate YAML files** from untrusted sources before loading

## Known Security Considerations

### YAML Loading
This tool uses `yaml.safe_load()` which is safe against arbitrary code execution. However, always validate YAML files from untrusted sources.

### Local Processing
All assessments run locally. No data is transmitted to external servers. However, generated reports may contain sensitive information from your configuration and evidence files.

### Subprocess Calls
The tool invokes `pip-audit` and `pipdeptree` as subprocesses. Ensure these tools are from trusted sources.

### File System Access
The tool reads files specified in your configuration. Ensure proper file permissions and do not run with elevated privileges unless necessary.

## Security Scanning in CI/CD

We use the following security tools in our CI/CD pipeline:

- **pip-audit**: Scan for known vulnerabilities in dependencies
- **ruff**: Linting and security pattern detection
- **mypy**: Type checking to catch potential issues

## Contact

For security issues: security@example.com (replace with actual)
For general issues: https://github.com/yourusername/responsible-ai-compliance-blueprint/issues
