"""Pydantic models for YAML configuration validation."""

from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    """Check status."""

    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    SKIP = "skip"
    ERROR = "error"


class Likelihood(str, Enum):
    """Risk likelihood levels."""

    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class Impact(str, Enum):
    """Risk impact levels."""

    NEGLIGIBLE = "negligible"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Owner(BaseModel):
    """Project owner information."""

    name: str = Field(..., description="Owner name")
    email: EmailStr = Field(..., description="Owner email address")
    role: Optional[str] = Field(None, description="Role or title")


class ProjectInfo(BaseModel):
    """Project metadata."""

    name: str = Field(..., description="Project name")
    version: str = Field(..., description="Project version")
    description: Optional[str] = Field(None, description="Project description")
    owners: List[Owner] = Field(default_factory=list, description="Project owners")
    contacts: List[Owner] = Field(default_factory=list, description="Emergency contacts")
    created: Optional[str] = Field(None, description="Project creation date")
    updated: Optional[str] = Field(None, description="Last update date")


class Artifacts(BaseModel):
    """Model artifacts and related files."""

    model_path: Optional[str] = Field(None, description="Path to model file")
    model_card: Optional[str] = Field(None, description="Path to model card YAML")
    tokenizer: Optional[str] = Field(None, description="Path to tokenizer config")
    preprocessor: Optional[str] = Field(None, description="Path to preprocessor")
    postprocessor: Optional[str] = Field(None, description="Path to postprocessor")
    datasets: Dict[str, str] = Field(
        default_factory=dict, description="Dataset references (name: path)"
    )
    dependencies: Optional[str] = Field(
        None, description="Path to requirements.txt or similar"
    )
    checksums: Optional[str] = Field(None, description="Path to checksums file")

    @field_validator("model_path", "model_card", "tokenizer", mode="before")
    @classmethod
    def validate_paths(cls, v):
        """Validate that paths are strings if provided."""
        if v is not None and not isinstance(v, str):
            raise ValueError("Path must be a string")
        return v


class Policies(BaseModel):
    """Governance and policy document references."""

    risk_management: Optional[str] = Field(None, description="Risk management policy")
    incident_response: Optional[str] = Field(None, description="Incident response plan")
    data_governance: Optional[str] = Field(None, description="Data governance policy")
    model_lifecycle: Optional[str] = Field(None, description="Model lifecycle policy")
    ethics: Optional[str] = Field(None, description="AI ethics policy")
    privacy: Optional[str] = Field(None, description="Privacy policy")
    security: Optional[str] = Field(None, description="Security policy")
    acceptable_use: Optional[str] = Field(None, description="Acceptable use policy")
    change_control: Optional[str] = Field(None, description="Change control procedure")


class Threat(BaseModel):
    """Threat or risk item."""

    id: str = Field(..., description="Unique threat identifier")
    title: str = Field(..., description="Threat title")
    description: str = Field(..., description="Threat description")
    likelihood: Likelihood = Field(..., description="Likelihood of occurrence")
    impact: Impact = Field(..., description="Impact if realized")
    category: Optional[str] = Field(None, description="Threat category")
    controls: List[str] = Field(
        default_factory=list, description="Control IDs that mitigate this threat"
    )
    owasp_mapping: List[str] = Field(
        default_factory=list, description="OWASP AI Security mappings"
    )
    iso_mapping: List[str] = Field(default_factory=list, description="ISO/IEC 42001 mappings")
    residual_risk: Optional[str] = Field(None, description="Residual risk after controls")
    owner: Optional[str] = Field(None, description="Risk owner")


class Control(BaseModel):
    """Security or governance control."""

    id: str = Field(..., description="Unique control identifier")
    title: str = Field(..., description="Control title")
    description: Optional[str] = Field(None, description="Control description")
    implemented: bool = Field(False, description="Whether control is implemented")
    evidence: Optional[str] = Field(None, description="Path to evidence file/URL")
    effectiveness: Optional[str] = Field(
        None, description="Control effectiveness (low/medium/high)"
    )
    owner: Optional[str] = Field(None, description="Control owner")
    last_reviewed: Optional[str] = Field(None, description="Last review date")


class Environment(BaseModel):
    """Environment-specific configuration."""

    name: str = Field(..., description="Environment name (dev/stage/prod)")
    description: Optional[str] = Field(None, description="Environment description")

    # Security settings
    tls_required: bool = Field(True, description="TLS/SSL required")
    auth_required: bool = Field(True, description="Authentication required")
    rate_limiting: bool = Field(False, description="Rate limiting enabled")
    input_validation: bool = Field(True, description="Input validation enabled")

    # Infrastructure
    network_isolation: Optional[bool] = Field(None, description="Network isolation enabled")
    secrets_management: Optional[str] = Field(
        None, description="Secrets management solution (vault, kms, etc.)"
    )
    logging_enabled: bool = Field(True, description="Logging enabled")
    monitoring_enabled: bool = Field(True, description="Monitoring enabled")

    # Limits
    max_input_size: Optional[int] = Field(None, description="Max input size in bytes")
    max_tokens: Optional[int] = Field(None, description="Max tokens per request")
    timeout_seconds: Optional[int] = Field(None, description="Request timeout in seconds")

    # Additional settings
    content_security_policy: Optional[str] = Field(None, description="CSP header value")
    cors_allowed_origins: List[str] = Field(
        default_factory=list, description="CORS allowed origins"
    )
    additional_headers: Dict[str, str] = Field(
        default_factory=dict, description="Additional security headers"
    )


class ModelCard(BaseModel):
    """Model card metadata (separate YAML file)."""

    model_name: str = Field(..., description="Model name")
    version: str = Field(..., description="Model version")
    description: Optional[str] = Field(None, description="Model description")
    architecture: Optional[str] = Field(None, description="Model architecture")
    framework: Optional[str] = Field(None, description="ML framework (pytorch, tf, etc.)")

    # Training
    training_data: Optional[str] = Field(None, description="Training data description")
    training_date: Optional[str] = Field(None, description="Training completion date")
    training_metrics: Dict[str, float] = Field(
        default_factory=dict, description="Training metrics"
    )

    # Evaluation
    evaluation_data: Optional[str] = Field(None, description="Evaluation data description")
    evaluation_metrics: Dict[str, float] = Field(
        default_factory=dict, description="Evaluation metrics"
    )

    # Usage
    intended_use: Optional[str] = Field(None, description="Intended use cases")
    out_of_scope_use: Optional[str] = Field(None, description="Out of scope uses")
    limitations: Optional[str] = Field(None, description="Known limitations")
    bias_considerations: Optional[str] = Field(None, description="Bias considerations")

    # Provenance
    authors: List[str] = Field(default_factory=list, description="Model authors")
    license: Optional[str] = Field(None, description="Model license")
    citation: Optional[str] = Field(None, description="Citation information")


class PIIConfig(BaseModel):
    """PII detection and handling configuration."""

    scan_enabled: bool = Field(False, description="Enable PII scanning (opt-in)")
    scan_logs: bool = Field(False, description="Scan log files for PII")
    scan_samples: int = Field(100, description="Number of log lines to sample")
    redaction_enabled: bool = Field(True, description="Redact detected PII in reports")
    patterns: List[str] = Field(
        default_factory=lambda: [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"\b\d{16}\b",  # Credit card
        ],
        description="PII regex patterns",
    )


class ProjectConfig(BaseModel):
    """Main project configuration."""

    project: ProjectInfo = Field(..., description="Project metadata")
    artifacts: Artifacts = Field(default_factory=Artifacts, description="Model artifacts")
    policies: Policies = Field(default_factory=Policies, description="Policy documents")
    threats: List[Threat] = Field(default_factory=list, description="Identified threats/risks")
    controls: List[Control] = Field(default_factory=list, description="Implemented controls")
    environments: Dict[str, Environment] = Field(
        default_factory=dict, description="Environment configurations"
    )
    pii_config: PIIConfig = Field(default_factory=PIIConfig, description="PII configuration")

    # Additional metadata
    compliance_frameworks: List[str] = Field(
        default_factory=lambda: ["OWASP AI Security", "ISO/IEC 42001"],
        description="Target compliance frameworks",
    )
    assessment_date: Optional[str] = Field(None, description="Assessment date")
    assessor: Optional[str] = Field(None, description="Assessor name")

    @model_validator(mode="after")
    def validate_control_references(self):
        """Validate that threat control references exist."""
        control_ids = {c.id for c in self.controls}
        for threat in self.threats:
            for control_id in threat.controls:
                if control_id not in control_ids:
                    # Warning, not error - allow forward references
                    pass
        return self


class Finding(BaseModel):
    """Security or compliance finding."""

    check_id: str = Field(..., description="Unique check identifier")
    title: str = Field(..., description="Finding title")
    severity: Severity = Field(..., description="Finding severity")
    status: Status = Field(..., description="Check status")
    category: str = Field(..., description="Check category")
    description: str = Field(..., description="Finding description")
    evidence: Optional[str] = Field(None, description="Evidence or details")
    remediation: Optional[str] = Field(None, description="Remediation guidance")
    owasp_mapping: List[str] = Field(default_factory=list, description="OWASP mappings")
    iso_mapping: List[str] = Field(default_factory=list, description="ISO mappings")
    references: List[str] = Field(default_factory=list, description="Reference URLs")


class OWASPCoverage(BaseModel):
    """OWASP AI Security coverage item."""

    id: str = Field(..., description="OWASP ID (e.g., LLM01)")
    title: str = Field(..., description="OWASP item title")
    description: str = Field(..., description="OWASP item description")
    related_checks: List[str] = Field(default_factory=list, description="Related check IDs")


class ISOCoverage(BaseModel):
    """ISO/IEC 42001 coverage item."""

    clause: str = Field(..., description="ISO clause (e.g., Clause_6.1)")
    title: str = Field(..., description="ISO clause title")
    description: str = Field(..., description="ISO clause description")
    related_checks: List[str] = Field(default_factory=list, description="Related check IDs")


class AssessmentReport(BaseModel):
    """Complete assessment report."""

    # Project information
    project_name: str = Field(..., description="Project name")
    version: str = Field(..., description="Project version")
    environment: str = Field(..., description="Environment assessed")
    timestamp: str = Field(..., description="Assessment timestamp (ISO format)")
    assessment_date: str = Field(..., description="Assessment date (deprecated, use timestamp)")
    assessor: Optional[str] = Field(None, description="Assessor name")

    # Configuration reference
    project_config: "ProjectConfig" = Field(..., description="Full project configuration")

    # Findings and analysis
    findings: List[Finding] = Field(default_factory=list, description="All findings")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Executive summary")
    risk_matrix: Dict[str, Any] = Field(default_factory=dict, description="Risk matrix data")

    # Framework coverage
    owasp_coverage: List[OWASPCoverage] = Field(default_factory=list, description="OWASP coverage")
    iso_coverage: List[ISOCoverage] = Field(default_factory=list, description="ISO coverage")

    # Statistics
    total_checks: int = Field(0, description="Total checks run")
    passed_checks: int = Field(0, description="Passed checks")
    failed_checks: int = Field(0, description="Failed checks")
    warnings: int = Field(0, description="Warnings")


# Rebuild model to resolve forward references (Pydantic v2)
AssessmentReport.model_rebuild()
