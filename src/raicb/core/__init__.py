"""Core functionality for compliance checking."""

from .loader import load_config, load_model_card
from .evaluator import run_all_checks
from .mapping import OWASP_MAPPING, ISO_MAPPING, get_framework_mappings
from .report import generate_report
from .utils import compute_file_hash, scan_for_pii, get_project_root
from .logger import get_logger, setup_logger
from .baseline import Baseline
from .cache import CheckCache
from .plugin import PluginManager, ComplianceCheckPlugin
from .dashboard import TrendTracker
from .remediation import RemediationWizard

__all__ = [
    # Version 1 exports
    "load_config",
    "load_model_card",
    "run_all_checks",
    "OWASP_MAPPING",
    "ISO_MAPPING",
    "get_framework_mappings",
    "generate_report",
    "compute_file_hash",
    "scan_for_pii",
    "get_project_root",
    # Version 2 exports
    "get_logger",
    "setup_logger",
    "Baseline",
    "CheckCache",
    "PluginManager",
    "ComplianceCheckPlugin",
    "TrendTracker",
    "RemediationWizard",
]
