"""Integrations for external systems and formats."""

from .webhook import WebhookIntegration
from .sarif import SARIFExporter

__all__ = ["WebhookIntegration", "SARIFExporter"]
