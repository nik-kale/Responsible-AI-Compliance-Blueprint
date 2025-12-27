"""Custom exceptions for RAICB."""

from contextlib import contextmanager
from typing import Optional, Generator, Any
from raicb.core.logger import get_logger

logger = get_logger(__name__)


class RAICBError(Exception):
    """Base exception for RAICB."""
    pass


class CheckExecutionError(RAICBError):
    """Error during check execution."""

    def __init__(self, check_id: str, message: str, cause: Optional[Exception] = None):
        self.check_id = check_id
        self.cause = cause
        super().__init__(f"[{check_id}] {message}")


class ConfigurationError(RAICBError):
    """Error in configuration."""
    pass


@contextmanager
def error_context(operation: str, **context: Any) -> Generator[None, None, None]:
    """
    Context manager to add context to errors.

    Args:
        operation: Description of the operation being performed
        **context: Key-value pairs of context information
    """
    try:
        yield
    except Exception as e:
        logger.error(f"Error during {operation}", extra={
            "context": context,
            "error_type": type(e).__name__,
            "error_message": str(e),
        }, exc_info=True)
        raise

