import uuid
from contextvars import ContextVar

correlation_id: ContextVar[str] = ContextVar('correlation_id', default='')

def get_correlation_id() -> str:
    """Get the current correlation ID, generating a new one if not set."""
    cid = correlation_id.get()
    if not cid:
        cid = str(uuid.uuid4())
        correlation_id.set(cid)
    return cid

def set_correlation_id(cid: str = None) -> str:
    """Set a new correlation ID."""
    if not cid:
        cid = str(uuid.uuid4())
    correlation_id.set(cid)
    return cid

