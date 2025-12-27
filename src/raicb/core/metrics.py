import time
from functools import wraps
from typing import Any, Callable

from prometheus_client import Counter, Histogram

from raicb.core.logger import get_logger

logger = get_logger(__name__)

# Prometheus metrics
CHECK_DURATION = Histogram(
    'raicb_check_duration_seconds',
    'Check execution time',
    ['check_module', 'check_id']
)

CHECK_RESULTS = Counter(
    'raicb_check_results_total',
    'Check results by status',
    ['status', 'severity']
)

CACHE_HITS = Counter(
    'raicb_cache_hits_total',
    'Cache hits total'
)

CACHE_MISSES = Counter(
    'raicb_cache_misses_total',
    'Cache misses total'
)

CACHE_SIZE = Histogram(
    'raicb_cache_size_bytes',
    'Cache size in bytes'
)


def timed_check(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator to time check execution and record metrics."""
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()

        # Extract context if available
        check_id = kwargs.get('check_id', 'unknown')
        if not check_id and args and hasattr(args[0], 'id'):
             check_id = args[0].id

        module = func.__module__.split('.')[-1]

        try:
            result = func(*args, **kwargs)
            duration = time.perf_counter() - start

            # Record metrics
            CHECK_DURATION.labels(check_module=module, check_id=check_id).observe(duration)

            # Log timing
            logger.debug("Check completed", extra={
                "check": func.__name__,
                "check_id": check_id,
                "duration_ms": round(duration * 1000, 2)
            })

            return result
        except Exception:
            # We re-raise, but still want to track duration up to failure?
            # Or maybe not count failed durations in the same histogram?
            # For now, just record duration.
            duration = time.perf_counter() - start
            CHECK_DURATION.labels(check_module=module, check_id=check_id).observe(duration)
            raise

    return wrapper

