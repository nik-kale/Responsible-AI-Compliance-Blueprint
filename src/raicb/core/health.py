from pathlib import Path
import shutil
from typing import Dict, Any
from raicb import __version__
from raicb.core.cache import CheckCache

def check_health() -> Dict[str, Any]:
    """Perform health checks on the system."""
    health = {
        "status": "healthy",
        "version": __version__,
        "dependencies": {},
        "system": {}
    }

    # Check dependencies
    # Check for CLI tools if they are used via subprocess
    # pip-audit and pipdeptree are installed as python packages
    try:
        import pip_audit
        health["dependencies"]["pip-audit"] = True
    except ImportError:
        health["dependencies"]["pip-audit"] = False
        health["status"] = "degraded"

    try:
        import pipdeptree
        health["dependencies"]["pipdeptree"] = True
    except ImportError:
        health["dependencies"]["pipdeptree"] = False
        health["status"] = "degraded"

    # Check cache
    try:
        cache = CheckCache()
        test_file = cache.cache_dir / ".health_check"
        test_file.touch()
        test_file.unlink()
        health["system"]["cache_writable"] = True
    except Exception as e:
        health["status"] = "unhealthy"
        health["system"]["cache_error"] = str(e)
        health["system"]["cache_writable"] = False

    return health

