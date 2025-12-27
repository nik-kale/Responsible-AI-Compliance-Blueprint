"""Caching system for compliance check results."""

import hashlib
import pickle
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from raicb.core.logger import get_logger
from raicb.core.metrics import CACHE_HITS, CACHE_MISSES, CACHE_SIZE

logger = get_logger(__name__)


class CheckCache:
    """Cache check results to avoid re-running expensive checks."""

    def __init__(self, cache_dir: Path = None):
        """
        Initialize cache manager.

        Args:
            cache_dir: Directory for cache files (default: ~/.raicb/cache)
        """
        self.cache_dir = cache_dir or (Path.home() / ".raicb" / "cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Cache directory: {self.cache_dir}")

    def _get_cache_key(self, config_path: Path, env: str) -> str:
        """
        Generate cache key from config file hash and environment.

        Args:
            config_path: Path to configuration file
            env: Environment name

        Returns:
            Cache key string
        """
        # Hash config file content
        try:
            content = config_path.read_bytes()
            hash_obj = hashlib.sha256(content)
            config_hash = hash_obj.hexdigest()[:16]

            # Combine with environment
            cache_key = f"{config_hash}_{env}"
            return cache_key

        except Exception as e:
            logger.error(f"Failed to generate cache key: {e}")
            return f"fallback_{env}"

    def get(
        self, config_path: Path, env: str, max_age: timedelta = timedelta(hours=1)
    ) -> Optional[Any]:
        """
        Get cached result if fresh.

        Args:
            config_path: Path to configuration file
            env: Environment name
            max_age: Maximum age of cache entry

        Returns:
            Cached data or None if not found/expired
        """
        try:
            key = self._get_cache_key(config_path, env)
            cache_file = self.cache_dir / f"{key}.cache"

            if not cache_file.exists():
                logger.debug(f"Cache miss: {key}")
                CACHE_MISSES.inc()
                return None

            # Check age
            mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
            age = datetime.now() - mtime

            if age > max_age:
                logger.debug(f"Cache expired: {key} (age: {age})")
                CACHE_MISSES.inc()
                # Clean up expired cache
                cache_file.unlink()
                return None

            # Load from cache
            with open(cache_file, "rb") as f:
                data = pickle.load(f)

            logger.info(f"Cache hit: {key} (age: {age})")
            CACHE_HITS.inc()
            return data

        except Exception as e:
            logger.error(f"Failed to load from cache: {e}")
            CACHE_MISSES.inc()
            return None

    def set(self, config_path: Path, env: str, data: Any) -> bool:
        """
        Cache result.

        Args:
            config_path: Path to configuration file
            env: Environment name
            data: Data to cache

        Returns:
            True if cached successfully
        """
        try:
            key = self._get_cache_key(config_path, env)
            cache_file = self.cache_dir / f"{key}.cache"

            with open(cache_file, "wb") as f:
                pickle.dump(data, f)

            logger.debug(f"Cached: {key}")
            
            # Update cache size metric
            CACHE_SIZE.observe(cache_file.stat().st_size)
            
            return True

        except Exception as e:
            logger.error(f"Failed to save to cache: {e}")
            return False

    def clear(self, older_than: Optional[timedelta] = None) -> int:
        """
        Clear cached results.

        Args:
            older_than: Only clear cache entries older than this (None = clear all)

        Returns:
            Number of cache entries cleared
        """
        cleared = 0

        try:
            for cache_file in self.cache_dir.glob("*.cache"):
                should_delete = False

                if older_than is None:
                    should_delete = True
                else:
                    mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
                    age = datetime.now() - mtime
                    if age > older_than:
                        should_delete = True

                if should_delete:
                    cache_file.unlink()
                    cleared += 1

            logger.info(f"Cleared {cleared} cache entries")
            return cleared

        except Exception as e:
            logger.error(f"Failed to clear cache: {e}")
            return cleared

    def stats(self) -> dict:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        try:
            cache_files = list(self.cache_dir.glob("*.cache"))
            total_size = sum(f.stat().st_size for f in cache_files)

            if cache_files:
                oldest = min(cache_files, key=lambda f: f.stat().st_mtime)
                newest = max(cache_files, key=lambda f: f.stat().st_mtime)

                oldest_age = datetime.now() - datetime.fromtimestamp(oldest.stat().st_mtime)
                newest_age = datetime.now() - datetime.fromtimestamp(newest.stat().st_mtime)
            else:
                oldest_age = timedelta(0)
                newest_age = timedelta(0)

            return {
                "cache_dir": str(self.cache_dir),
                "total_entries": len(cache_files),
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "oldest_entry_age": str(oldest_age),
                "newest_entry_age": str(newest_age),
            }

        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {"error": str(e)}
