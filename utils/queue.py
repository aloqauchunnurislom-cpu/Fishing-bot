"""
queue.py — Request Queue.
asyncio.Semaphore(5) bilan bir vaqtda maksimal 5 ta parallel tekshiruv.
"""

import asyncio
import logging
from typing import Any, Callable, Coroutine

from config import MAX_PARALLEL_CHECKS, CHECK_TIMEOUT

logger = logging.getLogger(__name__)

# Global semaphore
_semaphore = asyncio.Semaphore(MAX_PARALLEL_CHECKS)


async def queued_check(
    coro: Coroutine[Any, Any, Any],
    timeout: int = CHECK_TIMEOUT,
) -> Any:
    """
    URL tekshiruvini navbat orqali bajarish.
    - Bir vaqtda maks 5 ta parallel
    - Har biri maks 30 sekund
    - Timeout bo'lsa None qaytadi

    Usage:
        result = await queued_check(check_url(url))
    """
    async with _semaphore:
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("URL tekshiruv timeout (%ds)", timeout)
            return None
        except Exception as e:
            logger.error("URL tekshiruv xatolik: %s", e)
            return None


def get_queue_info() -> dict:
    """Navbat holati haqida ma'lumot."""
    return {
        "max_parallel": MAX_PARALLEL_CHECKS,
        "available": _semaphore._value,
        "busy": MAX_PARALLEL_CHECKS - _semaphore._value,
    }
