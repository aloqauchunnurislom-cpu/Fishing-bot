"""
memory.py — 2-QATLAM
In-memory dict cache, TTL=24 soat, max 2000 yozuv.
Bot qayta ishga tushganda tozalanadi.
"""

import time
from typing import Optional

from config import CACHE_TTL, CACHE_MAX_SIZE


class CacheEntry:
    """Bir URL uchun cache yozuvi."""

    __slots__ = ("score", "level", "source", "signals", "timestamp")

    def __init__(
        self,
        score: int,
        level: str,
        source: str,
        signals: list[str],
    ):
        self.score = score
        self.level = level
        self.source = source
        self.signals = signals
        self.timestamp = time.time()

    def is_expired(self) -> bool:
        return (time.time() - self.timestamp) > CACHE_TTL


class MemoryCache:
    """
    O'lchamli in-memory cache.
    - TTL: 24 soat (default)
    - Max: 2000 yozuv
    - Eski yozuvlar avtomatik o'chiriladi
    """

    def __init__(self):
        self._store: dict[str, CacheEntry] = {}

    def get(self, url: str) -> Optional[CacheEntry]:
        """URL uchun cache yozuvini olish. Expired bo'lsa None."""
        key = url.lower().strip()
        entry = self._store.get(key)
        if entry is None:
            return None
        if entry.is_expired():
            del self._store[key]
            return None
        return entry

    def put(
        self,
        url: str,
        score: int,
        level: str,
        source: str,
        signals: list[str],
    ):
        """Yangi natijani cache ga saqlash."""
        key = url.lower().strip()

        # Hajm limitini tekshirish
        if len(self._store) >= CACHE_MAX_SIZE:
            self._evict_oldest()

        self._store[key] = CacheEntry(score, level, source, signals)

    def _evict_oldest(self):
        """Eng eski yozuvlarni o'chirish (25% tozalash)."""
        # Avval expired larni tozalash
        expired_keys = [
            k for k, v in self._store.items() if v.is_expired()
        ]
        for k in expired_keys:
            del self._store[k]

        # Hali ham ko'p bo'lsa, eng eskilarini o'chirish
        if len(self._store) >= CACHE_MAX_SIZE:
            sorted_keys = sorted(
                self._store.keys(),
                key=lambda k: self._store[k].timestamp,
            )
            # 25% ni o'chirish
            to_remove = len(sorted_keys) // 4
            for k in sorted_keys[:to_remove]:
                del self._store[k]

    @property
    def size(self) -> int:
        return len(self._store)

    def clear(self):
        self._store.clear()
