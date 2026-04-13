"""
local_db.py — 3-QATLAM
SQLite baza va oflayn CSV blacklist lar bilan ishlash.
~245,000 URL oflayn tekshiriladi.
"""

import csv
import logging
from pathlib import Path
from typing import Optional

import aiosqlite

from config import DB_PATH, URLHAUS_PATH, PHISHTANK_PATH, OPENPHISH_PATH

logger = logging.getLogger(__name__)


class LocalDB:
    """SQLite baza + RAM dagi CSV blacklist setlari."""

    def __init__(self):
        self.db_path = str(DB_PATH)
        self.urlhaus_set: set[str] = set()
        self.phishtank_set: set[str] = set()
        self.openphish_set: set[str] = set()
        self._db: Optional[aiosqlite.Connection] = None

    async def initialize(self):
        """Bot ishga tushganda: SQLite jadvallar yaratish va CSV lar yuklash."""
        self._db = await aiosqlite.connect(self.db_path)
        await self._db.execute("PRAGMA journal_mode=WAL")

        # Tekshirilgan URL lar jadvali
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS checked_urls (
                url TEXT PRIMARY KEY,
                score INTEGER,
                level TEXT,
                source TEXT,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Guruh sozlamalari jadvali
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS group_settings (
                group_id INTEGER PRIMARY KEY,
                scan_enabled INTEGER DEFAULT 1,
                strict_mode INTEGER DEFAULT 0,
                language TEXT DEFAULT 'latin',
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Foydalanuvchi til sozlamalari
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS user_settings (
                user_id INTEGER PRIMARY KEY,
                language TEXT DEFAULT 'latin',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Statistika jadvali
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS daily_stats (
                date TEXT,
                total_checked INTEGER DEFAULT 0,
                total_dangerous INTEGER DEFAULT 0,
                total_deleted INTEGER DEFAULT 0,
                PRIMARY KEY (date)
            )
        """)

        await self._db.commit()

        # CSV fayllarni RAM ga yuklash
        self._load_csv_files()
        logger.info(
            "LocalDB tayyor: URLhaus=%d, PhishTank=%d, OpenPhish=%d",
            len(self.urlhaus_set), len(self.phishtank_set), len(self.openphish_set),
        )

    def _load_csv_files(self):
        """CSV va TXT fayllarni set sifatida RAMga yuklash — O(1) qidirish."""
        self.urlhaus_set = self._load_urlhaus(URLHAUS_PATH)
        self.phishtank_set = self._load_phishtank(PHISHTANK_PATH)
        self.openphish_set = self._load_openphish(OPENPHISH_PATH)

    def reload_csv_files(self):
        """CSV yangilanganidan keyin qayta yuklash (updater chaqiradi)."""
        self._load_csv_files()
        logger.info(
            "CSV qayta yuklandi: URLhaus=%d, PhishTank=%d, OpenPhish=%d",
            len(self.urlhaus_set), len(self.phishtank_set), len(self.openphish_set),
        )

    @staticmethod
    def _load_urlhaus(path: Path) -> set[str]:
        """URLhaus CSV formatini o'qish: id,dateadded,url,..."""
        urls: set[str] = set()
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 3 and not row[0].startswith("#"):
                        url = row[2].strip().strip('"').lower()
                        if url.startswith("http"):
                            urls.add(url)
        except FileNotFoundError:
            pass
        return urls

    @staticmethod
    def _load_phishtank(path: Path) -> set[str]:
        """PhishTank CSV: phish_id,url,..."""
        urls: set[str] = set()
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                next(reader, None)  # Header o'tkazish
                for row in reader:
                    if len(row) >= 2:
                        url = row[1].strip().strip('"').lower()
                        if url.startswith("http"):
                            urls.add(url)
        except FileNotFoundError:
            pass
        return urls

    @staticmethod
    def _load_openphish(path: Path) -> set[str]:
        """OpenPhish: har qatorda bitta URL."""
        urls: set[str] = set()
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip().lower()
                    if line.startswith("http"):
                        urls.add(line)
        except FileNotFoundError:
            pass
        return urls

    def check_blacklists(self, url: str) -> tuple[int, list[str]]:
        """
        URL ni uchta oflayn blacklist da qidirish.
        Hit bo'lsa +55 ball.
        """
        url_lower = url.lower().strip()
        score = 0
        signals: list[str] = []

        if url_lower in self.urlhaus_set:
            score += 55
            signals.append("🔴 URLhaus blacklist da topildi")
        elif url_lower in self.phishtank_set:
            score += 55
            signals.append("🔴 PhishTank blacklist da topildi")
        elif url_lower in self.openphish_set:
            score += 55
            signals.append("🔴 OpenPhish blacklist da topildi")

        return score, signals

    # ─── URL natija saqlash / o'qish ─────────────────────────────────

    async def save_result(self, url: str, score: int, level: str, source: str):
        """Tekshirilgan URL natijasini saqlash."""
        if self._db is None:
            return
        await self._db.execute(
            """INSERT OR REPLACE INTO checked_urls (url, score, level, source)
               VALUES (?, ?, ?, ?)""",
            (url.lower(), score, level, source),
        )
        await self._db.commit()

    async def get_saved_result(self, url: str) -> Optional[dict]:
        """Avval tekshirilgan natijani olish."""
        if self._db is None:
            return None
        async with self._db.execute(
            "SELECT score, level, source, checked_at FROM checked_urls WHERE url = ?",
            (url.lower(),),
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return {
                    "score": row[0],
                    "level": row[1],
                    "source": row[2],
                    "checked_at": row[3],
                }
        return None

    # ─── Guruh sozlamalari ────────────────────────────────────────────

    async def get_group_settings(self, group_id: int) -> dict:
        """Guruh sozlamalarini olish (yo'q bo'lsa default)."""
        if self._db is None:
            return {"scan_enabled": True, "strict_mode": False, "language": "latin"}
        await self._db.execute(
            "INSERT OR IGNORE INTO group_settings (group_id) VALUES (?)",
            (group_id,),
        )
        await self._db.commit()
        async with self._db.execute(
            "SELECT scan_enabled, strict_mode, language FROM group_settings WHERE group_id = ?",
            (group_id,),
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return {
                    "scan_enabled": bool(row[0]),
                    "strict_mode": bool(row[1]),
                    "language": row[2],
                }
        return {"scan_enabled": True, "strict_mode": False, "language": "latin"}

    async def set_group_scan(self, group_id: int, enabled: bool):
        await self._ensure_group(group_id)
        if self._db:
            await self._db.execute(
                "UPDATE group_settings SET scan_enabled = ? WHERE group_id = ?",
                (int(enabled), group_id),
            )
            await self._db.commit()

    async def set_group_strict(self, group_id: int, strict: bool):
        await self._ensure_group(group_id)
        if self._db:
            await self._db.execute(
                "UPDATE group_settings SET strict_mode = ? WHERE group_id = ?",
                (int(strict), group_id),
            )
            await self._db.commit()

    async def set_group_language(self, group_id: int, lang: str):
        await self._ensure_group(group_id)
        if self._db:
            await self._db.execute(
                "UPDATE group_settings SET language = ? WHERE group_id = ?",
                (lang, group_id),
            )
            await self._db.commit()

    async def _ensure_group(self, group_id: int):
        if self._db:
            await self._db.execute(
                "INSERT OR IGNORE INTO group_settings (group_id) VALUES (?)",
                (group_id,),
            )
            await self._db.commit()

    # ─── Foydalanuvchi til sozlamasi ──────────────────────────────────

    async def get_user_language(self, user_id: int) -> str:
        if self._db is None:
            return "latin"
        async with self._db.execute(
            "SELECT language FROM user_settings WHERE user_id = ?",
            (user_id,),
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else "latin"

    async def set_user_language(self, user_id: int, lang: str):
        if self._db:
            await self._db.execute(
                "INSERT OR REPLACE INTO user_settings (user_id, language) VALUES (?, ?)",
                (user_id, lang),
            )
            await self._db.commit()

    # ─── Statistika ──────────────────────────────────────────────────

    async def increment_stats(
        self, dangerous: bool = False, deleted: bool = False
    ):
        """Bugungi statistikani oshirish."""
        if self._db is None:
            return
        from datetime import date
        today = date.today().isoformat()
        await self._db.execute(
            "INSERT OR IGNORE INTO daily_stats (date) VALUES (?)",
            (today,),
        )
        await self._db.execute(
            "UPDATE daily_stats SET total_checked = total_checked + 1 WHERE date = ?",
            (today,),
        )
        if dangerous:
            await self._db.execute(
                "UPDATE daily_stats SET total_dangerous = total_dangerous + 1 WHERE date = ?",
                (today,),
            )
        if deleted:
            await self._db.execute(
                "UPDATE daily_stats SET total_deleted = total_deleted + 1 WHERE date = ?",
                (today,),
            )
        await self._db.commit()

    async def get_today_stats(self) -> dict:
        """Bugungi statistikani olish."""
        if self._db is None:
            return {"total_checked": 0, "total_dangerous": 0, "total_deleted": 0}
        from datetime import date
        today = date.today().isoformat()
        async with self._db.execute(
            "SELECT total_checked, total_dangerous, total_deleted FROM daily_stats WHERE date = ?",
            (today,),
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return {
                    "total_checked": row[0],
                    "total_dangerous": row[1],
                    "total_deleted": row[2],
                }
        return {"total_checked": 0, "total_dangerous": 0, "total_deleted": 0}

    async def close(self):
        """Bot to'xtaganda bazani yopish."""
        if self._db:
            await self._db.close()
