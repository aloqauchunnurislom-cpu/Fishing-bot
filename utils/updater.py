"""
updater.py — CSV blacklist yangilash.
APScheduler bilan har 6 soatda avtomatik yangilanadi.
URLhaus, PhishTank, OpenPhish dan yuklab oladi.
"""

import logging
import asyncio
from pathlib import Path

import aiohttp

from config import (
    CSV_UPDATE_INTERVAL_HOURS,
    URLHAUS_PATH,
    PHISHTANK_PATH,
    OPENPHISH_PATH,
)

logger = logging.getLogger(__name__)

# ─── Manba URL lari ──────────────────────────────────────────────────
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
PHISHTANK_URL = (
    "http://data.phishtank.com/data/online-valid.csv"
)
OPENPHISH_URL = "https://openphish.com/feed.txt"


async def _download_file(url: str, dest: Path, name: str) -> bool:
    """Faylni yuklab olish."""
    try:
        timeout = aiohttp.ClientTimeout(total=120)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    dest.write_bytes(content)
                    size_kb = len(content) / 1024
                    logger.info(
                        "%s yangilandi: %.1f KB", name, size_kb
                    )
                    return True
                else:
                    logger.warning(
                        "%s yuklab bo'lmadi: status=%d", name, resp.status
                    )
                    return False
    except Exception as e:
        logger.error("%s yuklab olishda xatolik: %s", name, e)
        return False


async def update_all_feeds(local_db=None):
    """
    Barcha CSV/TXT feedlarni yangilash.
    local_db berilsa — RAM dagi setlarni qayta yuklaydi.
    """
    logger.info("CSV feedlar yangilanmoqda...")

    results = await asyncio.gather(
        _download_file(URLHAUS_URL, URLHAUS_PATH, "URLhaus"),
        _download_file(PHISHTANK_URL, PHISHTANK_PATH, "PhishTank"),
        _download_file(OPENPHISH_URL, OPENPHISH_PATH, "OpenPhish"),
        return_exceptions=True,
    )

    success_count = sum(1 for r in results if r is True)
    logger.info(
        "CSV yangilash tugadi: %d/3 muvaffaqiyatli", success_count
    )

    # RAM dagi setlarni qayta yuklash
    if local_db and success_count > 0:
        local_db.reload_csv_files()

    return success_count


def setup_scheduler(local_db=None):
    """
    APScheduler ni sozlash — har N soatda CSV yangilash.
    Bot ishga tushganda chaqiriladi.
    """
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.interval import IntervalTrigger

    scheduler = AsyncIOScheduler()

    async def _job():
        await update_all_feeds(local_db)

    scheduler.add_job(
        _job,
        trigger=IntervalTrigger(hours=CSV_UPDATE_INTERVAL_HOURS),
        id="csv_updater",
        name="CSV Feed Updater",
        replace_existing=True,
    )

    scheduler.start()
    logger.info(
        "CSV updater rejalashtirild: har %d soatda",
        CSV_UPDATE_INTERVAL_HOURS,
    )
    return scheduler
