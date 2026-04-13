"""
bot.py — Anti-Phishing Bot Entry Point.
Barcha komponentlarni yig'ib polling rejimida ishga tushiradi.

🛡 O'zbekiston Telegram auditoriyasi uchun maxsus anti-phishing bot.
"""

import asyncio
import logging
import sys

from aiogram import Bot, Dispatcher
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from aiohttp import web
import aiohttp
import os

from config import BOT_TOKEN
from checker.local_db import LocalDB
from cache.memory import MemoryCache
from utils.updater import setup_scheduler, update_all_feeds

# ─── Self-ping (Render uxlamasligi uchun) ────────────────────────────
RENDER_URL = os.getenv("RENDER_EXTERNAL_URL", "")

async def self_ping():
    """Har 10 daqiqada o'z-o'ziga ping — Render uxlamaydi."""
    if not RENDER_URL:
        return
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(RENDER_URL, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                logger.info("🏓 Self-ping: %s (status=%d)", RENDER_URL, resp.status)
    except Exception as e:
        logger.warning("🏓 Self-ping xatolik: %s", e)

# ─── Logging sozlash ────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("antiphish")

# Keraksiz loglarni pasaytirish
logging.getLogger("aiohttp").setLevel(logging.WARNING)
logging.getLogger("aiogram").setLevel(logging.WARNING)
logging.getLogger("apscheduler").setLevel(logging.WARNING)


async def main():
    """Botni ishga tushirish."""

    # ── Token tekshirish ─────────────────────────────────────────
    if not BOT_TOKEN:
        logger.error("❌ BOT_TOKEN .env faylida topilmadi!")
        logger.error("   .env.example dan nusxa oling va to'ldiring.")
        sys.exit(1)

    logger.info("🛡 Anti-Phishing Bot ishga tushmoqda...")

    # ── Komponentlarni yaratish ──────────────────────────────────
    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher()

    # Render uchun kichik web server (Uxlamasligi uchun)
    async def handle_ping(request):
        return web.Response(text="Bot is alive!")

    app = web.Application()
    app.router.add_get("/", handle_ping)
    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.getenv("PORT", 8080))
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    logger.info("🌐 Web server port %d da ishga tushdi", port)

    # LocalDB
    local_db = LocalDB()
    await local_db.initialize()
    logger.info("✅ SQLite baza tayyor")

    # Memory Cache
    cache = MemoryCache()
    logger.info("✅ In-memory cache tayyor")

    # Komponentlarni bot obyektiga biriktirish (handler lardan foydalanish uchun)
    bot._local_db = local_db  # type: ignore
    bot._cache = cache  # type: ignore

    # ── CSV feedlarni dastlabki yuklash ──────────────────────────
    logger.info("📥 CSV blacklist lar yuklanmoqda...")
    await update_all_feeds(local_db)

    # ── APScheduler — har 6 soatda CSV yangilash ─────────────────
    scheduler = setup_scheduler(local_db)
    logger.info("✅ CSV updater rejalashtirild")

    # ── Self-ping — har 10 daqiqada (Render uxlamasligi uchun) ───
    if RENDER_URL:
        from apscheduler.triggers.interval import IntervalTrigger
        scheduler.add_job(
            self_ping,
            trigger=IntervalTrigger(minutes=10),
            id="self_ping",
            name="Self Ping (Keep Alive)",
            replace_existing=True,
        )
        logger.info("🏓 Self-ping yoqildi: har 10 daqiqada → %s", RENDER_URL)
    else:
        logger.info("ℹ️ RENDER_EXTERNAL_URL topilmadi — self-ping o'chirilgan")

    # ── Handler larni ro'yxatdan o'tkazish ───────────────────────
    from handlers import commands, admin, messages, inline

    # Tartib muhim: avval commands (buyruqlar), keyin admin, keyin inline, oxirida messages
    dp.include_router(commands.router)
    dp.include_router(admin.router)
    dp.include_router(inline.router)
    dp.include_router(messages.router)  # Eng oxirida — catch-all
    logger.info("✅ Handler lar ro'yxatdan o'tdi")

    # ── Bot ma'lumotlarini olish ──────────────────────────────────
    bot_info = await bot.get_me()
    logger.info("🤖 Bot: @%s (%s)", bot_info.username, bot_info.full_name)
    logger.info("📊 Cache: max %d yozuv", cache._store.__class__.__name__ and 2000)
    logger.info(
        "📦 Blacklist: URLhaus=%d, PhishTank=%d, OpenPhish=%d",
        len(local_db.urlhaus_set),
        len(local_db.phishtank_set),
        len(local_db.openphish_set),
    )

    # ── Bot buyruqlarini o'rnatish ────────────────────────────────
    await bot.set_my_commands([
        {"command": "start", "description": "Botni ishga tushirish"},
        {"command": "help", "description": "Yordam"},
        {"command": "scan", "description": "Havola tekshirish — /scan URL"},
        {"command": "stats", "description": "Bugungi statistika"},
        {"command": "lang_latin", "description": "🌐 Lotin alifbosi"},
        {"command": "lang_cyrillic", "description": "🌐 Кирилл алифбоси"},
    ])

    logger.info("🚀 Bot polling rejimida ishga tushdi!")
    logger.info("━" * 50)

    # ── Polling boshlash ─────────────────────────────────────────
    try:
        await dp.start_polling(
            bot,
            allowed_updates=[
                "message",
                "inline_query",
                "chat_member",
            ],
        )
    finally:
        logger.info("Bot to'xtatilmoqda...")
        scheduler.shutdown(wait=False)
        await local_db.close()
        await bot.session.close()
        logger.info("✅ Bot to'xtatildi.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 Ctrl+C — bot to'xtatildi.")
    except Exception as e:
        logger.exception("❌ Kutilmagan xatolik: %s", e)
        sys.exit(1)
