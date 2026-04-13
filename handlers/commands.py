"""
commands.py — /start, /help, /scan, /stats, /lang_* buyruqlari.
"""

import logging

from aiogram import Router, types
from aiogram.filters import Command
from aiogram.utils.keyboard import InlineKeyboardBuilder

from utils.languages import get_text
from utils.extractor import extract_urls

logger = logging.getLogger(__name__)
router = Router()

# ─── Kanal obunasi tekshiruvi ────────────────────────────────────────
CHANNEL_USERNAME = "sharofiddinov_n"

async def is_subscribed(bot, user_id: int) -> bool:
    """Foydalanuvchi kanalga obuna bo'lganmi."""
    try:
        member = await bot.get_chat_member(
            chat_id=f"@{CHANNEL_USERNAME}",
            user_id=user_id
        )
        return member.status not in ("left", "kicked")
    except Exception:
        return False

def subscription_keyboard() -> types.InlineKeyboardMarkup:
    """Obuna bo'lish tugmasi."""
    builder = InlineKeyboardBuilder()
    builder.button(
        text="📢 Kanalga obuna bo'lish",
        url=f"https://t.me/{CHANNEL_USERNAME}"
    )
    builder.button(
        text="✅ Obuna bo'ldim",
        callback_data="check_sub"
    )
    builder.adjust(1)
    return builder.as_markup()


@router.message(Command("start"))
async def cmd_start(message: types.Message):
    """Bot bilan tanishtirish."""
    local_db = message.bot.__dict__.get("_local_db")
    lang = "latin"
    if local_db and message.from_user:
        lang = await local_db.get_user_language(message.from_user.id)

    # Obuna tekshirish
    if message.from_user and not await is_subscribed(message.bot, message.from_user.id):
        await message.answer(
            "⚠️ Botdan foydalanish uchun avval kanalga obuna bo'ling!",
            reply_markup=subscription_keyboard()
        )
        return

    await message.answer(
        get_text("start", lang),
        parse_mode="HTML",
    )


@router.callback_query(lambda c: c.data == "check_sub")
async def check_subscription_callback(callback: types.CallbackQuery):
    """Obuna bo'ldim tugmasi."""
    if await is_subscribed(callback.bot, callback.from_user.id):
        local_db = callback.bot.__dict__.get("_local_db")
        lang = "latin"
        if local_db:
            lang = await local_db.get_user_language(callback.from_user.id)
        await callback.message.edit_text(
            get_text("start", lang),
            parse_mode="HTML",
        )
    else:
        await callback.answer(
            "❌ Siz hali obuna bo'lmagansiz!",
            show_alert=True
        )


@router.message(Command("help"))
async def cmd_help(message: types.Message):
    """Yordam xabari."""
    local_db = message.bot.__dict__.get("_local_db")
    lang = "latin"
    if local_db and message.from_user:
        lang = await local_db.get_user_language(message.from_user.id)

    await message.answer(
        get_text("help", lang),
        parse_mode="HTML",
    )


@router.message(Command("scan"))
async def cmd_scan(message: types.Message):
    """
    /scan https://misol.uz — bitta URL ni tekshirish.
    """
    local_db = message.bot.__dict__.get("_local_db")
    lang = "latin"
    if local_db and message.from_user:
        lang = await local_db.get_user_language(message.from_user.id)

    # URL ni buyruq argumentidan olish
    args = (message.text or "").split(maxsplit=1)
    if len(args) < 2:
        await message.answer(get_text("no_url", lang))
        return

    url_text = args[1].strip()
    urls = extract_urls(url_text)
    if not urls:
        await message.answer(get_text("no_url", lang))
        return

    # Obuna tekshirish
    if message.from_user and not await is_subscribed(message.bot, message.from_user.id):
        await message.answer(
            "⚠️ Botdan foydalanish uchun avval kanalga obuna bo'ling!",
            reply_markup=subscription_keyboard()
        )
        return

    # Tekshirish logikasiga yo'naltirish (messages handler dagi engine)
    from handlers.messages import _run_full_check

    status_msg = await message.answer(get_text("checking", lang))

    for url in urls[:3]:  # Maks 3 ta URL
        result = await _run_full_check(url, message.text or "", message.bot)

        if result:
            from checker.scorer import Scorer
            response = Scorer.format_private_response(result, lang)
            await message.answer(response, parse_mode="HTML")

    # Status xabarni o'chirish
    try:
        await status_msg.delete()
    except Exception:
        pass


@router.message(Command("stats"))
async def cmd_stats(message: types.Message):
    """Bugungi statistikani ko'rsatish."""
    local_db = message.bot.__dict__.get("_local_db")
    lang = "latin"
    if local_db and message.from_user:
        lang = await local_db.get_user_language(message.from_user.id)

    if not local_db:
        await message.answer("Statistika mavjud emas.")
        return

    stats = await local_db.get_today_stats()
    cache = message.bot.__dict__.get("_cache")

    text = (
        f"📊 <b>{get_text('stats_title', lang)}</b>\n\n"
        f"🔗 {get_text('stats_checked', lang)}: {stats['total_checked']}\n"
        f"⚠️ {get_text('stats_dangerous', lang)}: {stats['total_dangerous']}\n"
        f"🗑 {get_text('stats_deleted', lang)}: {stats['total_deleted']}\n"
    )

    if cache:
        text += f"\n💾 Cache: {cache.size} yozuv"

    await message.answer(text, parse_mode="HTML")


@router.message(Command("lang_latin"))
async def cmd_lang_latin(message: types.Message):
    """Lotin alifbosini tanlash."""
    local_db = message.bot.__dict__.get("_local_db")
    if local_db and message.from_user:
        await local_db.set_user_language(message.from_user.id, "latin")

    await message.answer(get_text("lang_set_latin", "latin"))


@router.message(Command("lang_cyrillic"))
async def cmd_lang_cyrillic(message: types.Message):
    """Kirill alifbosini tanlash."""
    local_db = message.bot.__dict__.get("_local_db")
    if local_db and message.from_user:
        await local_db.set_user_language(message.from_user.id, "cyrillic")

    await message.answer(get_text("lang_set_cyrillic", "cyrillic"))
