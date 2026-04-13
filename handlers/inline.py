"""
inline.py — Inline mode handler.
@botismi havola yozsa, istalgan chatda tez natija chiqadi.
"""

import logging
import hashlib

from aiogram import Router, types

from utils.extractor import extract_urls
from handlers.messages import _run_full_check

logger = logging.getLogger(__name__)
router = Router()


@router.inline_query()
async def handle_inline_query(inline_query: types.InlineQuery):
    """
    Inline rejam: foydalanuvchi @botismi https://... yozganida
    natija tezda ko'rsatiladi.
    """
    query_text = inline_query.query.strip()

    if not query_text:
        # Bo'sh so'rov — qisqa ko'rsatma
        await inline_query.answer(
            results=[
                types.InlineQueryResultArticle(
                    id="help",
                    title="🛡 Havola tekshirish",
                    description="URL yozing: @botismi https://misol.uz",
                    input_message_content=types.InputTextMessageContent(
                        message_text=(
                            "🛡 <b>Anti-Phishing Bot</b>\n"
                            "Havola tekshirish uchun:\n"
                            "@botismi https://misol.uz"
                        ),
                        parse_mode="HTML",
                    ),
                )
            ],
            cache_time=300,
        )
        return

    # URL larni ajratish
    urls = extract_urls(query_text)

    if not urls:
        await inline_query.answer(
            results=[
                types.InlineQueryResultArticle(
                    id="not_found",
                    title="❌ URL topilmadi",
                    description="To'g'ri URL kiriting",
                    input_message_content=types.InputTextMessageContent(
                        message_text="❌ Havola topilmadi.",
                    ),
                )
            ],
            cache_time=10,
        )
        return

    # Birinchi URL ni tekshirish
    url = urls[0]
    result = await _run_full_check(url, query_text, inline_query.bot)

    if not result:
        await inline_query.answer(
            results=[
                types.InlineQueryResultArticle(
                    id="error",
                    title="⚠️ Tekshirishda xatolik",
                    description="Qayta urinib ko'ring",
                    input_message_content=types.InputTextMessageContent(
                        message_text="⚠️ Tekshirishda xatolik yuz berdi.",
                    ),
                )
            ],
            cache_time=10,
        )
        return

    # Natijani formatlash
    result_id = hashlib.md5(url.encode()).hexdigest()[:16]

    display_url = url[:60] + ("..." if len(url) > 60 else "")
    title = f"{result.emoji} {result.level.upper()} — Ball: {result.score}/100"
    description = display_url

    # Batafsil xabar
    signals_text = "\n".join(f"  {s}" for s in result.signals[:5])
    message_text = (
        f"{result.emoji} <b>Havola tekshiruvi</b>\n\n"
        f"🔗 {display_url}\n"
        f"📊 Ball: {result.score}/100\n"
        f"📋 Daraja: {result.level}\n"
    )
    if result.source:
        message_text += f"🔍 Manba: {result.source}\n"
    if signals_text:
        message_text += f"\n📝 Tafsilotlar:\n{signals_text}\n"

    # Tavsiya
    if result.score >= 90:
        message_text += "\n⛔ XAVF! Bu havola juda xavfli — kirmang!"
    elif result.score >= 75:
        message_text += "\n⚠️ Bu havola xavfli. Ehtiyot bo'ling!"
    elif result.score >= 50:
        message_text += "\n⚡ Shubhali havola. Ehtiyotkor bo'ling."
    else:
        message_text += "\n✅ Bu havola xavfsiz ko'rinadi."

    await inline_query.answer(
        results=[
            types.InlineQueryResultArticle(
                id=result_id,
                title=title,
                description=description,
                input_message_content=types.InputTextMessageContent(
                    message_text=message_text,
                    parse_mode="HTML",
                ),
            )
        ],
        cache_time=300,  # 5 daqiqa cache
    )
