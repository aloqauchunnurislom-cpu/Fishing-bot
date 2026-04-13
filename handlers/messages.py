"""
messages.py — Havola xabarlarni ushlab olish va tekshirish.
Bu botning asosiy qismi — har bir xabardagi URL larni tekshiradi.
"""

import logging

from aiogram import Router, types, F

from checker.prefilter import PreFilter
from checker.local_db import LocalDB
from checker.redirect import RedirectResolver
from checker.apis import APIChecker
from checker.scorer import Scorer, ScanResult
from cache.memory import MemoryCache
from utils.extractor import extract_urls_from_entities
from utils.languages import get_text
from utils.queue import queued_check
from config import ADMIN_IDS

logger = logging.getLogger(__name__)
router = Router()

# Global komponentlar (bot.py dan o'rnatiladi)
prefilter = PreFilter()
redirect_resolver = RedirectResolver()
api_checker = APIChecker()
scorer = Scorer()


async def _run_full_check(
    url: str,
    message_text: str,
    bot,
    strict_mode: bool = False,
) -> ScanResult | None:
    """
    URL ni barcha 6 qatlam orqali tekshirish.
    Bu funksiya /scan buyrug'i va avtomatik guruh tekshiruvidan chaqiriladi.
    """
    cache: MemoryCache = bot.__dict__.get("_cache")
    local_db: LocalDB = bot.__dict__.get("_local_db")

    # ── 0. Cache tekshirish ──────────────────────────────────────
    if cache:
        cached = cache.get(url)
        if cached:
            logger.debug("Cache hit: %s (score=%d)", url[:50], cached.score)
            return ScanResult(
                url=url,
                final_url=url,
                score=cached.score,
                level=cached.level,
                emoji="🟢" if cached.score < 25 else "🔴",
                signals=cached.signals,
                source=cached.source,
                should_delete=cached.score >= 90,
                should_warn=cached.score >= 50,
                redirect_hops=0,
            )

    # ── 1. Prefilter ─────────────────────────────────────────────
    pf = prefilter.check(url, message_text)
    if pf.is_whitelisted:
        return scorer.calculate(
            url=url,
            final_url=url,
            prefilter_score=pf.score,
            prefilter_signals=pf.signals,
            blacklist_score=0,
            blacklist_signals=[],
            redirect_score=0,
            redirect_signals=[],
            redirect_hops=0,
            api_score=0,
            api_signals=[],
            api_source="",
            strict_mode=strict_mode,
        )

    # ── 2. Oflayn blacklist ──────────────────────────────────────
    bl_score, bl_signals = 0, []
    if local_db:
        bl_score, bl_signals = local_db.check_blacklists(url)

    # Blacklist da topilsa — API ga bormasdan javob berish
    if bl_score >= 50:
        result = scorer.calculate(
            url=url, final_url=url,
            prefilter_score=pf.score, prefilter_signals=pf.signals,
            blacklist_score=bl_score, blacklist_signals=bl_signals,
            redirect_score=0, redirect_signals=[], redirect_hops=0,
            api_score=0, api_signals=[], api_source="",
            strict_mode=strict_mode,
        )
        _save_to_cache(cache, url, result)
        if local_db:
            await local_db.save_result(url, result.score, result.level, result.source)
            await local_db.increment_stats(dangerous=True)
        return result

    # ── 3. Redirect ochish ───────────────────────────────────────
    rd_score, rd_signals, rd_hops = 0, [], 0
    final_url = url

    if pf.is_shortener or pf.score >= 10:
        rd_result = await queued_check(redirect_resolver.resolve(url))
        if rd_result:
            final_url = rd_result.final_url
            rd_score = rd_result.score
            rd_signals = rd_result.signals
            rd_hops = rd_result.hop_count

            # Yakuniy URL ni yana prefilter va blacklist dan o'tkazish
            if final_url != url:
                pf2 = prefilter.check(final_url, message_text)
                if pf2.is_whitelisted:
                    pf = pf2
                else:
                    pf = pf._replace(
                        score=pf.score + pf2.score,
                        signals=pf.signals + pf2.signals,
                    )

                if local_db:
                    bl2_score, bl2_signals = local_db.check_blacklists(final_url)
                    bl_score += bl2_score
                    bl_signals.extend(bl2_signals)

    # ── 4. Oflayn blacklist yakuniy URL uchun ────────────────────
    if bl_score >= 50:
        result = scorer.calculate(
            url=url, final_url=final_url,
            prefilter_score=pf.score, prefilter_signals=pf.signals,
            blacklist_score=bl_score, blacklist_signals=bl_signals,
            redirect_score=rd_score, redirect_signals=rd_signals,
            redirect_hops=rd_hops,
            api_score=0, api_signals=[], api_source="",
            strict_mode=strict_mode,
        )
        _save_to_cache(cache, url, result)
        if local_db:
            await local_db.save_result(url, result.score, result.level, result.source)
            await local_db.increment_stats(dangerous=True)
        return result

    # ── 5. API tekshirish ────────────────────────────────────────
    api_result = await queued_check(api_checker.check(final_url))
    api_score = api_result.score if api_result else 0
    api_signals = api_result.signals if api_result else []
    api_source = api_result.source if api_result else ""

    # ── 6. Yakuniy ball hisoblash ────────────────────────────────
    result = scorer.calculate(
        url=url, final_url=final_url,
        prefilter_score=pf.score, prefilter_signals=pf.signals,
        blacklist_score=bl_score, blacklist_signals=bl_signals,
        redirect_score=rd_score, redirect_signals=rd_signals,
        redirect_hops=rd_hops,
        api_score=api_score, api_signals=api_signals,
        api_source=api_source,
        strict_mode=strict_mode,
    )

    # Natijani saqlash
    _save_to_cache(cache, url, result)
    if local_db:
        await local_db.save_result(url, result.score, result.level, result.source)
        is_dangerous = result.score >= 50
        await local_db.increment_stats(dangerous=is_dangerous)

    return result


def _save_to_cache(cache: MemoryCache | None, url: str, result: ScanResult):
    """Natijani cache ga saqlash."""
    if cache:
        cache.put(url, result.score, result.level, result.source, result.signals)


# ─── Shaxsiy chat handleri ───────────────────────────────────────────

@router.message(F.chat.type == "private")
async def handle_private_message(message: types.Message):
    """Shaxsiy chatda kelgan xabarlardan URL larni tekshirish."""
    urls = extract_urls_from_entities(message)
    if not urls:
        return  # URL bo'lmasa — e'tiborsiz qoldirish

    local_db: LocalDB = message.bot.__dict__.get("_local_db")
    lang = "latin"
    if local_db and message.from_user:
        lang = await local_db.get_user_language(message.from_user.id)

    # Status xabari
    status_msg = await message.answer(get_text("checking", lang))

    for url in urls[:3]:  # Maks 3 ta URL
        result = await _run_full_check(url, message.text or "", message.bot)
        if result:
            response = Scorer.format_private_response(result, lang)
            await message.answer(response, parse_mode="HTML")

    # Status o'chirish
    try:
        await status_msg.delete()
    except Exception:
        pass


# ─── Guruh handleri ──────────────────────────────────────────────────

@router.message(F.chat.type.in_({"group", "supergroup"}))
async def handle_group_message(message: types.Message):
    """Guruhda kelgan xabarlardan URL larni tekshirish."""
    urls = extract_urls_from_entities(message)
    if not urls:
        return

    local_db: LocalDB = message.bot.__dict__.get("_local_db")

    # Guruh sozlamalarini tekshirish
    if local_db:
        settings = await local_db.get_group_settings(message.chat.id)
        if not settings["scan_enabled"]:
            return
        strict_mode = settings["strict_mode"]
        lang = settings["language"]
    else:
        strict_mode = False
        lang = "latin"

    for url in urls[:5]:  # Guruhda maks 5 URL
        result = await _run_full_check(
            url, message.text or "", message.bot, strict_mode=strict_mode
        )

        if not result:
            continue

        # ── Xavfli — xabarni o'chirish ──────────────────────────
        if result.should_delete:
            try:
                await message.delete()
            except Exception as e:
                logger.warning("Xabar o'chirishda xatolik: %s", e)

            # Guruhga ogohlantirish
            warn_text = get_text("message_deleted", lang)
            await message.answer(warn_text)

            # Adminlarga xabar
            user_name = (
                message.from_user.full_name if message.from_user else "Noma'lum"
            )
            chat_title = message.chat.title or "Noma'lum guruh"
            admin_alert = Scorer.format_admin_alert(result, user_name, chat_title)

            for admin_id in ADMIN_IDS:
                try:
                    await message.bot.send_message(admin_id, admin_alert)
                except Exception:
                    pass

            if local_db:
                await local_db.increment_stats(dangerous=True, deleted=True)

            break  # Xabar o'chirildi — boshqa URL tekshirish shart emas

        # ── Shubhali — faqat ogohlantirish ──────────────────────
        elif result.should_warn:
            warn_text = Scorer.format_group_warning(result, lang)
            await message.reply(warn_text, parse_mode="HTML")
