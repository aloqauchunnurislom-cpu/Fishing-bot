"""
admin.py — Admin buyruqlari.
/scan_on, /scan_off, /strict_mode, /whitelist_add, /whitelist_remove
"""

import logging

from aiogram import Router, types
from aiogram.filters import Command

from config import ADMIN_IDS
from utils.languages import get_text

logger = logging.getLogger(__name__)
router = Router()


async def _is_group_admin(message: types.Message) -> bool:
    """Foydalanuvchi guruh admini yoki bot adminimi tekshirish."""
    if not message.from_user:
        return False

    # Bot admin ro'yxatida
    if message.from_user.id in ADMIN_IDS:
        return True

    # Guruh admini
    if message.chat.type in ("group", "supergroup"):
        try:
            member = await message.chat.get_member(message.from_user.id)
            return member.status in ("administrator", "creator")
        except Exception:
            return False

    return False


@router.message(Command("scan_on"))
async def cmd_scan_on(message: types.Message):
    """Guruhda skanerlashni yoqish."""
    if message.chat.type not in ("group", "supergroup"):
        return

    if not await _is_group_admin(message):
        local_db = message.bot.__dict__.get("_local_db")
        lang = "latin"
        if local_db:
            settings = await local_db.get_group_settings(message.chat.id)
            lang = settings["language"]
        await message.answer(get_text("not_admin", lang))
        return

    local_db = message.bot.__dict__.get("_local_db")
    if local_db:
        await local_db.set_group_scan(message.chat.id, True)
        settings = await local_db.get_group_settings(message.chat.id)
        lang = settings["language"]
    else:
        lang = "latin"

    await message.answer(get_text("scan_enabled", lang))
    logger.info("Scan yoqildi: guruh %d", message.chat.id)


@router.message(Command("scan_off"))
async def cmd_scan_off(message: types.Message):
    """Guruhda skanerlashni o'chirish."""
    if message.chat.type not in ("group", "supergroup"):
        return

    if not await _is_group_admin(message):
        lang = "latin"
        local_db = message.bot.__dict__.get("_local_db")
        if local_db:
            settings = await local_db.get_group_settings(message.chat.id)
            lang = settings["language"]
        await message.answer(get_text("not_admin", lang))
        return

    local_db = message.bot.__dict__.get("_local_db")
    if local_db:
        await local_db.set_group_scan(message.chat.id, False)
        settings = await local_db.get_group_settings(message.chat.id)
        lang = settings["language"]
    else:
        lang = "latin"

    await message.answer(get_text("scan_disabled", lang))
    logger.info("Scan o'chirildi: guruh %d", message.chat.id)


@router.message(Command("strict_mode"))
async def cmd_strict_mode(message: types.Message):
    """Qattiq rejimni yoqish/o'chirish: /strict_mode on yoki /strict_mode off"""
    if message.chat.type not in ("group", "supergroup"):
        return

    if not await _is_group_admin(message):
        lang = "latin"
        local_db = message.bot.__dict__.get("_local_db")
        if local_db:
            settings = await local_db.get_group_settings(message.chat.id)
            lang = settings["language"]
        await message.answer(get_text("not_admin", lang))
        return

    args = (message.text or "").split()
    mode = args[1].lower() if len(args) > 1 else ""

    local_db = message.bot.__dict__.get("_local_db")
    lang = "latin"

    if mode == "on":
        if local_db:
            await local_db.set_group_strict(message.chat.id, True)
            settings = await local_db.get_group_settings(message.chat.id)
            lang = settings["language"]
        await message.answer(get_text("strict_on", lang))
        logger.info("Strict mode ON: guruh %d", message.chat.id)

    elif mode == "off":
        if local_db:
            await local_db.set_group_strict(message.chat.id, False)
            settings = await local_db.get_group_settings(message.chat.id)
            lang = settings["language"]
        await message.answer(get_text("strict_off", lang))
        logger.info("Strict mode OFF: guruh %d", message.chat.id)

    else:
        await message.answer(
            "Foydalanish: <code>/strict_mode on</code> yoki <code>/strict_mode off</code>",
            parse_mode="HTML",
        )


@router.message(Command("whitelist_add"))
async def cmd_whitelist_add(message: types.Message):
    """Lokal whitelist ga domen qo'shish: /whitelist_add domen.uz"""
    if not await _is_group_admin(message) and (
        not message.from_user or message.from_user.id not in ADMIN_IDS
    ):
        await message.answer(get_text("not_admin", "latin"))
        return

    args = (message.text or "").split()
    if len(args) < 2:
        await message.answer("Foydalanish: <code>/whitelist_add domen.uz</code>", parse_mode="HTML")
        return

    domain = args[1].strip().lower()

    # Prefilter dagi whitelist ga qo'shish
    from handlers.messages import prefilter
    prefilter.whitelist.add(domain)

    await message.answer(f"✅ <code>{domain}</code> whitelist ga qo'shildi.", parse_mode="HTML")
    logger.info("Whitelist +: %s (by user %s)", domain, message.from_user.id if message.from_user else "?")


@router.message(Command("whitelist_remove"))
async def cmd_whitelist_remove(message: types.Message):
    """Whitelist dan domen o'chirish: /whitelist_remove domen.uz"""
    if not await _is_group_admin(message) and (
        not message.from_user or message.from_user.id not in ADMIN_IDS
    ):
        await message.answer(get_text("not_admin", "latin"))
        return

    args = (message.text or "").split()
    if len(args) < 2:
        await message.answer(
            "Foydalanish: <code>/whitelist_remove domen.uz</code>",
            parse_mode="HTML",
        )
        return

    domain = args[1].strip().lower()

    from handlers.messages import prefilter
    prefilter.whitelist.discard(domain)

    await message.answer(
        f"🗑 <code>{domain}</code> whitelist dan o'chirildi.",
        parse_mode="HTML",
    )
    logger.info(
        "Whitelist -: %s (by user %s)",
        domain,
        message.from_user.id if message.from_user else "?",
    )
