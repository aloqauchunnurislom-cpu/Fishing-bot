"""
languages.py — Til tizimi.
Faqat ikki variant: O'zbek lotin va O'zbek kirill.
Barcha xabarlar ikkala alifboda alohida yozilgan.
"""

# ─── Barcha xabarlar ─────────────────────────────────────────────────

TEXTS: dict[str, dict[str, str]] = {
    # ── /start buyrug'i ──────────────────────────────────────────
    "start": {
        "latin": (
            "🛡 <b>Anti-Phishing Bot</b>\n\n"
            "Salom! Men sizni phishing havolalardan himoya qilaman.\n\n"
            "📌 <b>Imkoniyatlar:</b>\n"
            "• Havolani yuboring — tezkor tekshiraman\n"
            "• Guruhga qo'shing — avtomatik himoya\n"
            "• Inline rejimda istalgan chatda tekshiring\n\n"
            "🌐 O'zbek lotin va kirill alifbosida ishlaydi.\n"
            "🇺🇿 O'zbekiston uchun maxsus ishlab chiqilgan.\n\n"
            "📝 Buyruqlar: /help"
        ),
        "cyrillic": (
            "🛡 <b>Анти-Фишинг Бот</b>\n\n"
            "Салом! Мен сизни фишинг ҳаволалардан ҳимоя қиламан.\n\n"
            "📌 <b>Имкониятлар:</b>\n"
            "• Ҳаволани юборинг — тезкор текширамман\n"
            "• Гуруҳга қўшинг — автоматик ҳимоя\n"
            "• Инлайн режимда исталган чатда текширинг\n\n"
            "🌐 Ўзбек лотин ва кирилл алифбосида ишлайди.\n"
            "🇺🇿 Ўзбекистон учун махсус ишлаб чиқилган.\n\n"
            "📝 Буйруқлар: /help"
        ),
    },

    # ── /help buyrug'i ───────────────────────────────────────────
    "help": {
        "latin": (
            "📖 <b>Yordam</b>\n\n"
            "🔗 <b>Havola tekshirish:</b>\n"
            "Menga istalgan havolani yuboring yoki /scan buyrug'i bilan:\n"
            "<code>/scan https://misol.uz</code>\n\n"
            "👥 <b>Guruhda ishlatish:</b>\n"
            "1. Botni guruhga admin qilib qo'shing\n"
            "2. /scan_on — skanerlashni yoqish\n"
            "3. Bot avtomatik xavfli havolalarni aniqlaydi\n\n"
            "⚙️ <b>Admin buyruqlari:</b>\n"
            "/scan_on — Skanerlashni yoqish\n"
            "/scan_off — O'chirish\n"
            "/strict_mode on/off — Qattiq rejim\n"
            "/stats — Bugungi statistika\n\n"
            "🌐 <b>Til:</b>\n"
            "/lang_latin — Lotin alifbosi\n"
            "/lang_cyrillic — Кирилл алифбоси\n\n"
            "🔍 <b>Inline rejim:</b>\n"
            "Istalgan chatda @botismi havola yozing"
        ),
        "cyrillic": (
            "📖 <b>Ёрдам</b>\n\n"
            "🔗 <b>Ҳавола текшириш:</b>\n"
            "Менга исталган ҳаволани юборинг ёки /scan буйруғи билан:\n"
            "<code>/scan https://мисол.уз</code>\n\n"
            "👥 <b>Гуруҳда ишлатиш:</b>\n"
            "1. Ботни гуруҳга админ қилиб қўшинг\n"
            "2. /scan_on — сканерлашни ёқиш\n"
            "3. Бот автоматик хавфли ҳаволаларни аниқлайди\n\n"
            "⚙️ <b>Админ буйруқлари:</b>\n"
            "/scan_on — Сканерлашни ёқиш\n"
            "/scan_off — Ўчириш\n"
            "/strict_mode on/off — Қаттиқ режим\n"
            "/stats — Бугунги статистика\n\n"
            "🌐 <b>Тил:</b>\n"
            "/lang_latin — Lotin alifbosi\n"
            "/lang_cyrillic — Кирилл алифбоси\n\n"
            "🔍 <b>Инлайн режим:</b>\n"
            "Исталган чатда @ботисми ҳавола ёзинг"
        ),
    },

    # ── Scan natijalari ──────────────────────────────────────────
    "scan_title": {
        "latin": "HAVOLA TEKSHIRUVI",
        "cyrillic": "ҲАВОЛА ТЕКШИРУВИ",
    },
    "final_url": {
        "latin": "Yakuniy URL",
        "cyrillic": "Якуний URL",
    },
    "score": {
        "latin": "Ball",
        "cyrillic": "Балл",
    },
    "level": {
        "latin": "Daraja",
        "cyrillic": "Даража",
    },
    "source": {
        "latin": "Manba",
        "cyrillic": "Манба",
    },
    "details": {
        "latin": "Tafsilotlar",
        "cyrillic": "Тафсилотлар",
    },

    # ── Daraja nomlari ───────────────────────────────────────────
    "level_safe": {
        "latin": "Xavfsiz",
        "cyrillic": "Хавфсиз",
    },
    "level_low": {
        "latin": "Past xavf",
        "cyrillic": "Паст хавф",
    },
    "level_medium": {
        "latin": "O'rtacha xavf",
        "cyrillic": "Ўртача хавф",
    },
    "level_high": {
        "latin": "Yuqori xavf",
        "cyrillic": "Юқори хавф",
    },
    "level_critical": {
        "latin": "Juda xavfli!",
        "cyrillic": "Жуда хавфли!",
    },

    # ── Tavsiyalar ───────────────────────────────────────────────
    "advice_safe": {
        "latin": "Bu havola xavfsiz ko'rinadi. Ammo ehtiyot bo'ling!",
        "cyrillic": "Бу ҳавола хавфсиз кўринади. Аммо эҳтиёт бўлинг!",
    },
    "advice_low": {
        "latin": "Biroz shubhali belgilar bor. Diqqat bilan kiring.",
        "cyrillic": "Бироз шубҳали белгилар бор. Диққат билан киринг.",
    },
    "advice_medium": {
        "latin": "Bu havola shubhali! Agar bilmasangiz — kirmang.",
        "cyrillic": "Бу ҳавола шубҳали! Агар билмасангиз — кирманг.",
    },
    "advice_high": {
        "latin": "Do'stim, bu havola xavfli! Shaxsiy ma'lumot kiritmang!",
        "cyrillic": "Дўстим, бу ҳавола хавфли! Шахсий маълумот киритманг!",
    },
    "advice_critical": {
        "latin": "XAVF! Bu havola 100% phishing/malware. Hech qachon kirmang! Karta, parol kiritmang!",
        "cyrillic": "ХАВФ! Бу ҳавола 100% фишинг/малваре. Ҳеч қачон кирманг! Карта, парол киритманг!",
    },

    # ── Guruh xabarlari ──────────────────────────────────────────
    "group_warning": {
        "latin": "OGOHLANTIRISH: Shubhali havola aniqlandi!",
        "cyrillic": "ОГОҲЛАНТИРИШ: Шубҳали ҳавола аниқланди!",
    },
    "group_advice": {
        "latin": "Bu havolaga kirmang va shaxsiy ma'lumot kiritmang!",
        "cyrillic": "Бу ҳаволага кирманг ва шахсий маълумот киритманг!",
    },
    "message_deleted": {
        "latin": "⛔ Xavfli havola aniqlandi va xabar o'chirildi.",
        "cyrillic": "⛔ Хавфли ҳавола аниқланди ва хабар ўчирилди.",
    },

    # ── Tekshiruv jarayoni ───────────────────────────────────────
    "checking": {
        "latin": "🔍 Havola tekshirilmoqda...",
        "cyrillic": "🔍 Ҳавола текширилмоқда...",
    },
    "no_url": {
        "latin": "❌ Havola topilmadi. Iltimos, to'g'ri URL yuboring.",
        "cyrillic": "❌ Ҳавола топилмади. Илтимос, тўғри URL юборинг.",
    },

    # ── Admin xabarlari ──────────────────────────────────────────
    "scan_enabled": {
        "latin": "✅ Skanerlash yoqildi!",
        "cyrillic": "✅ Сканерлаш ёқилди!",
    },
    "scan_disabled": {
        "latin": "⏸ Skanerlash o'chirildi.",
        "cyrillic": "⏸ Сканерлаш ўчирилди.",
    },
    "strict_on": {
        "latin": "🔒 Qattiq rejim yoqildi (87+ ball = o'chirish).",
        "cyrillic": "🔒 Қаттиқ режим ёқилди (87+ балл = ўчириш).",
    },
    "strict_off": {
        "latin": "🔓 Qattiq rejim o'chirildi.",
        "cyrillic": "🔓 Қаттиқ режим ўчирилди.",
    },
    "not_admin": {
        "latin": "❌ Bu buyruq faqat adminlar uchun.",
        "cyrillic": "❌ Бу буйруқ фақат админлар учун.",
    },

    # ── Statistika ───────────────────────────────────────────────
    "stats_title": {
        "latin": "📊 Bugungi statistika",
        "cyrillic": "📊 Бугунги статистика",
    },
    "stats_checked": {
        "latin": "Tekshirilgan",
        "cyrillic": "Текширилган",
    },
    "stats_dangerous": {
        "latin": "Xavfli",
        "cyrillic": "Хавфли",
    },
    "stats_deleted": {
        "latin": "O'chirilgan",
        "cyrillic": "Ўчирилган",
    },

    # ── Til tanlash ──────────────────────────────────────────────
    "lang_set_latin": {
        "latin": "🌐 Til: Lotin alifbosi tanlandi.",
        "cyrillic": "🌐 Til: Lotin alifbosi tanlandi.",
    },
    "lang_set_cyrillic": {
        "latin": "🌐 Тил: Кирилл алифбоси танланди.",
        "cyrillic": "🌐 Тил: Кирилл алифбоси танланди.",
    },
}


def get_text(key: str, lang: str = "latin") -> str:
    """
    Kalit bo'yicha xabar matnini olish.
    key: xabar kaliti (masalan: "start", "help", "level_safe")
    lang: "latin" yoki "cyrillic"
    """
    entry = TEXTS.get(key, {})
    if isinstance(entry, dict):
        return entry.get(lang, entry.get("latin", f"[{key}]"))
    return str(entry)
