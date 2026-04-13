"""
scorer.py — 6-QATLAM
Barcha qatlamlardan kelgan signallarni yig'ib, yakuniy ball va daraja berish.
"""

from typing import NamedTuple

from config import AUTO_DELETE_THRESHOLD, STRICT_MODE_THRESHOLD


class ScanResult(NamedTuple):
    url: str
    final_url: str          # Redirect ochilganidan keyingi URL
    score: int              # 0-100+
    level: str              # "safe", "low", "medium", "high", "critical"
    emoji: str              # Daraja belgisi
    signals: list[str]      # Barcha signallar ro'yxati
    source: str             # Asosiy aniqlagan manba
    should_delete: bool     # Xabarni o'chirish kerakmi
    should_warn: bool       # Ogohlantirish kerakmi
    redirect_hops: int      # Redirect soni


# ─── Daraja jadvali ──────────────────────────────────────────────────
LEVELS = [
    # (min_score, level, emoji)
    (90, "critical", "🔴"),
    (75, "high", "🟠"),
    (50, "medium", "🟡"),
    (25, "low", "🔵"),
    (0, "safe", "🟢"),
]


class Scorer:
    """
    Barcha qatlamlardan kelgan ball va signallarni birlashtiradi.
    Yakuniy ScanResult beradi.
    """

    def calculate(
        self,
        url: str,
        final_url: str,
        prefilter_score: int,
        prefilter_signals: list[str],
        blacklist_score: int,
        blacklist_signals: list[str],
        redirect_score: int,
        redirect_signals: list[str],
        redirect_hops: int,
        api_score: int,
        api_signals: list[str],
        api_source: str,
        strict_mode: bool = False,
    ) -> ScanResult:
        """
        Barcha signallarni yig'ib yakuniy natija berish.

        Args:
            strict_mode: True bo'lsa 87+ dan o'chiradi (admin buyrug'i)
        """
        # Umumiy ball
        total_score = (
            prefilter_score + blacklist_score + redirect_score + api_score
        )
        total_score = max(total_score, 0)  # 0 dan past bo'lmasin

        # Barcha signallarni birlashtirish
        all_signals = (
            prefilter_signals
            + blacklist_signals
            + redirect_signals
            + api_signals
        )

        # Asosiy aniqlagan manba
        source = api_source
        if blacklist_score >= 50:
            source = "Oflayn blacklist"
        elif prefilter_score >= 20:
            source = source or "Prefilter"

        # Daraja aniqlash
        level = "safe"
        emoji = "🟢"
        for min_score, lvl, em in LEVELS:
            if total_score >= min_score:
                level = lvl
                emoji = em
                break

        # O'chirish va ogohlantirish qarorlari
        delete_threshold = (
            STRICT_MODE_THRESHOLD if strict_mode else AUTO_DELETE_THRESHOLD
        )
        should_delete = total_score >= delete_threshold
        should_warn = total_score >= 50  # Medium va undan yuqori

        return ScanResult(
            url=url,
            final_url=final_url,
            score=total_score,
            level=level,
            emoji=emoji,
            signals=all_signals,
            source=source,
            should_delete=should_delete,
            should_warn=should_warn,
            redirect_hops=redirect_hops,
        )

    @staticmethod
    def format_private_response(result: ScanResult, lang: str = "latin") -> str:
        """Shaxsiy chat uchun batafsil javob formatlash."""
        from utils.languages import get_text

        lines: list[str] = []

        # Sarlavha
        lines.append(f"{result.emoji} {get_text('scan_title', lang)}")
        lines.append("")

        # URL
        display_url = result.url[:80] + ("..." if len(result.url) > 80 else "")
        lines.append(f"🔗 URL: {display_url}")

        # Agar redirect bo'lgan bo'lsa
        if result.final_url != result.url:
            final_display = result.final_url[:80] + (
                "..." if len(result.final_url) > 80 else ""
            )
            lines.append(
                f"↪️ {get_text('final_url', lang)}: {final_display}"
            )
            lines.append(
                f"🔄 Redirect: {result.redirect_hops} hop"
            )

        lines.append("")

        # Ball va daraja
        level_text = get_text(f"level_{result.level}", lang)
        lines.append(f"📊 {get_text('score', lang)}: {result.score}/100")
        lines.append(f"📋 {get_text('level', lang)}: {level_text}")

        # Manba
        if result.source:
            lines.append(f"🔍 {get_text('source', lang)}: {result.source}")

        lines.append("")

        # Signallar
        if result.signals:
            lines.append(f"📝 {get_text('details', lang)}:")
            for sig in result.signals[:8]:  # Maks 8 ta signal
                lines.append(f"  {sig}")
            lines.append("")

        # Tavsiya
        if result.level == "critical":
            lines.append(f"⛔ {get_text('advice_critical', lang)}")
        elif result.level == "high":
            lines.append(f"⚠️ {get_text('advice_high', lang)}")
        elif result.level == "medium":
            lines.append(f"⚡ {get_text('advice_medium', lang)}")
        elif result.level == "low":
            lines.append(f"ℹ️ {get_text('advice_low', lang)}")
        else:
            lines.append(f"✅ {get_text('advice_safe', lang)}")

        return "\n".join(lines)

    @staticmethod
    def format_group_warning(result: ScanResult, lang: str = "latin") -> str:
        """Guruh uchun qisqa ogohlantirish."""
        from utils.languages import get_text

        level_text = get_text(f"level_{result.level}", lang)
        return (
            f"{result.emoji} {get_text('group_warning', lang)}\n"
            f"📊 {get_text('score', lang)}: {result.score}/100 — {level_text}\n"
            f"⚠️ {get_text('group_advice', lang)}"
        )

    @staticmethod
    def format_admin_alert(
        result: ScanResult, user_name: str, chat_title: str
    ) -> str:
        """Admin uchun batafsil xabar."""
        return (
            f"🚨 XAVFLI HAVOLA O'CHIRILDI\n\n"
            f"👤 Foydalanuvchi: {user_name}\n"
            f"💬 Guruh: {chat_title}\n"
            f"🔗 URL: {result.url[:100]}\n"
            f"📊 Ball: {result.score}/100\n"
            f"🔍 Manba: {result.source}\n\n"
            f"Signallar:\n"
            + "\n".join(f"  {s}" for s in result.signals[:5])
        )
