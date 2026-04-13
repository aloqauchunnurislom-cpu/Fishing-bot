"""
prefilter.py — 1-QATLAM
Whitelist, kalit so'z, gomografik tahlil, qisqa link, shubhali pattern.
API chaqirmasdan tezkor tekshirish.
"""

import json
import re
from urllib.parse import urlparse
from typing import NamedTuple

from config import WHITELIST_PATH, KEYWORDS_PATH


class PreFilterResult(NamedTuple):
    score: int
    signals: list[str]
    is_whitelisted: bool
    is_shortener: bool
    final_note: str


# ─── Gomografik xarita — Kirill → Lotin vizual o'xshash juftliklar ──
HOMOGLYPH_MAP: dict[str, str] = {
    "\u0430": "a",   # а → a
    "\u0435": "e",   # е → e
    "\u043e": "o",   # о → o
    "\u0440": "p",   # р → p
    "\u0441": "c",   # с → c
    "\u0445": "x",   # х → x
    "\u0443": "y",   # у → y
    "\u041a": "K",   # К → K
    "\u041c": "M",   # М → M
    "\u0422": "T",   # Т → T
    "\u041d": "H",   # Н → H
    "\u0412": "B",   # В → B
    "\u0410": "A",   # А → A
    "\u0415": "E",   # Е → E
    "\u041e": "O",   # О → O
    "\u0420": "P",   # Р → P
    "\u0421": "C",   # С → C
    "\u0425": "X",   # Х → X
    "\u0423": "Y",   # У → Y
    "\u0456": "i",   # і → i (Ukrainian i)
    "\u0406": "I",   # І → I
    "\u04bb": "h",   # һ → h
    "\u049b": "k",   # қ → k (misused)
    "\u0493": "g",   # ғ → g (misused)
}

# ─── Qisqa link domenlari ────────────────────────────────────────────
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "clck.ru", "is.gd", "v.gd", "buff.ly",
    "lnkd.in", "fb.me", "amzn.to", "youtu.be", "shor.by",
    "cutt.ly", "rebrand.ly", "tiny.cc", "shorturl.at",
    "rb.gy", "qps.ru", "u.to", "s.id", "t.ly",
    "clicky.me", "shorte.st", "adf.ly", "bc.vc",
    "ouo.io", "za.gl", "exe.io", "link.tl",
}

# ─── O'zbek brend taqlidi patternlari ────────────────────────────────
UZ_BRAND_PATTERNS = [
    r"kapitalbank[^.]",
    r"uzcard[^.]",
    r"humo[^.]",
    r"click[^.].*\.(?!uz)",
    r"payme[^.].*\.(?!uz)",
    r"\.uz\.(ru|com|xyz|net|org|info|top|tk|ml|ga|cf|gq)",
    r"uz-official",
    r"gov-uz",
    r"click-uz",
    r"payme-verify",
    r"uzcard-login",
    r"humo-update",
    r"click.*official",
    r"payme.*bonus",
    r"uzcard.*free",
]


class PreFilter:
    """Tezkor (0ms) prefilter — API ga bormasdan shubha darajasini aniqlaydi."""

    def __init__(self):
        self.whitelist: set[str] = set()
        self.keywords_latin: list[str] = []
        self.keywords_cyrillic: list[str] = []
        self.apk_patterns: list[str] = []
        self.malware_names: list[str] = []
        self._load_data()

    def _load_data(self):
        """JSON fayllardan ma'lumotlarni RAM ga yuklash."""
        # Whitelist
        try:
            with open(WHITELIST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.whitelist = set(data.get("trusted_domains", []))
        except (FileNotFoundError, json.JSONDecodeError):
            self.whitelist = set()

        # Kalit so'zlar
        try:
            with open(KEYWORDS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.keywords_latin = data.get("latin", [])
                self.keywords_cyrillic = data.get("cyrillic", [])
                self.apk_patterns = data.get("suspicious_apk_patterns", [])
                self.malware_names = data.get("malware_names", [])
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def check(self, url: str, message_text: str = "") -> PreFilterResult:
        """
        URL va xabar matnini prefilter dan o'tkazish.
        Return: PreFilterResult(score, signals, is_whitelisted, is_shortener, note)
        """
        score = 0
        signals: list[str] = []
        parsed = urlparse(url if "://" in url else f"https://{url}")
        domain = (parsed.hostname or "").lower().strip(".")
        full_text = f"{url} {message_text}".lower()

        # ── 1. Whitelist tekshiruvi ──────────────────────────────
        if self._is_whitelisted(domain):
            return PreFilterResult(
                score=-100,
                signals=["✅ Ishonchli domen (whitelist)"],
                is_whitelisted=True,
                is_shortener=False,
                final_note="Xavfsiz",
            )

        # ── 2. Gomografik tahlil ─────────────────────────────────
        homo_score, homo_signals = self._check_homoglyph(domain)
        score += homo_score
        signals.extend(homo_signals)

        # ── 3. Kalit so'z tekshiruvi ─────────────────────────────
        kw_score, kw_signals = self._check_keywords(full_text)
        score += kw_score
        signals.extend(kw_signals)

        # ── 4. Qisqa link aniqlash ──────────────────────────────
        is_shortener = self._is_shortener(domain)
        if is_shortener:
            score += 10
            signals.append("🔗 Qisqa link aniqlandi — redirect tekshirilmoqda")

        # ── 5. O'zbek brend taqlidi ──────────────────────────────
        brand_score, brand_signals = self._check_brand_patterns(url)
        score += brand_score
        signals.extend(brand_signals)

        # ── 6. Shubhali TLD ──────────────────────────────────────
        tld_score, tld_signals = self._check_suspicious_tld(domain)
        score += tld_score
        signals.extend(tld_signals)

        # ── 7. APK pattern ───────────────────────────────────────
        apk_score, apk_signals = self._check_apk(full_text)
        score += apk_score
        signals.extend(apk_signals)

        # Yakuniy eslatma
        note = "Tekshirilmoqda" if score < 30 else "Shubhali belgilar aniqlandi"
        return PreFilterResult(
            score=max(score, 0),
            signals=signals,
            is_whitelisted=False,
            is_shortener=is_shortener,
            final_note=note,
        )

    # ─── Yordamchi metodlar ───────────────────────────────────────────

    def _is_whitelisted(self, domain: str) -> bool:
        """Domen yoki uning ota-domeni whitelist da bormi."""
        if domain in self.whitelist:
            return True
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.whitelist:
                return True
        return False

    def _is_shortener(self, domain: str) -> bool:
        """Domen qisqartiruvchi servismi."""
        return domain in SHORTENER_DOMAINS

    def _check_homoglyph(self, domain: str) -> tuple[int, list[str]]:
        """
        Domen ichida kirill va lotin harflar aralashganmi tekshirish.
        Masalan: "uzсard.com" (с — kirill) → gomografik hujum.
        """
        has_latin = False
        has_cyrillic = False
        suspicious_chars: list[str] = []

        for ch in domain:
            if ch in ".-0123456789":
                continue
            if ch in HOMOGLYPH_MAP:
                has_cyrillic = True
                suspicious_chars.append(
                    f"'{ch}' (kirill) → '{HOMOGLYPH_MAP[ch]}' (lotin)"
                )
            elif "a" <= ch <= "z" or "A" <= ch <= "Z":
                has_latin = True

        if has_latin and has_cyrillic:
            detail = ", ".join(suspicious_chars[:3])
            return 20, [f"⚠️ Gomografik hujum aniqlandi: {detail}"]
        if has_cyrillic and not has_latin:
            return 15, ["⚠️ To'liq kirill domen — shubhali"]
        return 0, []

    def _check_keywords(self, text: str) -> tuple[int, list[str]]:
        """Xabar va URL da phishing kalit so'zlar bormi."""
        score = 0
        signals: list[str] = []
        found: list[str] = []

        for kw in self.keywords_latin:
            if kw in text:
                found.append(kw)
        for kw in self.keywords_cyrillic:
            if kw in text:
                found.append(kw)

        if found:
            score = min(len(found) * 4, 24)  # Har biri +4, maks +24
            preview = ", ".join(found[:5])
            signals.append(f"🔑 Phishing kalit so'zlar: {preview}")

        # Malware nomlari (jiddiyroq)
        for name in self.malware_names:
            if name in text:
                score += 15
                signals.append(f"🦠 Ma'lum malware nomi: {name}")

        return score, signals

    def _check_brand_patterns(self, url: str) -> tuple[int, list[str]]:
        """O'zbek brend nomi taqlid qilinayotganini tekshirish."""
        score = 0
        signals: list[str] = []
        url_lower = url.lower()

        for pattern in UZ_BRAND_PATTERNS:
            if re.search(pattern, url_lower):
                score += 15
                signals.append(f"🏦 O'zbek brend taqlidi: {pattern[:30]}")
                break  # Birinchi topilganda yetarli

        return score, signals

    def _check_suspicious_tld(self, domain: str) -> tuple[int, list[str]]:
        """Xavfli TLD lar (bepul domenlar ko'pincha phishing uchun ishlatiladi)."""
        suspicious_tlds = {
            ".tk", ".ml", ".ga", ".cf", ".gq",
            ".xyz", ".top", ".work", ".click",
            ".icu", ".buzz", ".monster",
            ".loan", ".racing", ".win",
        }
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return 12, [f"🌐 Shubhali TLD: {tld}"]
        return 0, []

    def _check_apk(self, text: str) -> tuple[int, list[str]]:
        """Shubhali APK pattern larni aniqlash."""
        score = 0
        signals: list[str] = []

        for pattern in self.apk_patterns:
            if pattern in text:
                score += 25
                signals.append(f"📱 Shubhali APK aniqlandi: {pattern}")
                break

        # Double extension (eng xavfli)
        double_ext = re.search(r"\.\w{2,4}\.apk", text)
        if double_ext:
            score += 30
            signals.append(
                f"⚠️ Ikki kengaytmali APK (juda xavfli): {double_ext.group()}"
            )

        return score, signals
