"""
prefilter.py — 1-QATLAM (KUCHAYTIRILGAN)
Whitelist, kalit so'z, gomografik tahlil, qisqa link, shubhali pattern.
Domen tuzilmasi, URL path tahlili, yil/raqam patternlari.
API chaqirmasdan tezkor tekshirish.
"""

import json
import re
from urllib.parse import urlparse, unquote
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

# ─── URL path (yo'l) da ko'p uchraydigan phishing so'zlari ──────────
PHISHING_PATH_WORDS = {
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "update", "confirm", "account", "wallet",
    "banking", "bank", "payment", "pay", "cash", "money", "prize",
    "bonus", "gift", "reward", "claim", "redeem", "offer",
    "free", "win", "winner", "lucky", "lottery", "promo",
    "alert", "warning", "suspend", "locked", "limit", "urgent",
    "password", "passwd", "credential", "identity", "reset",
    "restore", "recover", "support", "helpdesk",
}

# ─── Shubhali so'zlar (domen nomida) ────────────────────────────────
SUSPICIOUS_DOMAIN_WORDS = {
    "yutuq", "sovga", "mukofot", "prize", "bonus", "reward",
    "free", "lucky", "omadli", "bepul", "tekin", "kredit",
    "lottery", "cash", "money", "secure", "verify", "login",
    "update", "official", "support", "helpdesk", "wallet",
    "banking", "payment", "invest", "daromad", "millioner",
    "hamyon", "karta", "winner", "gift", "promo",
}


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
        path = unquote(parsed.path or "").lower()
        query = unquote(parsed.query or "").lower()
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

        # ── 3. Kalit so'z tekshiruvi (kuchaytirilgan) ────────────
        kw_score, kw_signals = self._check_keywords(full_text)
        score += kw_score
        signals.extend(kw_signals)

        # ── 4. Qisqa link aniqlash ───────────────────────────────
        is_shortener = self._is_shortener(domain)
        if is_shortener:
            score += 15
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

        # ── 8. YANGI: Domen tuzilmasi tahlili ────────────────────
        domain_score, domain_signals = self._check_domain_structure(domain)
        score += domain_score
        signals.extend(domain_signals)

        # ── 9. YANGI: URL path tahlili ───────────────────────────
        path_score, path_signals = self._check_path_keywords(path, query)
        score += path_score
        signals.extend(path_signals)

        # ── 10. YANGI: Domen nomi ichidagi shubhali so'zlar ─────
        dw_score, dw_signals = self._check_domain_words(domain)
        score += dw_score
        signals.extend(dw_signals)

        # ── 11. YANGI: Kombinatsion hujum aniqlash ───────────────
        combo_score, combo_signals = self._check_combo_attack(
            domain, path, kw_score, domain_score, tld_score
        )
        score += combo_score
        signals.extend(combo_signals)

        # Yakuniy eslatma
        if score >= 60:
            note = "XAVFLI belgilar aniqlandi"
        elif score >= 30:
            note = "Shubhali belgilar aniqlandi"
        else:
            note = "Tekshirilmoqda"

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
            return 35, [f"⚠️ Gomografik hujum aniqlandi: {detail}"]
        if has_cyrillic and not has_latin:
            return 25, ["⚠️ To'liq kirill domen — shubhali"]
        return 0, []

    def _check_keywords(self, text: str) -> tuple[int, list[str]]:
        """Xabar va URL da phishing kalit so'zlar bormi (KUCHAYTIRILGAN)."""
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
            # KUCHAYTIRILGAN: har bir so'z uchun +8 (avval +4 edi)
            # 1 so'z = +8, 2 so'z = +16, 3+ = +24 min
            score = min(len(found) * 8, 48)

            # Agar "yutuq", "priz", "g'olib" kabi juda xavfli so'z bo'lsa — qo'shimcha ball
            high_risk_words = {
                "yutuq", "priz", "g'olib", "mukofot", "sovg'a", "bepul",
                "tekin", "prezident yordami", "davlat yordami", "moliyaviy yordam",
                "hisobingiz xavf ostida", "kartani bloklash", "sud xabarnomasi",
                "sud chaqiruvi", "sud qarori", "ютуқ", "мукофот", "совға",
                "бепул", "текин", "президент ёрдами", "давлат ёрдами",
            }
            high_risk_found = [w for w in found if w in high_risk_words]
            if high_risk_found:
                score += len(high_risk_found) * 10
                signals.append(
                    f"🚨 Juda xavfli so'zlar: {', '.join(high_risk_found[:3])}"
                )

            preview = ", ".join(found[:5])
            signals.append(f"🔑 Phishing kalit so'zlar: {preview}")

        # Malware nomlari (jiddiyroq)
        for name in self.malware_names:
            if name in text:
                score += 25
                signals.append(f"🦠 Ma'lum malware nomi: {name}")

        return score, signals

    def _check_brand_patterns(self, url: str) -> tuple[int, list[str]]:
        """O'zbek brend nomi taqlid qilinayotganini tekshirish."""
        score = 0
        signals: list[str] = []
        url_lower = url.lower()

        for pattern in UZ_BRAND_PATTERNS:
            if re.search(pattern, url_lower):
                score += 25  # Avval 15 edi
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
            ".rest", ".fit", ".surf", ".life",
            ".site", ".online", ".store", ".shop",
        }
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return 15, [f"🌐 Shubhali TLD: {tld}"]
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

    # ─── YANGI METODLAR ──────────────────────────────────────────────

    def _check_domain_structure(self, domain: str) -> tuple[int, list[str]]:
        """
        Domen tuzilmasini tahlil qilish:
        - Yil raqamlari (2024, 2025, 2026...)
        - Haddan tashqari ko'p tire (-) belgilari
        - Juda uzun domen nomi
        - Raqam va harf aralashmasi
        """
        score = 0
        signals: list[str] = []

        # Yil raqamlarini aniqlash (2020-2030)
        year_match = re.search(r"20[2-3][0-9]", domain)
        if year_match:
            score += 20
            signals.append(f"📅 Domen ichida yil raqami: {year_match.group()}")

        # Haddan tashqari ko'p tire
        hyphen_count = domain.count("-")
        if hyphen_count >= 3:
            score += 15
            signals.append(f"➖ Haddan tashqari ko'p tire ({hyphen_count} ta)")
        elif hyphen_count >= 2:
            score += 8

        # Juda uzun subdomen
        parts = domain.split(".")
        longest_part = max(len(p) for p in parts) if parts else 0
        if longest_part > 25:
            score += 12
            signals.append(f"📏 Juda uzun domen nomi ({longest_part} belgi)")

        # Ko'p subdomenlari bor (3+ qatlam)
        if len(parts) >= 4:
            score += 10
            signals.append(f"🔗 Ko'p subdomenlari bor ({len(parts)} qatlam)")

        # Raqamli fragment — domen nomlari orasida ko'p raqam (noma'lum saytlar)
        name_part = parts[0] if parts else domain
        digit_ratio = sum(c.isdigit() for c in name_part) / max(len(name_part), 1)
        if digit_ratio > 0.4 and len(name_part) > 5:
            score += 10
            signals.append("🔢 Domen nomida ko'p raqamlar")

        return score, signals

    def _check_path_keywords(self, path: str, query: str) -> tuple[int, list[str]]:
        """URL yo'l (path) va query dagi shubhali so'zlarni aniqlash."""
        score = 0
        signals: list[str] = []
        found_words: list[str] = []

        full_path = f"{path} {query}".lower()
        # Path segmentlarini ajratish
        segments = re.split(r"[/\-_?&=.]", full_path)

        for segment in segments:
            segment = segment.strip()
            if segment in PHISHING_PATH_WORDS:
                found_words.append(segment)

        if found_words:
            score = min(len(found_words) * 8, 32)
            preview = ", ".join(found_words[:5])
            signals.append(f"🛤️ URL yo'lida shubhali so'zlar: {preview}")

        return score, signals

    def _check_domain_words(self, domain: str) -> tuple[int, list[str]]:
        """Domen nomi ichidagi shubhali so'zlarni aniqlash."""
        score = 0
        signals: list[str] = []
        found_words: list[str] = []

        # Domen nomini tire va nuqtalar bo'yicha ajratish
        segments = re.split(r"[.\-]", domain)

        for segment in segments:
            segment_lower = segment.lower()
            if segment_lower in SUSPICIOUS_DOMAIN_WORDS:
                found_words.append(segment_lower)

        if len(found_words) >= 2:
            # Ikki yoki undan ko'p shubhali so'z — juda xavfli
            score = 30
            preview = ", ".join(found_words[:4])
            signals.append(f"🚨 Domen nomida bir nechta shubhali so'z: {preview}")
        elif len(found_words) == 1:
            score = 12
            signals.append(f"⚠️ Domen nomida shubhali so'z: {found_words[0]}")

        return score, signals

    def _check_combo_attack(
        self,
        domain: str,
        path: str,
        kw_score: int,
        domain_score: int,
        tld_score: int,
    ) -> tuple[int, list[str]]:
        """
        Kombinatsion hujumni aniqlash — bir nechta kuchsiz signal
        birgalikda kuchli xavf belgisiga aylanadi.
        Masalan: shubhali TLD + URL dagi kalit so'z + domen ichida yil
        """
        score = 0
        signals: list[str] = []
        danger_factors = 0

        if kw_score > 0:
            danger_factors += 1
        if domain_score > 0:
            danger_factors += 1
        if tld_score > 0:
            danger_factors += 1

        # Noma'lum TLD + kalit so'z + shubhali domen = juda xavfli
        if danger_factors >= 3:
            score += 25
            signals.append("🔥 Kombinatsion hujum: bir nechta xavf belgilari birgalikda aniqlandi")
        elif danger_factors >= 2:
            score += 15
            signals.append("⚡ Bir nechta shubhali omillar birgalikda aniqlandi")

        return score, signals
