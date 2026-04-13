"""
extractor.py — Xabardan URL larni ajratib olish.
Telegram xabar matnidan barcha HTTP(S) havolalarni topadi.
"""

import re
from urllib.parse import urlparse


# URL ni topish uchun regex — HTTP(S) va yalang'och domen
_URL_PATTERN = re.compile(
    r"(?:https?://)"                         # http:// yoki https://
    r"(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}"    # domen
    r"(?::\d{1,5})?"                          # port (ixtiyoriy)
    r"(?:/[^\s<>\"\'\)\]\}]*)?"              # path (ixtiyoriy)
    r"|"                                      # YOKI
    r"(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}"    # faqat domen (http siz)
    r"(?::\d{1,5})?"
    r"(?:/[^\s<>\"\'\)\]\}]*)?",
    re.IGNORECASE,
)

# Minimal TLD lar (yalang'och domenlarni aniqlash uchun)
VALID_TLDS = {
    "com", "org", "net", "uz", "ru", "io", "me", "co",
    "info", "biz", "xyz", "top", "tk", "ml", "ga", "cf", "gq",
    "site", "online", "store", "shop", "click", "link",
    "icu", "buzz", "monster", "work", "loan", "racing", "win",
    "dev", "app", "tech", "pro",
}


def extract_urls(text: str) -> list[str]:
    """
    Xabar matnidan barcha URL larni ajratib olish.
    HTTP(S) prefiksli va yalang'och domenlarni topadi.

    Returns:
        Noyob URL lar ro'yxati (HTTP qo'shilgan holda)
    """
    if not text:
        return []

    urls: list[str] = []
    seen: set[str] = set()

    for match in _URL_PATTERN.finditer(text):
        raw = match.group().strip().rstrip(".,;:!?)")
        if not raw:
            continue

        # HTTP prefiksi yo'q bo'lsa qo'shish
        if not raw.startswith("http"):
            # TLD tekshirish
            parts = raw.split(".")
            if len(parts) >= 2:
                tld = parts[-1].split("/")[0].split(":")[0].lower()
                if tld not in VALID_TLDS:
                    continue
            raw = f"https://{raw}"

        # Takrorlanmasin
        normalized = raw.lower()
        if normalized in seen:
            continue
        seen.add(normalized)

        # Yaroqli URL mi tekshirish
        try:
            parsed = urlparse(raw)
            if parsed.hostname and "." in parsed.hostname:
                urls.append(raw)
        except Exception:
            continue

    return urls


def extract_urls_from_entities(message) -> list[str]:
    """
    Telegram xabar entities laridan URL larni olish.
    aiogram Message obyektidan ishlaydi.
    """
    urls: list[str] = []
    seen: set[str] = set()

    if not message:
        return urls

    # Matn ichidagi URL lar
    text = message.text or message.caption or ""

    # Entities lardan URL lar
    entities = message.entities or message.caption_entities or []
    for entity in entities:
        if entity.type == "url":
            url = text[entity.offset : entity.offset + entity.length]
            if not url.startswith("http"):
                url = f"https://{url}"
            norm = url.lower()
            if norm not in seen:
                seen.add(norm)
                urls.append(url)
        elif entity.type == "text_link":
            url = entity.url or ""
            if url:
                norm = url.lower()
                if norm not in seen:
                    seen.add(norm)
                    urls.append(url)

    # Matndan ham qo'shimcha URL lar
    for url in extract_urls(text):
        norm = url.lower()
        if norm not in seen:
            seen.add(norm)
            urls.append(url)

    return urls
