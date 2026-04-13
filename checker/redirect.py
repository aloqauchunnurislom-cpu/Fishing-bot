"""
redirect.py — 4-QATLAM
Qisqa link va redirect zanjirini ochish (8 hop gacha).
aiohttp HEAD request bilan tezkor ishlaydi.
"""

import logging
from typing import NamedTuple

import aiohttp

from config import MAX_REDIRECTS, REDIRECT_TIMEOUT

logger = logging.getLogger(__name__)


class RedirectResult(NamedTuple):
    final_url: str
    hop_count: int
    score: int
    signals: list[str]
    chain: list[str]  # Redirect zanjiri


class RedirectResolver:
    """URL ning yakuniy manzilini aniqlash (redirect zanjiri ochish)."""

    async def resolve(self, url: str) -> RedirectResult:
        """
        URL ni kuzatib yakuniy manzilni aniqlash.
        Har hop da HEAD request yuboriladi.
        """
        chain: list[str] = [url]
        current = url
        score = 0
        signals: list[str] = []

        try:
            timeout = aiohttp.ClientTimeout(total=REDIRECT_TIMEOUT * MAX_REDIRECTS)
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=aiohttp.TCPConnector(ssl=False),
            ) as session:
                for hop in range(MAX_REDIRECTS):
                    try:
                        async with session.head(
                            current,
                            allow_redirects=False,
                            timeout=aiohttp.ClientTimeout(total=REDIRECT_TIMEOUT),
                        ) as resp:
                            if resp.status in (301, 302, 303, 307, 308):
                                location = resp.headers.get("Location", "")
                                if not location:
                                    break

                                # Nisbiy URL ni to'liq qilish
                                if location.startswith("/"):
                                    from urllib.parse import urlparse
                                    parsed = urlparse(current)
                                    location = (
                                        f"{parsed.scheme}://{parsed.netloc}{location}"
                                    )

                                current = location
                                chain.append(current)
                            else:
                                # Redirect tugadi
                                break
                    except (aiohttp.ClientError, TimeoutError, OSError) as e:
                        logger.warning("Redirect hop #%d xatolik: %s", hop + 1, e)
                        score += 10
                        signals.append(
                            f"⚠️ Redirect #{hop + 1} xatolik — shubhali"
                        )
                        break

        except Exception as e:
            logger.error("Redirect resolver umumiy xatolik: %s", e)
            score += 10
            signals.append("⚠️ Redirect tekshirishda xatolik")

        # ── Hop soni baholash ────────────────────────────────────
        hop_count = len(chain) - 1

        if hop_count >= 4:
            extra = 15
            score += extra
            signals.append(
                f"🔄 Ko'p redirect: {hop_count} hop (shubhali)"
            )
        elif hop_count >= 2:
            signals.append(f"🔄 Redirect: {hop_count} hop")

        if hop_count >= MAX_REDIRECTS:
            score += 10
            signals.append(
                f"🔴 Maksimal redirect ({MAX_REDIRECTS}) ga yetdi!"
            )

        final_url = chain[-1] if chain else url
        return RedirectResult(
            final_url=final_url,
            hop_count=hop_count,
            score=score,
            signals=signals,
            chain=chain,
        )
