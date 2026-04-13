"""
apis.py — 5-QATLAM
Google Safe Browsing → VirusTotal → IPQS zanjiri.
Oldingi API xavfli desa keyingisi chaqirilmaydi.
"""

import asyncio
import logging
import time
from typing import NamedTuple

import aiohttp

from config import (
    GOOGLE_SAFE_BROWSING_KEY,
    VIRUSTOTAL_API_KEY,
    IPQS_API_KEY,
    VT_RATE_PER_MINUTE,
    IPQS_RATE_PER_DAY,
)

logger = logging.getLogger(__name__)


class APIResult(NamedTuple):
    score: int
    signals: list[str]
    source: str  # Qaysi API aniqladi


class APIChecker:
    """Tashqi API lar bilan tekshirish — zanjir tartibda."""

    def __init__(self):
        # Rate limiting
        self._vt_timestamps: list[float] = []
        self._ipqs_count_today = 0
        self._ipqs_day = 0

    async def check(self, url: str) -> APIResult:
        """
        URL ni 3 ta API dan ketma-ket tekshirish.
        Birinchi xavfli natija topilsa — qolganlar o'tkazib yuboriladi.
        """
        total_score = 0
        all_signals: list[str] = []
        source = ""

        # ── 1. Google Safe Browsing ──────────────────────────────
        if GOOGLE_SAFE_BROWSING_KEY:
            gsb_result = await self._check_gsb(url)
            if gsb_result:
                total_score += gsb_result.score
                all_signals.extend(gsb_result.signals)
                if gsb_result.score >= 50:
                    source = gsb_result.source
                    return APIResult(total_score, all_signals, source)
                source = gsb_result.source

        # ── 2. VirusTotal ────────────────────────────────────────
        if VIRUSTOTAL_API_KEY and self._vt_rate_ok():
            vt_result = await self._check_virustotal(url)
            if vt_result:
                total_score += vt_result.score
                all_signals.extend(vt_result.signals)
                if vt_result.score >= 40:
                    source = source or vt_result.source
                    return APIResult(total_score, all_signals, source)
                if not source:
                    source = vt_result.source

        # ── 3. IPQS ─────────────────────────────────────────────
        if IPQS_API_KEY and self._ipqs_rate_ok():
            ipqs_result = await self._check_ipqs(url)
            if ipqs_result:
                total_score += ipqs_result.score
                all_signals.extend(ipqs_result.signals)
                if not source:
                    source = ipqs_result.source

        return APIResult(total_score, all_signals, source or "API")

    # ─── Google Safe Browsing ────────────────────────────────────────

    async def _check_gsb(self, url: str) -> APIResult | None:
        """Google Safe Browsing Lookup API v4."""
        api_url = (
            "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={GOOGLE_SAFE_BROWSING_KEY}"
        )
        payload = {
            "client": {"clientId": "antiphish-bot", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    api_url, json=payload, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        matches = data.get("matches", [])
                        if matches:
                            threat_type = matches[0].get("threatType", "UNKNOWN")
                            score = 60
                            signal = f"🔴 Google Safe Browsing: {threat_type}"
                            return APIResult(score, [signal], "GSB")
                        return APIResult(0, [], "GSB")
                    else:
                        logger.warning("GSB API xatolik: status=%d", resp.status)
                        return None
        except Exception as e:
            logger.error("GSB API Exception: %s", e)
            return None

    # ─── VirusTotal ──────────────────────────────────────────────────

    async def _check_virustotal(self, url: str) -> APIResult | None:
        """VirusTotal URL scan natijasi."""
        import base64

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    api_url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    self._vt_timestamps.append(time.time())
                    if resp.status == 200:
                        data = await resp.json()
                        stats = (
                            data.get("data", {})
                            .get("attributes", {})
                            .get("last_analysis_stats", {})
                        )
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        total_bad = malicious + suspicious

                        if total_bad >= 5:
                            return APIResult(
                                50,
                                [f"🔴 VirusTotal: {total_bad} antivirus aniqladi"],
                                "VT",
                            )
                        elif total_bad >= 1:
                            return APIResult(
                                30,
                                [f"🟡 VirusTotal: {total_bad} antivirus shubhalanmoqda"],
                                "VT",
                            )
                        return APIResult(0, [], "VT")
                    elif resp.status == 404:
                        # URL hali VT da scan qilinmagan
                        return APIResult(0, [], "VT")
                    else:
                        logger.warning("VT API xatolik: status=%d", resp.status)
                        return None
        except Exception as e:
            logger.error("VT API Exception: %s", e)
            return None

    # ─── IPQS ────────────────────────────────────────────────────────

    async def _check_ipqs(self, url: str) -> APIResult | None:
        """IPQualityScore URL reputation check."""
        import urllib.parse

        encoded = urllib.parse.quote(url, safe="")
        api_url = (
            f"https://ipqualityscore.com/api/json/url/{IPQS_API_KEY}/{encoded}"
        )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    api_url, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    self._ipqs_count_today += 1
                    if resp.status == 200:
                        data = await resp.json()
                        if not data.get("success", False):
                            return None

                        fraud_score = data.get("risk_score", 0)
                        phishing = data.get("phishing", False)
                        malware = data.get("malware", False)

                        score = 0
                        signals: list[str] = []

                        if fraud_score >= 80:
                            score += 40
                            signals.append(
                                f"🔴 IPQS fraud score: {fraud_score}/100"
                            )
                        elif fraud_score >= 50:
                            score += 20
                            signals.append(
                                f"🟡 IPQS fraud score: {fraud_score}/100"
                            )

                        if phishing:
                            score += 25
                            signals.append("🔴 IPQS: Phishing aniqlandi")
                        if malware:
                            score += 25
                            signals.append("🔴 IPQS: Malware aniqlandi")

                        return APIResult(score, signals, "IPQS")
                    else:
                        logger.warning("IPQS API xatolik: status=%d", resp.status)
                        return None
        except Exception as e:
            logger.error("IPQS API Exception: %s", e)
            return None

    # ─── Rate Limiting ───────────────────────────────────────────────

    def _vt_rate_ok(self) -> bool:
        """VirusTotal minutlik limit tekshirish."""
        now = time.time()
        # 1 daqiqa ichidagi so'rovlarni saqlash
        self._vt_timestamps = [t for t in self._vt_timestamps if now - t < 60]
        return len(self._vt_timestamps) < VT_RATE_PER_MINUTE

    def _ipqs_rate_ok(self) -> bool:
        """IPQS kunlik limit tekshirish."""
        from datetime import date
        today = date.today().toordinal()
        if self._ipqs_day != today:
            self._ipqs_day = today
            self._ipqs_count_today = 0
        return self._ipqs_count_today < IPQS_RATE_PER_DAY
