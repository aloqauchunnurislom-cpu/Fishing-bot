"""
config.py — Barcha sozlamalar bir joyda.
.env dan o'qiladi, default qiymatlar belgilangan.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ─── Telegram ───────────────────────────────────────────────
BOT_TOKEN = os.getenv("BOT_TOKEN", "")

# Admin foydalanuvchi ID lar (vergul bilan ajratilgan)
_admin_ids_raw = os.getenv("ADMIN_IDS", "")
ADMIN_IDS: list[int] = [
    int(x.strip()) for x in _admin_ids_raw.split(",") if x.strip().isdigit()
]

# ─── API Kalitlar ───────────────────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
IPQS_API_KEY = os.getenv("IPQS_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
CHECKPHISH_API_KEY = os.getenv("CHECKPHISH_API_KEY", "")
KPHISH_API_KEY = os.getenv("KPHISH_API_KEY", "")

# ─── Cache ──────────────────────────────────────────────────
CACHE_TTL = int(os.getenv("CACHE_TTL", "86400"))          # 24 soat
CACHE_MAX_SIZE = int(os.getenv("CACHE_MAX_SIZE", "2000"))  # Maksimal yozuv

# ─── Redirect ──────────────────────────────────────────────
MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "8"))
REDIRECT_TIMEOUT = int(os.getenv("REDIRECT_TIMEOUT", "5"))  # Har hop uchun sekund

# ─── Scorer ─────────────────────────────────────────────────
AUTO_DELETE_THRESHOLD = int(os.getenv("AUTO_DELETE_THRESHOLD", "90"))
STRICT_MODE_THRESHOLD = int(os.getenv("STRICT_MODE_THRESHOLD", "87"))

# ─── Updater ────────────────────────────────────────────────
CSV_UPDATE_INTERVAL_HOURS = int(os.getenv("CSV_UPDATE_INTERVAL_HOURS", "6"))

# ─── Queue ──────────────────────────────────────────────────
MAX_PARALLEL_CHECKS = int(os.getenv("MAX_PARALLEL_CHECKS", "5"))
CHECK_TIMEOUT = int(os.getenv("CHECK_TIMEOUT", "30"))  # URL tekshiruv timeout

# ─── Rate Limits ────────────────────────────────────────────
VT_RATE_PER_MINUTE = int(os.getenv("VT_RATE_PER_MINUTE", "4"))
IPQS_RATE_PER_DAY = int(os.getenv("IPQS_RATE_PER_DAY", "33"))

# ─── Data fayl yo'llari ────────────────────────────────────
import pathlib

BASE_DIR = pathlib.Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

WHITELIST_PATH = DATA_DIR / "whitelist.json"
KEYWORDS_PATH = DATA_DIR / "uz_keywords.json"
URLHAUS_PATH = DATA_DIR / "urlhaus.csv"
PHISHTANK_PATH = DATA_DIR / "phishtank.csv"
OPENPHISH_PATH = DATA_DIR / "openphish.txt"
DB_PATH = BASE_DIR / "antiphish.db"
