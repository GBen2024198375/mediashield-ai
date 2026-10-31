"""
MediaShield AI — Central Configuration
=======================================
All model names, thresholds, weights, and paths live here.
Nothing downstream should hard-code these values.
"""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


# ─────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent

# Where uploaded files land temporarily
UPLOAD_DIR = BACKEND_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# Where Hugging Face weights cache (outside the repo tree so `git clean` doesn't nuke them)
MODEL_CACHE_DIR = PROJECT_ROOT / "models"
MODEL_CACHE_DIR.mkdir(exist_ok=True)


# ─────────────────────────────────────────────────────────────
# Settings (overridable via .env)
# ─────────────────────────────────────────────────────────────
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- Server ----
    APP_NAME: str = "MediaShield AI"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # CORS — frontend dev server origins
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",   # Vite default
        "http://localhost:3000",   # CRA / Next default
        "http://127.0.0.1:5173",
    ]

    # ---- Model cache ----
    HF_HOME: str = str(MODEL_CACHE_DIR)
    TRANSFORMERS_CACHE: str = str(MODEL_CACHE_DIR)

    # ---- Model identifiers (Hugging Face) ----
    IMAGE_MODEL_NAME: str = "prithivMLmods/deepfake-detector-model-v1"
    AUDIO_MODEL_NAME: str = "garystafford/wav2vec2-deepfake-voice-detector"
    TEXT_MODEL_NAME: str = "ealvaradob/bert-finetuned-phishing"

    # Fallback text model if the primary fails to load
    TEXT_FALLBACK_MODEL_NAME: str = "distilbert-base-uncased-finetuned-sst-2-english"

    # ---- Inference device ----
    DEVICE: str = "cpu"           # switch to "cuda" if you have a GPU
    MAX_TEXT_LENGTH: int = 512
    AUDIO_SAMPLE_RATE: int = 16000
    MAX_AUDIO_SECONDS: float = 30.0
    MAX_IMAGE_DIM: int = 1024     # images are resized before inference

    # ---- Upload limits ----
    MAX_UPLOAD_MB: int = 25
    ALLOWED_IMAGE_TYPES: list[str] = [
        "image/jpeg", "image/png", "image/webp", "image/bmp",
    ]
    ALLOWED_AUDIO_TYPES: list[str] = [
        "audio/wav", "audio/x-wav", "audio/mpeg", "audio/mp3",
        "audio/flac", "audio/ogg", "audio/webm",
    ]


settings = Settings()


# ─────────────────────────────────────────────────────────────
# Risk bands — used by every detector + the unified scorer
# ─────────────────────────────────────────────────────────────
# 0–30   → low_risk       (green)
# 31–60  → suspicious     (amber)
# 61–100 → high_risk      (red)
RISK_BANDS = {
    "low_risk":   (0,  30),
    "suspicious": (31, 60),
    "high_risk":  (61, 100),
}

# Per-detector verdict thresholds (probability 0.0–1.0)
DETECTION_THRESHOLDS = {
    "image": {"likely_authentic": 0.40, "likely_ai_generated": 0.70},
    "audio": {"likely_authentic": 0.40, "likely_synthetic": 0.70},
    "text":  {"safe": 0.40, "scam_likely": 0.70},
}


# ─────────────────────────────────────────────────────────────
# Scoring weights — used by utils/scoring.py
# ─────────────────────────────────────────────────────────────
# Only the weights of *present* components are used; the engine
# re-normalizes, so a text-only scan still works fine.
SCORING_WEIGHTS = {
    "image_model":     0.40,
    "image_forensics": 0.15,
    "audio_model":     0.45,
    "text_model":      0.50,
    "source_metadata": 0.10,
}

# Score adjustments applied *after* weighted averaging
SCORE_OVERRIDES = {
    "metadata_anomaly_penalty": 8,     # +8 risk per EXIF anomaly
    "metadata_anomaly_cap": 24,        # cap total penalty from metadata
    "c2pa_valid_bonus": -18,           # lower risk if provenance is signed
    "no_exif_penalty": 10,             # missing EXIF on a photo is suspicious
}


# ─────────────────────────────────────────────────────────────
# Text-signal keywords — used by models/text_analyzer.py
# ─────────────────────────────────────────────────────────────
URGENCY_KEYWORDS = [
    "urgent", "immediate", "act now", "expires", "final notice",
    "last chance", "within 24 hours", "account suspended",
    "verify immediately", "limited time",
]

SENSITIVE_REQUEST_KEYWORDS = [
    "otp", "one-time password", "password", "pin", "cvv", "ssn",
    "aadhaar", "pan number", "account number", "card number",
    "bank details", "upi", "ifsc", "net banking",
]

PAYMENT_KEYWORDS = [
    "pay", "payment", "transfer", "refund", "cash", "upi",
    "gift card", "bitcoin", "crypto", "wire", "deposit",
    "processing fee", "clearance fee", "customs fee",
]

LINK_KEYWORDS = [
    "click here", "click below", "tap here", "http://", "https://",
    "bit.ly", "tinyurl", "shorturl", "t.co",
]