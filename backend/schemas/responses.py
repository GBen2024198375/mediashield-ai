"""
MediaShield AI — Pydantic Response Models
==========================================
Every API endpoint's response shape is defined here. FastAPI uses these
for:
  - Automatic request/response validation
  - OpenAPI schema at /docs
  - Type hints for the frontend TypeScript (via openapi-typescript)
"""

from __future__ import annotations

from typing import Optional, Literal
from pydantic import BaseModel, Field


# ─────────────────────────────────────────────────────────────
# Common primitives
# ─────────────────────────────────────────────────────────────
RiskLevel = Literal["low_risk", "suspicious", "high_risk", "unknown"]
Verdict = Literal[
    "likely_ai_generated", "likely_authentic", "inconclusive",
    "likely_synthetic", "scam_likely", "safe", "suspicious",
    "unavailable",
]


# ─────────────────────────────────────────────────────────────
# Component result models
# ─────────────────────────────────────────────────────────────
class ModelOutputs(BaseModel):
    """Raw model probabilities — nullable when model was unavailable."""
    fake: Optional[float] = None
    real: Optional[float] = None
    phishing: Optional[float] = None
    legitimate: Optional[float] = None


class ImageScanResult(BaseModel):
    verdict: Verdict
    score: float = Field(ge=0, le=100, description="Risk contribution 0-100")
    confidence: float = Field(ge=0, le=1)
    high_freq_anomaly: bool
    spectrum_ratio: float
    model_outputs: ModelOutputs
    reason: Optional[str] = None


class AudioScanResult(BaseModel):
    verdict: Verdict
    score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    duration_seconds: float
    chunks_analyzed: int
    spectral_anomaly: bool
    model_outputs: Optional[ModelOutputs] = None
    reason: Optional[str] = None


class MatchedKeywords(BaseModel):
    urgency: list[str] = Field(default_factory=list)
    sensitive: list[str] = Field(default_factory=list)
    payment: list[str] = Field(default_factory=list)
    link_phrases: list[str] = Field(default_factory=list)


class TextScanResult(BaseModel):
    verdict: Verdict
    score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    signals: list[str] = Field(default_factory=list)
    matched_keywords: dict[str, list[str]] = Field(default_factory=dict)
    urls: list[str] = Field(default_factory=list)
    model_outputs: Optional[ModelOutputs] = None
    reason: Optional[str] = None


class C2PAInfo(BaseModel):
    valid: bool = False
    reason: Optional[str] = None
    signer: Optional[str] = None


class GPSCoords(BaseModel):
    lat: float
    lon: float


class SourceVerificationResult(BaseModel):
    exif_present: bool
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    software: Optional[str] = None
    timestamp: Optional[str] = None
    gps: Optional[GPSCoords] = None
    image_dimensions: Optional[list[int]] = None
    format: Optional[str] = None
    sha256: str
    c2pa: C2PAInfo
    anomalies: list[str] = Field(default_factory=list)
    risk_score: float = Field(ge=0, le=100)
    reason: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# Scoring models
# ─────────────────────────────────────────────────────────────
class ComponentScore(BaseModel):
    label: str
    score: float
    verdict: str
    confidence: float
    weight: float
    present: bool = True


class ScoringOverrides(BaseModel):
    metadata_anomalies: int = 0
    metadata_penalty: float = 0.0
    no_exif_penalty: float = 0.0
    c2pa_valid: bool = False
    c2pa_bonus: float = 0.0
    base_score: float = 0.0
    final_score: float = 0.0


class CoverageInfo(BaseModel):
    image: bool = False
    audio: bool = False
    text: bool = False
    source: bool = False


class UnifiedScore(BaseModel):
    risk_score: float = Field(ge=0, le=100)
    risk_level: RiskLevel
    confidence: float = Field(ge=0, le=1)
    components: dict[str, ComponentScore] = Field(default_factory=dict)
    overrides: dict = Field(default_factory=dict)
    summary: str
    coverage: CoverageInfo


# ─────────────────────────────────────────────────────────────
# Checklist models
# ─────────────────────────────────────────────────────────────
class ChecklistItem(BaseModel):
    priority: int
    icon: str
    title: str
    detail: str
    tags: list[str] = Field(default_factory=list)


class Checklist(BaseModel):
    title: str
    urgency: Literal["immediate", "warn", "informational"]
    items: list[ChecklistItem]
    sources: list[str] = Field(default_factory=list)
    total_items: int
    disclaimer: str


# ─────────────────────────────────────────────────────────────
# Endpoint request/response envelopes
# ─────────────────────────────────────────────────────────────
class MessageScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10_000)


class FullScanResponse(BaseModel):
    """Response for /api/scan/image, /api/scan/audio, /api/scan/message, /api/scan/full."""
    scan_id: str
    timestamp: str
    image: Optional[ImageScanResult] = None
    audio: Optional[AudioScanResult] = None
    text: Optional[TextScanResult] = None
    source: Optional[SourceVerificationResult] = None
    score: UnifiedScore
    checklist: Checklist


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    app_name: str
    version: str
    device: str
    models: dict[str, bool]
    timestamp: str


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    scan_id: Optional[str] = None