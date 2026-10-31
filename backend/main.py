"""
MediaShield AI — FastAPI Application Entry Point
=================================================
Endpoints:
  GET  /health                → service + model readiness
  POST /api/scan/image        → deepfake image scan
  POST /api/scan/audio        → voice-clone / synthetic speech scan
  POST /api/scan/message      → phishing / scam message analysis
  POST /api/scan/full         → combined scan (image + audio + text)
  POST /api/verify/source     → metadata / provenance verification
  POST /api/checklist         → standalone checklist generation

Run:
    uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from models.image_detector import image_detector
from models.audio_detector import audio_detector
from models.text_analyzer import text_analyzer
from models.model_loader import loader as model_loader
from utils.exif_parser import exif_parser
from utils.scoring import scoring_engine
from utils.checklist import checklist_generator
from utils.file_utils import (
    validate_upload,
    validate_image_bytes,
    validate_audio_bytes,
    save_upload,
    temp_upload_cleanup,
    purge_old_uploads,
)
from schemas.responses import (
    FullScanResponse,
    HealthResponse,
    MessageScanRequest,
    ErrorResponse,
)

# ─────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)-28s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("mediashield.main")


# ─────────────────────────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Everyday digital fraud protection. Detects deepfakes, voice clones, "
        "phishing messages, and suspicious source metadata — then generates a "
        "personalized prevention checklist."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
)


# ─────────────────────────────────────────────────────────────
# CORS
# ─────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────
# Global exception handler — never leak stack traces to the client
# ─────────────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):
    logger.exception(f"Unhandled error on {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="internal_error",
            detail=str(exc) if settings.DEBUG else "An unexpected error occurred",
        ).model_dump(),
    )


# ─────────────────────────────────────────────────────────────
# Startup / shutdown
# ─────────────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup() -> None:
    logger.info("=" * 70)
    logger.info(f"  {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"  Device: {settings.DEVICE} | Debug: {settings.DEBUG}")
    logger.info("=" * 70)

    # Purge stale uploads from previous runs
    purge_old_uploads(max_age_hours=24)

    # Preload all models. Runs in a thread so startup isn't blocked from
    # emitting logs — but startup itself awaits it, so /health reports ready.
    await asyncio.to_thread(model_loader.preload_all)

    logger.info("MediaShield AI is ready to accept requests.")


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_scan_id() -> str:
    return uuid.uuid4().hex[:12]


def _build_response(
    scan_id: str,
    image_result: Optional[dict] = None,
    audio_result: Optional[dict] = None,
    text_result: Optional[dict] = None,
    exif_result: Optional[dict] = None,
) -> dict:
    """Run scoring + checklist, return a dict ready for FullScanResponse."""
    score = scoring_engine.aggregate(
        image_result=image_result,
        audio_result=audio_result,
        text_result=text_result,
        exif_result=exif_result,
    )
    checklist = checklist_generator.generate(
        image_result=image_result,
        audio_result=audio_result,
        text_result=text_result,
        exif_result=exif_result,
        risk_level=score["risk_level"],
    )
    return {
        "scan_id": scan_id,
        "timestamp": _now_iso(),
        "image": image_result,
        "audio": audio_result,
        "text": text_result,
        "source": exif_result,
        "score": score,
        "checklist": checklist,
    }


# ─────────────────────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────────────────────
@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> dict:
    status = model_loader.status()
    models = {
        "image": status["image_model_ready"],
        "audio": status["audio_model_ready"],
        "text":  status["text_model_ready"],
    }
    all_ready = all(models.values())
    return {
        "status": "ok" if all_ready else "degraded",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "device": settings.DEVICE,
        "models": models,
        "timestamp": _now_iso(),
    }


@app.get("/", include_in_schema=False)
async def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/health",
    }


# ─────────────────────────────────────────────────────────────
# SCAN — IMAGE
# ─────────────────────────────────────────────────────────────
@app.post("/api/scan/image", tags=["scan"])
async def scan_image(file: UploadFile = File(...)) -> dict:
    """
    Scan an image for AI generation / deepfake signals and source metadata.
    Returns image verdict + EXIF provenance + unified score + checklist.
    """
    scan_id = _new_scan_id()
    validate_upload(file, settings.ALLOWED_IMAGE_TYPES)

    saved_path = await save_upload(file)

    try:
        validate_image_bytes(saved_path)

        # Run model + EXIF in parallel
        image_result, exif_result = await asyncio.gather(
            asyncio.to_thread(image_detector.analyze, saved_path),
            asyncio.to_thread(exif_parser.parse, saved_path),
        )
    finally:
        with temp_upload_cleanup(saved_path):
            pass  # context manager handles deletion

    return _build_response(
        scan_id=scan_id,
        image_result=image_result,
        exif_result=exif_result,
    )


# ─────────────────────────────────────────────────────────────
# SCAN — AUDIO
# ─────────────────────────────────────────────────────────────
@app.post("/api/scan/audio", tags=["scan"])
async def scan_audio(file: UploadFile = File(...)) -> dict:
    """
    Scan an audio file for voice-clone / synthetic-speech signals.
    """
    scan_id = _new_scan_id()
    validate_upload(file, settings.ALLOWED_AUDIO_TYPES)

    saved_path = await save_upload(file)

    try:
        validate_audio_bytes(saved_path)
        audio_result = await asyncio.to_thread(audio_detector.analyze, saved_path)
    finally:
        with temp_upload_cleanup(saved_path):
            pass

    return _build_response(scan_id=scan_id, audio_result=audio_result)


# ─────────────────────────────────────────────────────────────
# SCAN — MESSAGE (text)
# ─────────────────────────────────────────────────────────────
@app.post("/api/scan/message", tags=["scan"])
async def scan_message(payload: MessageScanRequest) -> dict:
    """
    Analyze a suspicious message (SMS/email/chat) for phishing signals.
    Body: {"text": "..."}
    """
    scan_id = _new_scan_id()
    text_result = await asyncio.to_thread(text_analyzer.analyze, payload.text)
    return _build_response(scan_id=scan_id, text_result=text_result)


# ─────────────────────────────────────────────────────────────
# SCAN — SOURCE / METADATA only
# ─────────────────────────────────────────────────────────────
@app.post("/api/verify/source", tags=["scan"])
async def verify_source(file: UploadFile = File(...)) -> dict:
    """
    Analyze only the metadata / provenance of an image (faster than full scan).
    """
    scan_id = _new_scan_id()
    validate_upload(file, settings.ALLOWED_IMAGE_TYPES)

    saved_path = await save_upload(file)
    try:
        validate_image_bytes(saved_path)
        exif_result = await asyncio.to_thread(exif_parser.parse, saved_path)
    finally:
        with temp_upload_cleanup(saved_path):
            pass

    return _build_response(scan_id=scan_id, exif_result=exif_result)


# ─────────────────────────────────────────────────────────────
# SCAN — FULL (all three + source)
# ─────────────────────────────────────────────────────────────
@app.post("/api/scan/full", tags=["scan"])
async def scan_full(
    image: Optional[UploadFile] = File(default=None),
    audio: Optional[UploadFile] = File(default=None),
    text: Optional[str] = Form(default=None),
) -> dict:
    """
    Combined scan. Accepts any subset of: image, audio, message text.
    All present inputs are analyzed in parallel.
    """
    scan_id = _new_scan_id()

    if not any([image, audio, text]):
        raise HTTPException(
            status_code=400,
            detail="Provide at least one of: image, audio, or text",
        )

    # Validate + save uploads up-front
    image_path: Optional[Path] = None
    audio_path: Optional[Path] = None

    if image and image.filename:
        validate_upload(image, settings.ALLOWED_IMAGE_TYPES)
        image_path = await save_upload(image)

    if audio and audio.filename:
        validate_upload(audio, settings.ALLOWED_AUDIO_TYPES)
        audio_path = await save_upload(audio)

    try:
        # Validate saved files
        if image_path:
            validate_image_bytes(image_path)
        if audio_path:
            validate_audio_bytes(audio_path)

        # Run all requested detectors concurrently
        tasks = {}

        if image_path:
            tasks["image"] = asyncio.to_thread(image_detector.analyze, image_path)
            tasks["source"] = asyncio.to_thread(exif_parser.parse, image_path)

        if audio_path:
            tasks["audio"] = asyncio.to_thread(audio_detector.analyze, audio_path)

        if text:
            tasks["text"] = asyncio.to_thread(text_analyzer.analyze, text)

        results = await asyncio.gather(*tasks.values())
        results_map = dict(zip(tasks.keys(), results))

    finally:
        with temp_upload_cleanup(image_path, audio_path):
            pass

    return _build_response(
        scan_id=scan_id,
        image_result=results_map.get("image"),
        audio_result=results_map.get("audio"),
        text_result=results_map.get("text"),
        exif_result=results_map.get("source"),
    )


# ─────────────────────────────────────────────────────────────
# CHECKLIST — standalone
# ─────────────────────────────────────────────────────────────
@app.post("/api/checklist", tags=["checklist"])
async def standalone_checklist(payload: MessageScanRequest) -> dict:
    """
    Generate a prevention checklist from a raw message without a full scan.
    Useful as a quick-reference tool.
    """
    text_result = await asyncio.to_thread(text_analyzer.analyze, payload.text)
    score = scoring_engine.aggregate(text_result=text_result)
    checklist = checklist_generator.generate(
        text_result=text_result,
        risk_level=score["risk_level"],
    )
    return {"score": score, "checklist": checklist}


# ─────────────────────────────────────────────────────────────
# Dev runner
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info",
    )