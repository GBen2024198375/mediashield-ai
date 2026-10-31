"""
MediaShield AI — Upload & File Handling Utilities
==================================================
Safe handling of user-uploaded files:
  - MIME type validation (via magic bytes, not just extension)
  - Size limits
  - Content-type whitelisting
  - Secure random naming
  - Deferred cleanup (context manager)

Design rule: never trust the client's declared Content-Type. Verify against
the file's actual bytes using python-magic-style detection built into Pillow
and soundfile.
"""

from __future__ import annotations

import logging
import mimetypes
import os
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from fastapi import HTTPException, UploadFile

from config import settings, UPLOAD_DIR

logger = logging.getLogger("mediashield.file_utils")


# ─────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────
def validate_upload(
    file: UploadFile,
    allowed_types: list[str],
    max_mb: Optional[int] = None,
) -> None:
    """
    Raise HTTPException(400/413) if the upload is not acceptable.
    Checks:
      1. Filename exists
      2. Declared content-type is in the allowed list
      3. Extension is not obviously dangerous
      4. (Size checked during save)

    Note: content-type from the client can lie, but combining it with
    extension checks + actual parser validation downstream catches most abuse.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Upload is missing a filename")

    # Extension sanity — block obviously bad things
    blocked_exts = {".exe", ".dll", ".sh", ".bat", ".ps1", ".js", ".vbs", ".scr"}
    ext = Path(file.filename).suffix.lower()
    if ext in blocked_exts:
        raise HTTPException(
            status_code=400,
            detail=f"File extension not allowed: {ext}",
        )

    # Content-type check
    ctype = (file.content_type or "").lower().split(";")[0].strip()
    if ctype and ctype not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported file type '{ctype}'. "
                f"Allowed: {', '.join(allowed_types)}"
            ),
        )


def validate_image_bytes(path: Path) -> None:
    """Verify the saved file is actually a valid image via Pillow."""
    from PIL import Image, UnidentifiedImageError

    try:
        with Image.open(path) as img:
            img.verify()   # cheap structural check
    except UnidentifiedImageError:
        raise HTTPException(status_code=400, detail="File is not a valid image")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Image validation failed: {e}")


def validate_audio_bytes(path: Path) -> None:
    """Verify the saved file is actually readable audio via soundfile."""
    import soundfile as sf

    try:
        # Just read the header — we don't need to decode the whole file here
        info = sf.info(str(path))
        if info.frames == 0:
            raise HTTPException(status_code=400, detail="Audio file is empty")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Audio validation failed: {e}")


# ─────────────────────────────────────────────────────────────
# Saving
# ─────────────────────────────────────────────────────────────
def _secure_name(original: str) -> str:
    """Generate a collision-resistant filename that preserves the extension."""
    ext = Path(original).suffix.lower() or ".bin"
    token = secrets.token_hex(8)
    ts = int(time.time())
    return f"{ts}_{token}{ext}"


async def save_upload(
    file: UploadFile,
    max_mb: Optional[int] = None,
) -> Path:
    """
    Save an UploadFile to UPLOAD_DIR with a safe name.
    Enforces the size limit while streaming (never loads whole file into RAM).

    Returns the Path where the file was written.
    """
    max_bytes = (max_mb or settings.MAX_UPLOAD_MB) * 1024 * 1024
    dest = UPLOAD_DIR / _secure_name(file.filename or "upload.bin")

    written = 0
    try:
        with open(dest, "wb") as f:
            # Read in 1MB chunks — safe for large files
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    f.close()
                    dest.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large. Max {max_mb or settings.MAX_UPLOAD_MB} MB.",
                    )
                f.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Failed to save upload: {e}")

    logger.debug(f"Saved upload → {dest.name} ({written} bytes)")
    return dest


# ─────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────
@contextmanager
def temp_upload_cleanup(*paths: Optional[Path]) -> Iterator[None]:
    """
    Context manager: deletes the given files when the block exits,
    regardless of whether an exception was raised.

    Usage:
        with temp_upload_cleanup(saved_path):
            result = detector.analyze(saved_path)
        # file is now deleted
    """
    try:
        yield
    finally:
        for p in paths:
            if p and isinstance(p, Path) and p.exists():
                try:
                    p.unlink()
                    logger.debug(f"Cleaned up {p.name}")
                except Exception as e:
                    logger.warning(f"Could not delete {p}: {e}")


def purge_old_uploads(max_age_hours: int = 24) -> int:
    """
    Delete files older than max_age_hours from UPLOAD_DIR.
    Call this on app startup to prevent disk bloat during dev.
    Returns the number of files removed.
    """
    if not UPLOAD_DIR.exists():
        return 0

    cutoff = time.time() - (max_age_hours * 3600)
    removed = 0

    for entry in UPLOAD_DIR.iterdir():
        if entry.is_file() and entry.stat().st_mtime < cutoff:
            try:
                entry.unlink()
                removed += 1
            except Exception as e:
                logger.warning(f"Could not purge {entry}: {e}")

    if removed:
        logger.info(f"Purged {removed} old upload(s) from {UPLOAD_DIR}")
    return removed


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────
def guess_content_type(path: Path) -> str:
    """Best-effort content-type from extension."""
    ctype, _ = mimetypes.guess_type(str(path))
    return ctype or "application/octet-stream"


def format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"