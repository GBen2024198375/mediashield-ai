"""
MediaShield AI — Source / Provenance Verifier
==============================================
Extracts and analyzes provenance signals from uploaded media:
  - EXIF metadata (camera, software, timestamp, GPS)
  - XMP metadata (Adobe editing traces)
  - PNG text chunks (generation-tool signatures)
  - C2PA Content Credentials (stubbed — see NOTE below)
  - SHA-256 content hash for tamper tracking
  - Anomaly heuristics that feed the unified risk score

NOTE ON C2PA:
    The real C2PA verification requires `c2pa-python`, which needs a Rust
    toolchain. We return a stub result now. The scoring engine treats
    `valid=False` as neutral (no penalty, no bonus) unless the manifest
    is explicitly marked as tampered.

Design rule: never raise. Always return a dict, even for unreadable files.
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Any, Optional

from PIL import Image, ExifTags
from PIL.TiffImagePlugin import IFDRational

logger = logging.getLogger("mediashield.exif_parser")


# ─────────────────────────────────────────────────────────────
# Known signatures — order matters, first match wins
# ─────────────────────────────────────────────────────────────

# Software that strongly suggests AI generation or editing
AI_GENERATION_SIGNATURES = [
    "midjourney", "dall-e", "dalle", "stable diffusion", "sdxl",
    "firefly", "imagen", "flux", "runway", "sora", "pika",
    "leonardo.ai", "ideogram", "playground ai", "nightcafe",
]

EDITING_SIGNATURES = [
    "photoshop", "gimp", "lightroom", "affinity photo",
    "pixelmator", "paintshop", "capture one", "snapseed",
]

# Software that suggests *capture* (good provenance signal)
CAMERA_SIGNATURES = [
    "camera", "ios", "android", "pixel", "iphone", "samsung",
    "oneplus", "xiaomi", "redmi", "realme", "oppo", "vivo",
]

# PNG text chunk keys that sometimes carry generation info
AI_PNG_CHUNK_KEYS = [
    "parameters", "prompt", "workflow", "negative prompt",
    "sd-metadata", "comfyui", "generation_data",
]


class ExifParser:
    """Extract + analyze provenance signals from an image file."""

    # ─────────────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────────────
    def parse(self, image_path: str | Path) -> dict:
        """
        Returns:
            {
                "exif_present": bool,
                "camera_make": str | None,
                "camera_model": str | None,
                "software": str | None,
                "timestamp": str | None,
                "gps": {"lat": float, "lon": float} | None,
                "image_dimensions": [w, h],
                "format": str,
                "sha256": str,
                "c2pa": {...},                    # stub, see note
                "anomalies": [str, ...],          # human-readable findings
                "risk_score": float,              # 0-100 from metadata alone
                "reason": str | None,             # set only on total failure
            }
        """
        path = Path(image_path)

        result: dict[str, Any] = {
            "exif_present": False,
            "camera_make": None,
            "camera_model": None,
            "software": None,
            "timestamp": None,
            "gps": None,
            "image_dimensions": None,
            "format": None,
            "sha256": self._sha256(path),
            "c2pa": {"valid": False, "reason": "c2pa_unavailable", "signer": None},
            "anomalies": [],
            "risk_score": 0.0,
            "reason": None,
        }

        # ── Open image ───────────────────────────────────────
        try:
            image = Image.open(path)
            result["format"] = image.format
            result["image_dimensions"] = list(image.size)
        except Exception as e:
            logger.warning(f"Cannot open {path.name}: {e}")
            result["reason"] = f"unreadable_image: {e}"
            result["risk_score"] = 30.0
            result["anomalies"].append("File could not be parsed as an image")
            return result

        # ── EXIF extraction ──────────────────────────────────
        try:
            exif = image.getexif()
            if exif and len(exif) > 0:
                result["exif_present"] = True
                self._populate_exif(result, exif)
        except Exception as e:
            logger.debug(f"EXIF read failed: {e}")
            result["anomalies"].append(f"EXIF parsing failed: {e}")

        # ── PNG text chunks (generation signatures) ──────────
        if result["format"] == "PNG":
            self._scan_png_chunks(image, result)

        # ── XMP / IPTC (editing traces) ──────────────────────
        try:
            xmp = image.info.get("xmp") if hasattr(image, "info") else None
            if xmp:
                xmp_str = xmp.decode("utf-8", errors="ignore") if isinstance(xmp, bytes) else str(xmp)
                self._scan_xmp(xmp_str, result)
        except Exception as e:
            logger.debug(f"XMP scan failed: {e}")

        # ── C2PA (stubbed) ───────────────────────────────────
        result["c2pa"] = self._verify_c2pa(path)

        # ── Anomaly heuristics ───────────────────────────────
        self._compute_anomalies(result)

        # ── Aggregate metadata risk score ────────────────────
        result["risk_score"] = self._score(result)

        logger.info(
            f"Source scan {path.name}: exif={result['exif_present']} "
            f"anomalies={len(result['anomalies'])} → risk {result['risk_score']}"
        )
        return result

    # ─────────────────────────────────────────────────────────
    # INTERNALS — extraction
    # ─────────────────────────────────────────────────────────
    def _populate_exif(self, result: dict, exif) -> None:
        """Populate camera_make, model, software, timestamp, GPS."""
        make = exif.get(ExifTags.Base.Make)
        model = exif.get(ExifTags.Base.Model)
        software = exif.get(ExifTags.Base.Software)
        dt = exif.get(ExifTags.Base.DateTime) or exif.get(ExifTags.Base.DateTimeOriginal)

        result["camera_make"] = self._clean(make)
        result["camera_model"] = self._clean(model)
        result["software"] = self._clean(software)
        result["timestamp"] = self._clean(dt)

        # GPS — usually nested under GPSInfo tag
        try:
            gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
            if gps_ifd:
                result["gps"] = self._parse_gps(gps_ifd)
        except Exception as e:
            logger.debug(f"GPS parse failed: {e}")

    def _parse_gps(self, gps_ifd: dict) -> Optional[dict]:
        """Convert GPS DMS to decimal degrees."""
        try:
            def dms_to_decimal(dms, ref):
                d, m, s = (float(x) for x in dms)
                dec = d + m / 60.0 + s / 3600.0
                if ref in ("S", "W"):
                    dec = -dec
                return round(dec, 6)

            lat_dms = gps_ifd.get(2)   # GPSLatitude
            lat_ref = gps_ifd.get(1)   # GPSLatitudeRef
            lon_dms = gps_ifd.get(4)   # GPSLongitude
            lon_ref = gps_ifd.get(3)   # GPSLongitudeRef

            if lat_dms and lon_dms and lat_ref and lon_ref:
                return {
                    "lat": dms_to_decimal(lat_dms, lat_ref),
                    "lon": dms_to_decimal(lon_dms, lon_ref),
                }
        except Exception as e:
            logger.debug(f"GPS conversion failed: {e}")
        return None

    def _scan_png_chunks(self, image: Image.Image, result: dict) -> None:
        """Look for AI-generation signatures in PNG text chunks."""
        try:
            info = image.info or {}
            for key, value in info.items():
                key_lower = str(key).lower()
                if any(sig in key_lower for sig in AI_PNG_CHUNK_KEYS):
                    snippet = str(value)[:120].replace("\n", " ")
                    result["anomalies"].append(
                        f"PNG text chunk '{key}' contains generation metadata: {snippet}…"
                    )
        except Exception as e:
            logger.debug(f"PNG chunk scan failed: {e}")

    def _scan_xmp(self, xmp_str: str, result: dict) -> None:
        """Scan XMP packet for known editing / generation tools."""
        lower = xmp_str.lower()

        for sig in AI_GENERATION_SIGNATURES:
            if sig in lower:
                result["anomalies"].append(f"XMP indicates AI generation tool: {sig}")
                return

        for sig in EDITING_SIGNATURES:
            if sig in lower:
                result["anomalies"].append(f"XMP indicates editing software: {sig}")
                return

        # XMP history with multiple entries = multiple edit sessions
        history_count = lower.count("<rdf:li")
        if history_count > 3:
            result["anomalies"].append(
                f"XMP history shows {history_count} edit operations"
            )

    # ─────────────────────────────────────────────────────────
    # INTERNALS — C2PA stub
    # ─────────────────────────────────────────────────────────
    def _verify_c2pa(self, path: Path) -> dict:
        """
        Placeholder for real C2PA verification.

        To enable real verification:
            pip install c2pa-python
        Then replace this body with:
            from c2pa import Reader
            reader = Reader(str(path))
            manifest = reader.get_active_manifest()
            ...

        For now, we do a lightweight check: does the file contain the
        string 'c2pa' anywhere in the first 4KB? This catches files that
        were signed but not properly processed.
        """
        try:
            with open(path, "rb") as f:
                header = f.read(4096)
            if b"c2pa" in header.lower() or b"jumb" in header.lower():
                return {
                    "valid": False,
                    "reason": "c2pa_signature_detected_but_unverified",
                    "signer": None,
                }
        except Exception:
            pass
        return {"valid": False, "reason": "c2pa_unavailable", "signer": None}

    # ─────────────────────────────────────────────────────────
    # INTERNALS — anomaly heuristics
    # ─────────────────────────────────────────────────────────
    def _compute_anomalies(self, result: dict) -> None:
        """Apply heuristic rules and append findings to result['anomalies']."""

        software = (result["software"] or "").lower()
        make = (result["camera_make"] or "").lower()
        model = (result["camera_model"] or "").lower()

        # 1. AI-generation software signature
        for sig in AI_GENERATION_SIGNATURES:
            if sig in software:
                result["anomalies"].append(
                    f"AI generation tool signature in metadata: '{result['software']}'"
                )
                break

        # 2. Editing software without camera make
        if not make:
            for sig in EDITING_SIGNATURES:
                if sig in software:
                    result["anomalies"].append(
                        f"Editing software present without camera capture info: '{result['software']}'"
                    )
                    break

        # 3. EXIF present but no camera make (suspicious stripping)
        if result["exif_present"] and not make and not model:
            result["anomalies"].append(
                "EXIF present but missing camera make/model — metadata may be stripped"
            )

        # 4. No EXIF at all (screenshot, download, or export)
        if not result["exif_present"]:
            result["anomalies"].append(
                "No EXIF data — image has been exported, screenshotted, or stripped"
            )

        # 5. Screenshot detection (dimensions match common device screens)
        dims = result.get("image_dimensions")
        if dims:
            w, h = dims
            common_screen_ratios = [
                (1080, 2340), (1170, 2532), (1284, 2778),  # iPhone
                (1080, 2400), (1440, 3200),                # Android
                (1920, 1080), (2560, 1440), (3840, 2160),  # Desktop
            ]
            if any(abs(w - sw) < 20 and abs(h - sh) < 20 for sw, sh in common_screen_ratios):
                if not result["anomalies"] or "screenshot" not in " ".join(result["anomalies"]).lower():
                    result["anomalies"].append(
                        "Dimensions match a common screen resolution — likely a screenshot"
                    )

        # 6. Timestamp sanity
        ts = result.get("timestamp")
        if ts:
            try:
                year = int(str(ts)[:4])
                if year < 2000 or year > 2100:
                    result["anomalies"].append(
                        f"Timestamp out of plausible range: {ts}"
                    )
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────
    # INTERNALS — scoring
    # ─────────────────────────────────────────────────────────
    def _score(self, result: dict) -> float:
        """
        Compute a 0-100 metadata risk score from anomalies + presence.

        This is *not* a deepfake probability — it's a "how trustworthy is
        the provenance story" score. Combined with the model outputs by
        the scoring engine.
        """
        score = 0.0

        # Baseline by EXIF presence
        if not result["exif_present"]:
            score += 15.0
        else:
            score += 5.0

        # Per-anomaly penalty (capped)
        score += min(len(result["anomalies"]) * 8.0, 40.0)

        # AI-signature in software → strong signal
        sw = (result["software"] or "").lower()
        if any(sig in sw for sig in AI_GENERATION_SIGNATURES):
            score += 25.0

        # Camera make/model present → reduces risk
        if result["camera_make"] and result["camera_model"]:
            score -= 10.0

        # GPS present → real capture signal
        if result["gps"]:
            score -= 5.0

        # C2PA valid would subtract more (stub never triggers this)
        if result.get("c2pa", {}).get("valid"):
            score -= 18.0

        return round(min(100.0, max(0.0, score)), 1)

    # ─────────────────────────────────────────────────────────
    # INTERNALS — helpers
    # ─────────────────────────────────────────────────────────
    def _sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            logger.debug(f"Hash failed for {path.name}: {e}")
            return ""

    def _clean(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        s = str(value).strip()
        return s or None


# Module-level singleton
exif_parser = ExifParser()