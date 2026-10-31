"""
MediaShield AI — Dynamic Fraud Prevention Checklist
====================================================
Generates an action plan tailored to the specific threats detected in a scan.

Design philosophy:
  - Detection is worthless if the user doesn't know what to do next.
  - Every checklist item must be concrete, actionable within 60 seconds,
    and specific to what was found (not generic advice).
  - Items are ordered by urgency (immediate action → follow-up).

Output structure:
    {
        "title": str,                     # headline for the UI
        "urgency": "immediate" | "warn" | "informational",
        "items": [
            {
                "priority": int,          # 1 = highest, used for sorting
                "icon": str,              # emoji hint for the UI
                "title": str,
                "detail": str,
                "tags": [str],            # e.g. ["banking", "voice-call"]
            },
            ...
        ],
        "sources": [str],                 # which detections triggered this
        "disclaimer": str,
    }
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("mediashield.checklist")


# ─────────────────────────────────────────────────────────────
# Base checklist — always included
# ─────────────────────────────────────────────────────────────
BASE_ITEMS = [
    {
        "priority": 90,
        "icon": "🔒",
        "title": "Never share OTPs, PINs, CVVs, or passwords",
        "detail": (
            "No legitimate bank, government agency, or company will ever ask "
            "for these over the phone, SMS, or email. If someone does, it's a scam — hang up."
        ),
        "tags": ["banking", "identity"],
    },
    {
        "priority": 91,
        "icon": "📞",
        "title": "Verify through an official number you look up yourself",
        "detail": (
            "Don't use numbers or links from the message. Open your bank's app or "
            "the back of your card to find the real contact number, then call them."
        ),
        "tags": ["verification"],
    },
    {
        "priority": 92,
        "icon": "🛡️",
        "title": "Enable two-factor authentication everywhere important",
        "detail": (
            "Use an authenticator app (not SMS) for email, banking, and social accounts. "
            "This is your last line of defense if a password leaks."
        ),
        "tags": ["hardening"],
    },
    {
        "priority": 95,
        "icon": "🚨",
        "title": "Report to your bank and cybercrime authority",
        "detail": (
            "In India: file at cybercrime.gov.in or call 1930. Globally: report to your "
            "bank's fraud line and your local police cyber cell. Speed matters — early "
            "reports recover money more often."
        ),
        "tags": ["reporting"],
    },
]


# ─────────────────────────────────────────────────────────────
# Triggered items — mapped from detector verdicts
# ─────────────────────────────────────────────────────────────
TRIGGERS: dict[str, dict[str, list[dict]]] = {
    "image": {
        "likely_ai_generated": [
            {
                "priority": 5,
                "icon": "🖼️",
                "title": "Do NOT use this image as proof of identity or consent",
                "detail": (
                    "This image shows strong signs of AI generation. Common scams: fake "
                    "job candidates, fake romance profiles, fake KYC documents, fake CEO "
                    "photos in 'urgent wire transfer' requests."
                ),
                "tags": ["identity", "deepfake"],
            },
            {
                "priority": 10,
                "icon": "🎥",
                "title": "Request a live video call to verify identity",
                "detail": (
                    "If someone claims this image is of them, ask for a live video call "
                    "where they turn their head, blink, and hold up today's newspaper. "
                    "Static AI images can't do that."
                ),
                "tags": ["verification", "deepfake"],
            },
            {
                "priority": 20,
                "icon": "🔍",
                "title": "Reverse-image search the photo",
                "detail": (
                    "Upload to Google Lens or TinEye. AI-generated faces sometimes reuse "
                    "training-set faces, and scam photos are often recycled across victims."
                ),
                "tags": ["verification"],
            },
        ],
        "inconclusive": [
            {
                "priority": 30,
                "icon": "⚠️",
                "title": "Treat this image with caution",
                "detail": (
                    "Our detector couldn't confidently classify this image. Before acting "
                    "on any request tied to it (money, identity, permission), verify through "
                    "a separate channel."
                ),
                "tags": ["caution"],
            },
        ],
    },
    "audio": {
        "likely_synthetic": [
            {
                "priority": 1,
                "icon": "🔊",
                "title": "Hang up. Call the person back on a number you already have",
                "detail": (
                    "Voice-clone scams usually impersonate family or executives. The cloned "
                    "voice is fake, but the panic is real. Never act on a voice call asking "
                    "for money or data without calling back on a known number."
                ),
                "tags": ["voice-call", "urgent"],
            },
            {
                "priority": 8,
                "icon": "🔑",
                "title": "Agree on a family 'safe word' for urgent requests",
                "detail": (
                    "Pick a word only your family knows. If a caller claiming to be family "
                    "can't say it, hang up. This single habit defeats almost every voice-clone scam."
                ),
                "tags": ["voice-call", "hardening"],
            },
            {
                "priority": 15,
                "icon": "🏦",
                "title": "Ask your bank to require in-person verification for large transfers",
                "detail": (
                    "Many banks let you add a callback or branch-verification requirement for "
                    "transfers above a threshold. Worth the 10-minute setup."
                ),
                "tags": ["banking", "hardening"],
            },
        ],
        "inconclusive": [
            {
                "priority": 30,
                "icon": "🎙️",
                "title": "Verify this audio through a separate channel",
                "detail": (
                    "Our detector couldn't confidently classify this audio. If it's being used "
                    "to request money, data, or action, verify through a channel you initiate."
                ),
                "tags": ["caution"],
            },
        ],
    },
    "text": {
        "scam_likely": [
            {
                "priority": 3,
                "icon": "⛔",
                "title": "Do NOT reply, click links, or call numbers in this message",
                "detail": (
                    "Replying confirms your number is live and can trigger more scam attempts. "
                    "Links can install malware or steal credentials. Just delete."
                ),
                "tags": ["sms", "email", "phishing"],
            },
            {
                "priority": 6,
                "icon": "🔗",
                "title": "Hover over every link before clicking — check the real domain",
                "detail": (
                    "Scammers use lookalike domains (sbi-online.co instead of sbi.co.in). "
                    "The visible text says one thing, the actual URL says another. On mobile, "
                    "long-press the link to preview it."
                ),
                "tags": ["phishing", "links"],
            },
            {
                "priority": 12,
                "icon": "📩",
                "title": "Forward the message to your bank's fraud department",
                "detail": (
                    "Most banks have a dedicated spam reporting number (often 1900-series). "
                    "Forwarding helps them block the scam for other customers too."
                ),
                "tags": ["reporting"],
            },
            {
                "priority": 18,
                "icon": "🧊",
                "title": "Report as spam/phishing in your messaging app",
                "detail": (
                    "In WhatsApp: long-press message → Report. In SMS: mark as spam. This "
                    "trains your carrier's filters to catch similar scams faster."
                ),
                "tags": ["reporting"],
            },
        ],
        "suspicious": [
            {
                "priority": 25,
                "icon": "🤔",
                "title": "Something feels off — verify before you act",
                "detail": (
                    "Our analysis found patterns common in scam messages. Don't act on this "
                    "message alone. Contact the organization directly through their official "
                    "app or website."
                ),
                "tags": ["caution"],
            },
        ],
    },
    "source": {
        "no_metadata": [
            {
                "priority": 22,
                "icon": "🧾",
                "title": "No source data — treat the file as unverified",
                "detail": (
                    "This file has no camera metadata, timestamp, or location. It could be a "
                    "screenshot, a downloaded image, or a deliberately stripped file. Do not "
                    "rely on it as evidence."
                ),
                "tags": ["provenance"],
            },
        ],
        "metadata_anomalies": [
            {
                "priority": 24,
                "icon": "🔬",
                "title": "Metadata inconsistencies detected — the file may have been edited",
                "detail": (
                    "The source data shows signs of editing, stripping, or generation tools. "
                    "If this file is being used as proof of something (identity, payment, "
                    "ownership), request the original unmodified version."
                ),
                "tags": ["provenance"],
            },
        ],
    },
}


class ChecklistGenerator:
    """Generate a personalized, prioritized fraud-prevention checklist."""

    # ─────────────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────────────
    def generate(
        self,
        image_result: Optional[dict] = None,
        audio_result: Optional[dict] = None,
        text_result: Optional[dict] = None,
        exif_result: Optional[dict] = None,
        risk_level: str = "low_risk",
    ) -> dict:
        """
        Returns the full checklist structure.

        `risk_level` comes from the scoring engine — we use it to decide
        whether to include base items only, or prepend triggered items.
        """
        triggered: list[dict] = []
        sources: list[str] = []

        # ── Text ─────────────────────────────────────────────
        if text_result and text_result.get("verdict") not in (None, "unavailable"):
            verdict = text_result["verdict"]
            items = TRIGGERS["text"].get(verdict, [])
            triggered.extend(items)
            if items:
                sources.append(f"message ({verdict.replace('_', ' ')})")

        # ── Image ────────────────────────────────────────────
        if image_result and image_result.get("verdict") not in (None, "unavailable"):
            verdict = image_result["verdict"]
            items = TRIGGERS["image"].get(verdict, [])
            triggered.extend(items)
            if items:
                sources.append(f"image ({verdict.replace('_', ' ')})")

        # ── Audio ────────────────────────────────────────────
        if audio_result and audio_result.get("verdict") not in (None, "unavailable"):
            verdict = audio_result["verdict"]
            items = TRIGGERS["audio"].get(verdict, [])
            triggered.extend(items)
            if items:
                sources.append(f"audio ({verdict.replace('_', ' ')})")

        # ── Source / metadata ────────────────────────────────
        if exif_result and not exif_result.get("reason"):
            source_verdict = self._source_verdict(exif_result)
            items = TRIGGERS["source"].get(source_verdict, [])
            triggered.extend(items)
            if items:
                sources.append(f"source ({source_verdict.replace('_', ' ')})")

        # ── Merge with base items, dedupe by title, sort by priority ──
        all_items = self._merge_items(triggered, BASE_ITEMS)
        all_items.sort(key=lambda x: x["priority"])

        # ── Determine headline urgency ───────────────────────
        urgency = self._urgency_from_risk(risk_level, triggered)

        # ── Title ────────────────────────────────────────────
        title = self._title_from_context(urgency, triggered, sources)

        result = {
            "title": title,
            "urgency": urgency,
            "items": all_items,
            "sources": sources,
            "total_items": len(all_items),
            "disclaimer": (
                "This checklist is generated by MediaShield AI based on the signals "
                "detected in your scan. It is not legal or financial advice. When in "
                "doubt, contact your bank or local cybercrime authority directly."
            ),
        }

        logger.info(
            f"Checklist: urgency={urgency} items={len(all_items)} "
            f"sources={sources or ['none']}"
        )
        return result

    # ─────────────────────────────────────────────────────────
    # INTERNALS
    # ─────────────────────────────────────────────────────────
    def _merge_items(
        self,
        triggered: list[dict],
        base: list[dict],
    ) -> list[dict]:
        """Dedupe by title, keeping the highest-urgency (lowest priority number) version."""
        seen: dict[str, dict] = {}

        for item in triggered + base:
            key = item["title"].lower()
            if key not in seen or item["priority"] < seen[key]["priority"]:
                seen[key] = item

        return list(seen.values())

    def _urgency_from_risk(self, risk_level: str, triggered: list[dict]) -> str:
        if risk_level == "high_risk" or any(t["priority"] <= 5 for t in triggered):
            return "immediate"
        if risk_level == "suspicious" or triggered:
            return "warn"
        return "informational"

    def _title_from_context(
        self,
        urgency: str,
        triggered: list[dict],
        sources: list[str],
    ) -> str:
        if urgency == "immediate":
            if any("voice" in s for s in sources):
                return "🚨 Act now — this voice may be a clone"
            if any("message" in s for s in sources):
                return "🚨 Act now — this message shows strong scam signals"
            if any("image" in s for s in sources):
                return "🚨 Act now — this image is likely AI-generated"
            return "🚨 Act now — high fraud risk detected"
        if urgency == "warn":
            return "⚠️ Review carefully — some fraud signals detected"
        return "✅ No major fraud indicators — basic safety steps"

    def _source_verdict(self, exif_result: dict) -> str:
        """Mirror of the logic in scoring.py — kept in sync."""
        anomalies = exif_result.get("anomalies", [])
        if not exif_result.get("exif_present"):
            return "no_metadata"
        if anomalies:
            return "metadata_anomalies"
        return "partial_metadata"


# Module-level singleton
checklist_generator = ChecklistGenerator()