
"""
MediaShield AI — Unified Risk Aggregator

Combines detector outputs into a single 0-100 risk score.
- Confidence-aware weighting
- Automatic re-normalization for available detectors
- Metadata and C2PA adjustments
- Explainable results and uncertainty-aware summaries
"""

from __future__ import annotations

import logging
from typing import Optional

from config import SCORING_WEIGHTS, SCORE_OVERRIDES, RISK_BANDS

logger = logging.getLogger("mediashield.scoring")


COMPONENT_LABELS = {
    "image_model": "Image Deepfake Model",
    "image_forensics": "Image Frequency Forensics",
    "audio_model": "Voice Clone Model",
    "text_model": "Message Phishing Model",
    "source_metadata": "Source / Metadata Verification",
}


class ScoringEngine:
    """Aggregates detector results into a unified risk score."""

    def aggregate(
        self,
        image_result: Optional[dict] = None,
        audio_result: Optional[dict] = None,
        text_result: Optional[dict] = None,
        exif_result: Optional[dict] = None,
    ) -> dict:

        # 1. Collect available components
        components: dict[str, dict] = {}

        self._add_component(
            components, "image_model",
            self._extract_image_component(image_result),
        )

        self._add_component(
            components, "image_forensics",
            self._extract_image_forensics(image_result),
        )

        self._add_component(
            components, "audio_model",
            self._extract_audio_component(audio_result),
        )

        self._add_component(
            components, "text_model",
            self._extract_text_component(text_result),
        )

        self._add_component(
            components, "source_metadata",
            self._extract_source_component(exif_result),
        )

        if not components:
            return self._empty_result()

        # 2. Calculate weighted average
        total_weight = sum(
            component["weight"]
            for component in components.values()
        )

        if total_weight <= 0:
            return self._empty_result()

        weighted_sum = sum(
            component["score"] * component["weight"]
            for component in components.values()
        )

        base_score = weighted_sum / total_weight

        # 3. Apply metadata and C2PA adjustments
        overrides = self._apply_overrides(base_score, exif_result)
        final_score = overrides["final_score"]

        # 4. Calculate confidence
        confidence = self._compute_confidence(components)

        # 5. Classify risk and generate explanation
        risk_level = self._band(final_score)

        summary = self._summarize(
            risk_level,
            final_score,
            components,
            overrides,
        )

        logger.info(
            "Scoring: base=%.1f final=%.1f level=%s components=%d",
            base_score,
            final_score,
            risk_level,
            len(components),
        )

        return {
            "risk_score": round(final_score, 1),
            "risk_level": risk_level,
            "confidence": round(confidence, 3),
            "components": components,
            "overrides": overrides,
            "summary": summary,
            "coverage": {
                "image": (
                    image_result is not None
                    and image_result.get("verdict") != "unavailable"
                    and image_result.get("reason") is None
                ),
                "audio": (
                    audio_result is not None
                    and audio_result.get("verdict") != "unavailable"
                    and audio_result.get("reason") is None
                ),
                "text": (
                    text_result is not None
                    and text_result.get("verdict") != "unavailable"
                    and text_result.get("reason") is None
                ),
                "source": (
                    exif_result is not None
                    and exif_result.get("reason") is None
                ),
            },
        }

    # ---------------------------------------------------------
    # Component extraction
    # ---------------------------------------------------------

    def _extract_image_component(
        self, result: Optional[dict]
    ) -> Optional[dict]:

        if (
            not result
            or result.get("verdict") == "unavailable"
            or result.get("reason")
        ):
            return None

        return {
            "score": result.get("score", 0.0),
            "verdict": result.get("verdict", "inconclusive"),
            "confidence": result.get("confidence", 0.5),
        }

    def _extract_image_forensics(
        self, result: Optional[dict]
    ) -> Optional[dict]:

        if (
            not result
            or result.get("reason")
            or not result.get("high_freq_anomaly")
        ):
            return None

        return {
            "score": 60.0,
            "verdict": "spectral_anomaly",
            "confidence": 0.5,
        }

    def _extract_audio_component(
        self, result: Optional[dict]
    ) -> Optional[dict]:

        if (
            not result
            or result.get("verdict") == "unavailable"
            or result.get("reason")
        ):
            return None

        return {
            "score": result.get("score", 0.0),
            "verdict": result.get("verdict", "inconclusive"),
            "confidence": result.get("confidence", 0.5),
        }

    def _extract_text_component(
        self, result: Optional[dict]
    ) -> Optional[dict]:

        if (
            not result
            or result.get("verdict") == "unavailable"
            or result.get("reason")
        ):
            return None

        return {
            "score": result.get("score", 0.0),
            "verdict": result.get("verdict", "inconclusive"),
            "confidence": result.get("confidence", 0.5),
        }

    def _extract_source_component(
        self, result: Optional[dict]
    ) -> Optional[dict]:

        if not result or result.get("reason"):
            return None

        no_exif = not result.get("exif_present")
        anomalies = result.get("anomalies", [])

        # Missing EXIF alone is not proof of a fake image.
        # Keep independently identified metadata anomalies.
        source_score = result.get("risk_score", 0.0)

        if no_exif and not anomalies:
            source_score = 0.0

        return {
            "score": source_score,
            "verdict": self._source_verdict(result),
            "confidence": 0.7,
        }

    def _source_verdict(self, result: dict) -> str:
        anomalies = result.get("anomalies", [])

        if (
            not anomalies
            and result.get("camera_make")
            and result.get("camera_model")
        ):
            return "verified_provenance"

        if not result.get("exif_present"):
            return "no_metadata"

        if anomalies:
            return "metadata_anomalies"

        return "partial_metadata"

    def _add_component(
        self,
        components: dict,
        key: str,
        extracted: Optional[dict],
    ) -> None:

        if extracted is None:
            return

        weight = SCORING_WEIGHTS.get(key, 0.0)

        if weight <= 0:
            return

        score = max(0.0, min(100.0, float(extracted["score"])))
        confidence = max(
            0.0,
            min(1.0, float(extracted.get("confidence", 0.5))),
        )

        # Reduce the influence of uncertain detectors.
        effective_weight = weight * (0.4 + 0.6 * confidence)

        components[key] = {
            "label": COMPONENT_LABELS.get(key, key),
            "score": round(score, 1),
            "verdict": extracted["verdict"],
            "confidence": round(confidence, 3),
            "weight": round(effective_weight, 4),
            "present": True,
        }

    # ---------------------------------------------------------
    # Overrides
    # ---------------------------------------------------------

    def _apply_overrides(
        self,
        base_score: float,
        exif_result: Optional[dict],
    ) -> dict:

        final_score = base_score
        anomaly_count = 0
        metadata_penalty = 0.0

        if exif_result and not exif_result.get("reason"):
            anomalies = exif_result.get("anomalies", [])

            # Do not count the absence of EXIF as an anomaly penalty
            # unless the parser identifies a separate anomaly.
            anomaly_count = len(anomalies)

            metadata_penalty = min(
                anomaly_count
                * SCORE_OVERRIDES["metadata_anomaly_penalty"],
                SCORE_OVERRIDES["metadata_anomaly_cap"],
            )

            final_score += metadata_penalty

        # Deliberately disable the separate missing-EXIF penalty.
        # Missing metadata can occur in genuine shared photographs.
        no_exif_penalty = 0.0

        c2pa_valid = bool(
            exif_result
            and exif_result.get("c2pa", {}).get("valid")
        )

        c2pa_bonus = (
            SCORE_OVERRIDES["c2pa_valid_bonus"]
            if c2pa_valid
            else 0.0
        )

        final_score += c2pa_bonus
        final_score = max(0.0, min(100.0, final_score))

        return {
            "metadata_anomalies": anomaly_count,
            "metadata_penalty": round(metadata_penalty, 1),
            "no_exif_penalty": no_exif_penalty,
            "c2pa_valid": c2pa_valid,
            "c2pa_bonus": round(c2pa_bonus, 1),
            "base_score": round(base_score, 1),
            "final_score": round(final_score, 1),
        }

    # ---------------------------------------------------------
    # Confidence and classification
    # ---------------------------------------------------------

    def _compute_confidence(self, components: dict) -> float:

        if not components:
            return 0.0

        coverage = min(
            1.0,
            len(components) / max(1, len(SCORING_WEIGHTS)),
        )

        average_confidence = sum(
            component["confidence"]
            for component in components.values()
        ) / len(components)

        return min(
            1.0,
            coverage * 0.6 + average_confidence * 0.4,
        )

    def _band(self, score: float) -> str:

        if score <= RISK_BANDS["low_risk"][1]:
            return "low_risk"

        if score <= RISK_BANDS["suspicious"][1]:
            return "suspicious"

        return "high_risk"

    def _summarize(
        self,
        risk_level: str,
        score: float,
        components: dict,
        overrides: dict,
    ) -> str:

        if risk_level == "high_risk":
            top = self._top_component(components)

            uncertain_verdicts = {
                "inconclusive",
                "no_metadata",
                "partial_metadata",
            }

            if top["verdict"] in uncertain_verdicts:
                return (
                    f"High risk ({score:.0f}/100), but the "
                    "primary signal is inconclusive. "
                    "Verify the source independently."
                )

            return (
                f"High risk ({score:.0f}/100). "
                f"Primary signal: {top['label']} flagged "
                f"'{top['verdict']}'."
            )

        if risk_level == "suspicious":
            return (
                f"Suspicious ({score:.0f}/100). "
                "Some risk indicators were detected. "
                "Verify the source before acting."
            )

        return (
            f"Low risk ({score:.0f}/100). "
            "No major fraud indicators detected. "
            "This does not guarantee authenticity."
        )

    def _top_component(self, components: dict) -> dict:
        return max(
            components.values(),
            key=lambda component: (
                component["score"] * component["weight"]
            ),
        )

    def _empty_result(self) -> dict:
        return {
            "risk_score": 0.0,
            "risk_level": "unknown",
            "confidence": 0.0,
            "components": {},
            "overrides": {},
            "summary": "No detectable input was provided.",
            "coverage": {
                "image": False,
                "audio": False,
                "text": False,
                "source": False,
            },
        }


# Module-level singleton
scoring_engine = ScoringEngine()
