# MediaShield AI

> **Everyday digital fraud protection.**
> Detect deepfakes, voice clones, phishing messages, and suspicious source metadata — then get a personalized prevention checklist.

**SHIELD Track — Everyday Digital Fraud & Scam Protection**
Computer Society (CS) · Hackathon Submission

---

## The Problem

Fraud has gone multimodal.

- A cloned voice calls a parent pretending to be their child in trouble.
- An AI-generated ID photo passes a KYC check.
- A "bank KYC" SMS with a shortened URL harvests OTPs in 60 seconds.
- A "job offer" image has EXIF stripped — because it was never photographed.

Existing tools detect **one** modality. Real fraud uses **whichever the victim trusts most**. MediaShield AI scans **all of them** — image, audio, and text — and produces a **single risk verdict plus a personalized action plan**.

---

## What It Does

| Feature | What It Answers |
|---|---|
| **🖼️ Image Deepfake Detector** | Is this photo AI-generated or captured by a real camera? |
| **🎙️ Voice Clone Detector** | Is this audio a real human or a synthetic voice? |
| **💬 Message Analyzer** | Is this SMS/email/chat a phishing attempt? |
| **🧾 Source Verifier** | Where did this image actually come from? |
| **📊 Unified Risk Score** | One number (0–100) blending all signals with confidence-aware weighting |
| **✅ Personalized Checklist** | Specific, actionable steps for the threats we found |

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    FRONTEND (React + Vite)                  │
│                                                             │
│  Media Scanner │ Message Analyzer │ Source Verifier │ Dash  │
└──────────────────────────┬──────────────────────────────────┘
                           │  REST (JSON + multipart)
                           │  (Vite proxy in dev)
┌──────────────────────────▼──────────────────────────────────┐
│                   BACKEND (FastAPI + Uvicorn)               │
│                                                             │
│  POST /api/scan/image      POST /api/scan/audio             │
│  POST /api/scan/message    POST /api/scan/full              │
│  POST /api/verify/source   GET  /health                     │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │            Inference Orchestrator                     │  │
│  │                                                       │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐      │  │
│  │  │ ImageDetector│ │AudioDetector│ │TextAnalyzer │      │  │
│  │  │  ViT (fake  │ │ Wav2Vec2    │ │ BERT        │      │  │
│  │  │  vs real)   │ │ (real/fake) │ │ (phishing)  │      │  │
│  │  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘      │  │
│  │         └────────────────┼───────────────┘             │  │
│  │                          ▼                             │  │
│  │              ┌─────────────────────┐                   │  │
│  │              │  Scoring Engine     │                   │  │
│  │              │  (confidence-aware  │                   │  │
│  │              │   weighted average) │                   │  │
│  │              └──────────┬──────────┘                   │  │
│  │                         ▼                              │  │
│  │              ┌─────────────────────┐                   │  │
│  │              │ Checklist Generator │                   │  │
│  │              │ (context-aware)     │                   │  │
│  │              └─────────────────────┘                   │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐     │
│  │ EXIF Parser  │ │ C2PA Verify  │ │ SHA-256 Hashing  │     │
│  │ (Pillow)     │ │ (stub)       │ │ (tamper track)   │     │
│  └──────────────┘ └──────────────┘ └──────────────────┘     │
└─────────────────────────────────────────────────────────────┘