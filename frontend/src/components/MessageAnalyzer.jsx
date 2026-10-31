import { useState } from 'react'
import { scanMessage } from '../api.js'
import RiskGauge from './RiskGauge.jsx'

const EXAMPLES = [
  {
    label: 'Bank KYC scam',
    text: 'URGENT: Your SBI account is suspended due to incomplete KYC. Verify immediately at http://sbi-verify.co.in and share your OTP to reactivate. Failure will result in permanent closure.',
  },
  {
    label: 'Delivery fee scam',
    text: 'Your parcel is held at customs. Pay the clearance fee of Rs.50 within 24 hours at http://bit.ly/payfees or it will be returned to sender.',
  },
  {
    label: 'Job offer scam',
    text: 'Congratulations! You have been selected for a work-from-home job with Rs.5000 daily income. Pay Rs.1500 registration fee to get started. Contact us on WhatsApp for details.',
  },
  {
    label: 'Clean message',
    text: 'Hey, are we still on for dinner at 8? I made a reservation at the Italian place near your office.',
  },
]

export default function MessageAnalyzer({ onResult }) {
  const [text, setText] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  const handleScan = async () => {
    if (!text.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const r = await scanMessage(text)
      setResult(r)
      onResult?.(r)
    } catch (e) {
      setError(e.message || 'Scan failed')
    } finally {
      setLoading(false)
    }
  }

  const handleExample = (t) => setText(t)

  return (
    <>
      <div className="card">
        <div className="card-title">Suspicious Message Analyzer</div>
        <div className="card-sub">
          Paste an SMS, WhatsApp, or email. We detect phishing patterns, urgency tactics,
          credential requests, and payment lures.
        </div>

        <textarea
          className="textarea"
          placeholder="Paste the suspicious message here…"
          value={text}
          onChange={(e) => setText(e.target.value)}
          maxLength={10000}
          disabled={loading}
        />

        <div className="flex gap-8 mt-16" style={{ flexWrap: 'wrap' }}>
          <button
            className="btn btn-primary"
            onClick={handleScan}
            disabled={!text.trim() || loading}
          >
            {loading ? <span className="spinner" /> : '🔍'} Analyze message
          </button>
          <button
            className="btn btn-ghost"
            onClick={() => { setText(''); setResult(null); setError(null) }}
            disabled={loading}
          >
            Clear
          </button>
        </div>

        {error && <div className="error-box">{error}</div>}
      </div>

      {/* Example messages */}
      {!result && (
        <div className="card">
          <div className="card-title">Try an example</div>
          <div className="card-sub">
            Click any of these to load a demo message. All are synthetic but based on real
            scam templates.
          </div>
          <div className="flex gap-8" style={{ flexWrap: 'wrap' }}>
            {EXAMPLES.map((ex) => (
              <button
                key={ex.label}
                className="btn btn-ghost"
                onClick={() => handleExample(ex.text)}
                disabled={loading}
              >
                {ex.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Result */}
      {result && <MessageResult result={result} />}
    </>
  )
}

function MessageResult({ result }) {
  const { score, text: textResult } = result

  return (
    <>
      <div className="card">
        <div className="card-title">Verdict</div>
        <div className="card-sub">
          Confidence-aware risk assessment based on {textResult?.model_outputs ? '3 sources' : 'rules'}.
        </div>
        <RiskGauge
          score={score.risk_score}
          level={score.risk_level}
          summary={score.summary}
          confidence={score.confidence}
        />
      </div>

      {textResult?.signals?.length > 0 && (
        <div className="card">
          <div className="card-title">Why we flagged this</div>
          <div className="card-sub">Evidence extracted from the message.</div>
          <ul className="signals">
            {textResult.signals.map((s, i) => (
              <li key={i} className="signal high">{s}</li>
            ))}
          </ul>

          {textResult.urls?.length > 0 && (
            <>
              <div className="mt-16 text-small text-muted">Extracted URLs:</div>
              <ul className="signals">
                {textResult.urls.map((u, i) => (
                  <li key={i} className="signal high text-mono">{u}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}

      {textResult?.model_outputs && (
        <div className="card">
          <div className="card-title">Model confidence</div>
          <div className="card-sub">Raw classifier probabilities.</div>
          <div className="component-row">
            <div className="component-label">Phishing likelihood</div>
            <div className="component-bar">
              <div
                className="component-bar-fill"
                style={{
                  width: `${(textResult.model_outputs.phishing * 100).toFixed(0)}%`,
                  background: 'var(--risk-high)',
                }}
              />
            </div>
            <div className="component-score">
              {(textResult.model_outputs.phishing * 100).toFixed(0)}
            </div>
          </div>
          <div className="component-row">
            <div className="component-label">Legitimate likelihood</div>
            <div className="component-bar">
              <div
                className="component-bar-fill"
                style={{
                  width: `${(textResult.model_outputs.legitimate * 100).toFixed(0)}%`,
                  background: 'var(--risk-low)',
                }}
              />
            </div>
            <div className="component-score">
              {(textResult.model_outputs.legitimate * 100).toFixed(0)}
            </div>
          </div>
        </div>
      )}
    </>
  )
}