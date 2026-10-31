import RiskGauge from './RiskGauge.jsx'
import FraudChecklist from './FraudChecklist.jsx'

function scoreColor(score) {
  if (score >= 61) return 'var(--risk-high)'
  if (score >= 31) return 'var(--risk-mid)'
  return 'var(--risk-low)'
}

export default function Dashboard({ result }) {
  if (!result) {
    return (
      <div className="card">
        <div className="empty-state">
          <div className="empty-icon">📊</div>
          <div className="empty-title">No scans yet</div>
          <div className="empty-hint">
            Run a Media Scanner, Message Analyzer, or Source Verifier scan to populate the dashboard.
          </div>
        </div>
      </div>
    )
  }

  const { score, checklist, scan_id, timestamp, coverage } = result
  const components = Object.entries(score.components || {})

  return (
    <>
      {/* ── Risk summary ────────────────────────────────── */}
      <div className="card">
        <div className="flex justify-between items-center mb-16" style={{ flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div className="card-title">Unified Risk Assessment</div>
            <div className="card-sub">
              Scan ID <span className="text-mono">{scan_id}</span> · {formatTime(timestamp)}
            </div>
          </div>
          <div className="flex gap-8">
            {coverage && Object.entries(coverage).map(([k, v]) => (
              <span key={k} className="checklist-tag" style={{ opacity: v ? 1 : 0.4 }}>
                {v ? '●' : '○'} {k}
              </span>
            ))}
          </div>
        </div>

        <RiskGauge
          score={score.risk_score}
          level={score.risk_level}
          summary={score.summary}
          confidence={score.confidence}
        />
      </div>

      {/* ── Component breakdown ─────────────────────────── */}
      {components.length > 0 && (
        <div className="card">
          <div className="card-title">Component Breakdown</div>
          <div className="card-sub">
            Each detector contributes to the unified score, weighted by its confidence.
          </div>
          <div>
            {components.map(([key, c]) => (
              <div key={key} className="component-row">
                <div className="component-label">
                  <div>{c.label}</div>
                  <div className="text-small text-muted" style={{ marginTop: 2 }}>
                    {formatVerdict(c.verdict)} · weight {c.weight}
                  </div>
                </div>
                <div className="component-bar">
                  <div
                    className="component-bar-fill"
                    style={{
                      width: `${Math.min(100, c.score)}%`,
                      background: scoreColor(c.score),
                    }}
                  />
                </div>
                <div className="component-score">{c.score.toFixed(0)}</div>
              </div>
            ))}
          </div>

          {/* Overrides (metadata penalties / C2PA) */}
          {score.overrides && hasOverrides(score.overrides) && (
            <div className="mt-16 text-small text-muted">
              <div style={{ marginBottom: 6 }}>Adjustments applied:</div>
              {score.overrides.metadata_penalties > 0 && (
                <div>+{score.overrides.metadata_penalties} — source metadata anomalies</div>
              )}
              {score.overrides.c2pa_bonus < 0 && (
                <div>{score.overrides.c2pa_bonus} — verified Content Credentials</div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Checklist ───────────────────────────────────── */}
      {checklist && <FraudChecklist data={checklist} />}
    </>
  )
}

function hasOverrides(o) {
  return (o.metadata_penalties || 0) > 0 || (o.c2pa_bonus || 0) < 0
}

function formatVerdict(v) {
  if (!v) return '—'
  return v.replace(/_/g, ' ')
}

function formatTime(iso) {
  if (!iso) return ''
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}