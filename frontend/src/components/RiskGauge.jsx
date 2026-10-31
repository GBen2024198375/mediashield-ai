/**
 * RiskGauge — circular SVG gauge for a 0-100 risk score.
 * Color-coded by band. Animates stroke-dashoffset on mount.
 */
import { useEffect, useState } from 'react'

function levelClass(level) {
  if (level === 'high_risk') return 'high'
  if (level === 'suspicious') return 'mid'
  if (level === 'low_risk') return 'low'
  return 'unknown'
}

function levelLabel(level) {
  switch (level) {
    case 'high_risk':   return 'HIGH RISK'
    case 'suspicious':  return 'SUSPICIOUS'
    case 'low_risk':    return 'LOW RISK'
    default:            return 'UNKNOWN'
  }
}

function strokeColor(level) {
  switch (level) {
    case 'high_risk':  return 'var(--risk-high)'
    case 'suspicious': return 'var(--risk-mid)'
    case 'low_risk':   return 'var(--risk-low)'
    default:           return 'var(--risk-unknown)'
  }
}

export default function RiskGauge({ score = 0, level = 'unknown', summary, confidence }) {
  const size = 140
  const stroke = 12
  const radius = (size - stroke) / 2
  const circumference = 2 * Math.PI * radius

  const [animatedScore, setAnimatedScore] = useState(0)
  const [pct, setPct] = useState(0)

  useEffect(() => {
    // Brief animation from current value to target
    const start = animatedScore
    const end = Math.max(0, Math.min(100, score))
    const duration = 700
    const t0 = performance.now()

    let raf
    const tick = (t) => {
      const elapsed = t - t0
      const progress = Math.min(1, elapsed / duration)
      const eased = 1 - Math.pow(1 - progress, 3) // ease-out cubic
      const value = start + (end - start) * eased
      setAnimatedScore(value)
      setPct(value / 100)
      if (progress < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [score])

  const offset = circumference * (1 - pct)
  const cls = levelClass(level)

  return (
    <div className="gauge-wrap">
      <svg
        className="gauge-svg"
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        aria-label={`Risk score ${Math.round(animatedScore)} out of 100`}
      >
        {/* Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--bg-3)"
          strokeWidth={stroke}
        />
        {/* Progress */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={strokeColor(level)}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: 'stroke 0.3s' }}
        />
        {/* Center text */}
        <text
          x="50%"
          y="47%"
          textAnchor="middle"
          dominantBaseline="middle"
          fontSize="30"
          fontWeight="700"
          fill="var(--fg-0)"
        >
          {Math.round(animatedScore)}
        </text>
        <text
          x="50%"
          y="65%"
          textAnchor="middle"
          dominantBaseline="middle"
          fontSize="11"
          fill="var(--fg-3)"
          letterSpacing="1.5"
        >
          RISK / 100
        </text>
      </svg>

      <div className="gauge-meta">
        <div className={`gauge-level ${cls}`}>{levelLabel(level)}</div>
        {summary && <div className="gauge-summary">{summary}</div>}
        {typeof confidence === 'number' && (
          <div className="gauge-confidence">
            confidence: {(confidence * 100).toFixed(0)}%
          </div>
        )}
      </div>
    </div>
  )
}