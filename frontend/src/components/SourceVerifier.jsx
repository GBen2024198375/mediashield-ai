import { useRef, useState } from 'react'
import { verifySource } from '../api.js'
import RiskGauge from './RiskGauge.jsx'

export default function SourceVerifier({ onResult }) {
  const inputRef = useRef(null)
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  const handleFile = (f) => {
    if (!f) return
    if (!f.type.startsWith('image/')) {
      setError('Not an image file')
      return
    }
    setFile(f)
    setError(null)
    setResult(null)
  }

  const handleScan = async () => {
    if (!file) return
    setLoading(true)
    setError(null)
    try {
      const r = await verifySource(file)
      setResult(r)
      onResult?.(r)
    } catch (e) {
      setError(e.message || 'Scan failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <div className="card">
        <div className="card-title">Source Verifier</div>
        <div className="card-sub">
          Extract EXIF, XMP, GPS, and provenance signals from an image. Faster than a
          full scan — useful when you only need the metadata story.
        </div>

        <div
          className="dropzone"
          onClick={() => inputRef.current?.click()}
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => { e.preventDefault(); handleFile(e.dataTransfer.files?.[0]) }}
        >
          <div className="dropzone-icon">🧾</div>
          <div className="dropzone-title">Drop an image here, or click to browse</div>
          <div className="dropzone-hint">JPG · PNG · WebP · BMP · max 25 MB</div>
          <input
            ref={inputRef}
            type="file"
            accept="image/*"
            hidden
            onChange={(e) => handleFile(e.target.files?.[0])}
          />
        </div>

        {file && (
          <div className="file-preview">
            <span>🧾</span>
            <span className="file-preview-name">{file.name}</span>
            <button
              className="file-clear"
              onClick={() => { setFile(null); setResult(null) }}
              aria-label="Clear file"
            >×</button>
          </div>
        )}

        <div className="flex gap-8 mt-16">
          <button
            className="btn btn-primary"
            onClick={handleScan}
            disabled={!file || loading}
          >
            {loading ? <span className="spinner" /> : '🔍'} Verify source
          </button>
        </div>

        {error && <div className="error-box">{error}</div>}
      </div>

      {result && <SourceResult result={result} />}
    </>
  )
}

function SourceResult({ result }) {
  const { score, source } = result
  if (!source) return null

  return (
    <>
      <div className="card">
        <div className="card-title">Provenance verdict</div>
        <div className="card-sub">Metadata-based trust assessment.</div>
        <RiskGauge
          score={score.risk_score}
          level={score.risk_level}
          summary={score.summary}
          confidence={score.confidence}
        />
      </div>

      <div className="card">
        <div className="card-title">Extracted metadata</div>
        <table className="meta-table mt-8">
          <tbody>
            <tr><td>Format</td><td>{source.format || '—'}</td></tr>
            <tr><td>Dimensions</td>
              <td>{source.image_dimensions ? source.image_dimensions.join(' × ') : '—'}</td>
            </tr>
            <tr><td>EXIF present</td><td>{source.exif_present ? 'Yes' : 'No'}</td></tr>
            <tr><td>Camera make</td><td>{source.camera_make || '—'}</td></tr>
            <tr><td>Camera model</td><td>{source.camera_model || '—'}</td></tr>
            <tr><td>Software</td><td>{source.software || '—'}</td></tr>
            <tr><td>Timestamp</td><td>{source.timestamp || '—'}</td></tr>
            <tr>
              <td>GPS</td>
              <td>
                {source.gps
                  ? `${source.gps.lat.toFixed(4)}, ${source.gps.lon.toFixed(4)}`
                  : '—'}
              </td>
            </tr>
            <tr>
              <td>C2PA Content Credentials</td>
              <td>
                {source.c2pa?.valid
                  ? `Valid (${source.c2pa.signer || 'unknown signer'})`
                  : `Not verified (${source.c2pa?.reason || 'unavailable'})`}
              </td>
            </tr>
            <tr>
              <td>SHA-256</td>
              <td className="mono-truncate" title={source.sha256}>
                {source.sha256?.slice(0, 32)}…
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      {source.anomalies?.length > 0 && (
        <div className="card">
          <div className="card-title">Anomalies detected</div>
          <div className="card-sub">
            Metadata inconsistencies suggest editing, stripping, or generation.
          </div>
          <ul className="signals">
            {source.anomalies.map((a, i) => (
              <li key={i} className="signal">{a}</li>
            ))}
          </ul>
        </div>
      )}
    </>
  )
}