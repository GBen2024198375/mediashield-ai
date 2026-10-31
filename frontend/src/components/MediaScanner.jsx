import { useRef, useState } from 'react'
import { scanImage, scanAudio } from '../api.js'
import RiskGauge from './RiskGauge.jsx'
import FraudChecklist from './FraudChecklist.jsx'

export default function MediaScanner({ onResult }) {
  const [mode, setMode] = useState('image')  // 'image' | 'audio'

  return (
    <>
      <div className="card">
        <div className="flex justify-between items-center mb-16">
          <div>
            <div className="card-title">Media Scanner</div>
            <div className="card-sub">
              Upload an image to check for AI generation, or audio to detect voice clones.
            </div>
          </div>
          <div className="flex gap-8">
            <button
              className={`btn ${mode === 'image' ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setMode('image')}
            >
              🖼️ Image
            </button>
            <button
              className={`btn ${mode === 'audio' ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setMode('audio')}
            >
              🎙️ Audio
            </button>
          </div>
        </div>

        {mode === 'image'
          ? <ImageUploader onResult={onResult} />
          : <AudioUploader onResult={onResult} />}
      </div>
    </>
  )
}

// ─────────────────────────────────────────────────────────────
// IMAGE
// ─────────────────────────────────────────────────────────────
function ImageUploader({ onResult }) {
  const inputRef = useRef(null)
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const [dragOver, setDragOver] = useState(false)

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
      const r = await scanImage(file)
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
      <div
        className={`dropzone ${dragOver ? 'drag-over' : ''}`}
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDragOver(false)
          handleFile(e.dataTransfer.files?.[0])
        }}
      >
        <div className="dropzone-icon">🖼️</div>
        <div className="dropzone-title">
          Drop an image here, or click to browse
        </div>
        <div className="dropzone-hint">
          JPG · PNG · WebP · BMP · max 25 MB
        </div>
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
          <span>🖼️</span>
          <span className="file-preview-name">{file.name}</span>
          <span className="file-preview-size">{formatBytes(file.size)}</span>
          <button
            className="file-clear"
            onClick={(e) => { e.stopPropagation(); setFile(null); setResult(null) }}
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
          {loading ? <span className="spinner" /> : '🔍'} Scan image
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}
      {result && <ImageResult result={result} />}
    </>
  )
}

function ImageResult({ result }) {
  const { score, image, source, checklist } = result

  return (
    <>
      <div className="card mt-16">
        <div className="card-title">Verdict</div>
        <div className="card-sub">Deepfake detection + source verification.</div>
        <RiskGauge
          score={score.risk_score}
          level={score.risk_level}
          summary={score.summary}
          confidence={score.confidence}
        />
      </div>

      {image && image.verdict !== 'unavailable' && (
        <div className="card">
          <div className="card-title">Image Forensics</div>
          <table className="meta-table mt-8">
            <tbody>
              <tr>
                <td>Model verdict</td>
                <td>{image.verdict.replace(/_/g, ' ')}</td>
              </tr>
              <tr>
                <td>Fake probability</td>
                <td>{image.model_outputs?.fake != null
                  ? `${(image.model_outputs.fake * 100).toFixed(1)}%`
                  : '—'}</td>
              </tr>
              <tr>
                <td>Spectral ratio</td>
                <td>{image.spectrum_ratio}</td>
              </tr>
              <tr>
                <td>High-freq anomaly</td>
                <td>{image.high_freq_anomaly ? 'Yes' : 'No'}</td>
              </tr>
            </tbody>
          </table>
        </div>
      )}

      {source && (
        <div className="card">
          <div className="card-title">Source Metadata</div>
          <table className="meta-table mt-8">
            <tbody>
              <tr><td>EXIF present</td><td>{source.exif_present ? 'Yes' : 'No'}</td></tr>
              <tr><td>Camera make</td><td>{source.camera_make || '—'}</td></tr>
              <tr><td>Camera model</td><td>{source.camera_model || '—'}</td></tr>
              <tr><td>Software</td><td>{source.software || '—'}</td></tr>
              <tr><td>Timestamp</td><td>{source.timestamp || '—'}</td></tr>
              <tr><td>Format</td><td>{source.format || '—'}</td></tr>
              <tr>
                <td>SHA-256</td>
                <td className="mono-truncate" title={source.sha256}>
                  {source.sha256?.slice(0, 24)}…
                </td>
              </tr>
            </tbody>
          </table>

          {source.anomalies?.length > 0 && (
            <>
              <div className="mt-16 text-small text-muted">Metadata anomalies:</div>
              <ul className="signals">
                {source.anomalies.map((a, i) => (
                  <li key={i} className="signal">{a}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}

      {checklist && <FraudChecklist data={checklist} />}
    </>
  )
}

// ─────────────────────────────────────────────────────────────
// AUDIO
// ─────────────────────────────────────────────────────────────
function AudioUploader({ onResult }) {
  const inputRef = useRef(null)
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const [dragOver, setDragOver] = useState(false)

  const handleFile = (f) => {
    if (!f) return
    if (!f.type.startsWith('audio/')) {
      setError('Not an audio file')
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
      const r = await scanAudio(file)
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
      <div
        className={`dropzone ${dragOver ? 'drag-over' : ''}`}
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDragOver(false)
          handleFile(e.dataTransfer.files?.[0])
        }}
      >
        <div className="dropzone-icon">🎙️</div>
        <div className="dropzone-title">
          Drop an audio file here, or click to browse
        </div>
        <div className="dropzone-hint">
          WAV · MP3 · FLAC · OGG · max 25 MB · best on 5–30 second clips
        </div>
        <input
          ref={inputRef}
          type="file"
          accept="audio/*"
          hidden
          onChange={(e) => handleFile(e.target.files?.[0])}
        />
      </div>

      {file && (
        <div className="file-preview">
          <span>🎙️</span>
          <span className="file-preview-name">{file.name}</span>
          <span className="file-preview-size">{formatBytes(file.size)}</span>
          <button
            className="file-clear"
            onClick={(e) => { e.stopPropagation(); setFile(null); setResult(null) }}
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
          {loading ? <span className="spinner" /> : '🔍'} Scan audio
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}
      {result && <AudioResult result={result} />}
    </>
  )
}

function AudioResult({ result }) {
  const { score, audio, checklist } = result

  return (
    <>
      <div className="card mt-16">
        <div className="card-title">Verdict</div>
        <div className="card-sub">Voice-clone / synthetic speech detection.</div>
        <RiskGauge
          score={score.risk_score}
          level={score.risk_level}
          summary={score.summary}
          confidence={score.confidence}
        />
      </div>

      {audio && audio.verdict !== 'unavailable' && (
        <div className="card">
          <div className="card-title">Audio Forensics</div>
          <table className="meta-table mt-8">
            <tbody>
              <tr><td>Model verdict</td><td>{audio.verdict.replace(/_/g, ' ')}</td></tr>
              <tr>
                <td>Fake probability</td>
                <td>{audio.model_outputs?.fake != null
                  ? `${(audio.model_outputs.fake * 100).toFixed(1)}%`
                  : '—'}</td>
              </tr>
              <tr><td>Duration</td><td>{audio.duration_seconds}s</td></tr>
              <tr><td>Chunks analyzed</td><td>{audio.chunks_analyzed}</td></tr>
              <tr><td>Spectral anomaly</td><td>{audio.spectral_anomaly ? 'Yes' : 'No'}</td></tr>
            </tbody>
          </table>
        </div>
      )}

      {checklist && <FraudChecklist data={checklist} />}
    </>
  )
}

// ─────────────────────────────────────────────────────────────
function formatBytes(n) {
  if (!n) return ''
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++ }
  return `${n.toFixed(1)} ${units[i]}`
}