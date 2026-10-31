import { useEffect, useState } from 'react'
import { getHealth } from './api.js'
import Dashboard from './components/Dashboard.jsx'
import MediaScanner from './components/MediaScanner.jsx'
import MessageAnalyzer from './components/MessageAnalyzer.jsx'
import SourceVerifier from './components/SourceVerifier.jsx'

const TABS = [
  { id: 'scanner', label: 'Media Scanner', icon: '🔍' },
  { id: 'message', label: 'Message Analyzer', icon: '💬' },
  { id: 'source', label: 'Source Verifier', icon: '🧾' },
  { id: 'dashboard', label: 'Dashboard', icon: '📊' },
]

export default function App() {
  const [tab, setTab] = useState('scanner')
  const [health, setHealth] = useState(null)
  const [healthError, setHealthError] = useState(null)
  // Shared result so Dashboard can show the latest scan regardless of tab
  const [latestResult, setLatestResult] = useState(null)

  // Poll health every 30s — nice live indicator for demos
  useEffect(() => {
    let cancelled = false
    const check = async () => {
      try {
        const h = await getHealth()
        if (!cancelled) {
          setHealth(h)
          setHealthError(null)
        }
      } catch (e) {
        if (!cancelled) {
          setHealth(null)
          setHealthError(e.message)
        }
      }
    }
    check()
    const t = setInterval(check, 30_000)
    return () => {
      cancelled = true
      clearInterval(t)
    }
  }, [])

  // Called by child components when a scan completes
  const handleResult = (result) => {
    setLatestResult(result)
  }

  const healthState = healthError
    ? { cls: 'degraded', text: 'Backend offline' }
    : health?.status === 'ok'
      ? { cls: 'ok', text: 'All systems ready' }
      : health?.status === 'degraded'
        ? { cls: 'degraded', text: 'Degraded — some models offline' }
        : { cls: '', text: 'Checking…' }

  const renderTab = () => {
    switch (tab) {
      case 'scanner':
        return <MediaScanner onResult={handleResult} />
      case 'message':
        return <MessageAnalyzer onResult={handleResult} />
      case 'source':
        return <SourceVerifier onResult={handleResult} />
      case 'dashboard':
        return <Dashboard result={latestResult} />
      default:
        return null
    }
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <img src="/shield.svg" alt="" className="brand-icon" />
          <div>
            <div className="brand-title">MediaShield AI</div>
            <div className="brand-sub">Everyday digital fraud protection</div>
          </div>
        </div>
        <div className="health-pill" title={healthError || 'Backend health'}>
          <span className={`health-dot ${healthState.cls}`} />
          <span>{healthState.text}</span>
        </div>
      </header>

      <main className="app-main">
        <nav className="tabs">
          {TABS.map((t) => (
            <button
              key={t.id}
              className={`tab ${tab === t.id ? 'active' : ''}`}
              onClick={() => setTab(t.id)}
            >
              <span>{t.icon}</span>
              <span>{t.label}</span>
              {t.id === 'dashboard' && latestResult && (
                <span className="tab-badge">1</span>
              )}
            </button>
          ))}
        </nav>

        {renderTab()}
      </main>

      <footer className="app-footer">
        MediaShield AI · Hackathon MVP · Not a substitute for professional cybersecurity advice
      </footer>
    </div>
  )
}