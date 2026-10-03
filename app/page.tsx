'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clipboard,
  CloudUpload,
  FileText,
  History,
  Image as ImageIcon,
  Inbox,
  Info,
  Link2,
  Loader2,
  LockKeyhole,
  Mail,
  Menu,
  MessageSquare,
  Network,
  Radar,
  RefreshCw,
  ScanSearch,
  Search,
  Shield,
  ShieldCheck,
  Sparkles,
  Upload,
  X,
  Zap,
} from 'lucide-react'

const API_BASE = (process.env.NEXT_PUBLIC_DIGITAL_GUARDIAN_API_URL ?? '').replace(/\/$/, '')
const API_CONFIGURED = true
const USING_LOCAL_API = !API_BASE
const MAX_FILE_SIZE = 8 * 1024 * 1024
const stages = ['Receiving input', 'Extracting signals', 'Checking suspicious patterns', 'Analyzing threat indicators', 'Running AI investigation', 'Building security assessment']

type Tab = 'smart' | 'url' | 'message' | 'screenshot'
type ScanResult = Record<string, any>

type HistoryItem = Record<string, any>

function firstValue(obj: ScanResult | undefined, keys: string[]) {
  if (!obj) return undefined
  for (const key of keys) {
    const value = key.split('.').reduce((acc: any, part) => acc?.[part], obj)
    if (value !== undefined && value !== null && value !== '') return value
  }
  return undefined
}

function listValue(obj: ScanResult | undefined, keys: string[]): any[] {
  const value = firstValue(obj, keys)
  if (Array.isArray(value)) return value
  if (typeof value === 'string' && value.trim()) return [value]
  return []
}

function labelForLevel(level: unknown) {
  if (!level) return 'UNKNOWN'
  return String(level).replace(/_/g, ' ').toUpperCase()
}

function toneForLevel(level: unknown) {
  const value = String(level ?? '').toLowerCase()
  if (value.includes('high') || value.includes('critical') || value.includes('danger')) return 'danger'
  if (value.includes('susp') || value.includes('medium') || value.includes('warn')) return 'warning'
  if (value.includes('low') || value.includes('safe') || value.includes('benign')) return 'safe'
  return 'neutral'
}

function formatDate(value: unknown) {
  if (!value) return '—'
  const date = new Date(String(value))
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}

export default function Page() {
  const [tab, setTab] = useState<Tab>('smart')
  const [input, setInput] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [preview, setPreview] = useState('')
  const [result, setResult] = useState<ScanResult | null>(null)
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [isScanning, setIsScanning] = useState(false)
  const [stage, setStage] = useState(0)
  const [status, setStatus] = useState<'checking' | 'online' | 'offline'>('checking')
  const [error, setError] = useState('')
  const [historyError, setHistoryError] = useState('')
  const [mobileOpen, setMobileOpen] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)

  async function checkHealth() {
    if (!API_CONFIGURED) {
      setStatus('offline')
      return
    }
    try {
      const response = await fetch(`${API_BASE}/api/health`, { cache: 'no-store' })
      setStatus(response.ok ? 'online' : 'offline')
    } catch {
      setStatus('offline')
    }
  }

  async function getHistory() {
    if (!API_CONFIGURED) {
      setHistoryError('Backend URL is not configured. Add NEXT_PUBLIC_DIGITAL_GUARDIAN_API_URL to connect scan history.')
      return
    }
    try {
      setHistoryError('')
      const response = await fetch(`${API_BASE}/api/history`, { cache: 'no-store' })
      if (!response.ok) throw new Error()
      const payload = await response.json()
      const items = Array.isArray(payload) ? payload : payload.history ?? payload.scans ?? payload.data ?? []
      setHistory(Array.isArray(items) ? items : [])
    } catch {
      setHistoryError('Unable to load scan history.')
    }
  }

  useEffect(() => {
    checkHealth()
    getHistory()
  }, [])

  useEffect(() => {
    if (!isScanning) return
    const timer = window.setInterval(() => setStage((current) => Math.min(current + 1, stages.length - 1)), 650)
    return () => window.clearInterval(timer)
  }, [isScanning])

  function chooseFile(nextFile: File | undefined) {
    if (!nextFile) return
    if (!['image/png', 'image/jpeg', 'image/webp'].includes(nextFile.type)) {
      setError('Please choose a PNG, JPG, JPEG or WEBP image.')
      return
    }
    if (nextFile.size > MAX_FILE_SIZE) {
      setError('That image is larger than 8 MB. Please choose a smaller file.')
      return
    }
    setError('')
    setFile(nextFile)
    setPreview(URL.createObjectURL(nextFile))
  }

  async function analyze(payload: { text: string; input_type: string } | FormData) {
    if (!API_CONFIGURED) {
      setError('The Digital Guardian backend is not connected. Configure NEXT_PUBLIC_DIGITAL_GUARDIAN_API_URL to enable live analysis.')
      return
    }
    setError('')
    setResult(null)
    setIsScanning(true)
    setStage(0)
    try {
      const response = await fetch(`${API_BASE}${payload instanceof FormData ? '/api/analyze-screenshot' : '/api/analyze'}`, {
        method: 'POST',
        ...(payload instanceof FormData ? { body: payload } : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
      })
      const body = await response.json().catch(() => null)
      if (!response.ok) throw new Error(typeof body?.detail === 'string' ? body.detail : 'The analysis could not be completed.')
      if (!body || typeof body !== 'object') throw new Error('The backend returned an invalid analysis.')
      setResult(body)
      await getHistory()
      setTimeout(() => document.getElementById('results')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50)
    } catch (caught) {
      setError(caught instanceof Error && caught.message !== 'Failed to fetch' ? caught.message : 'Unable to complete the analysis. Please check that the Digital Guardian backend is running and try again.')
    } finally {
      setIsScanning(false)
    }
  }

  function submit() {
    if (tab === 'screenshot') {
      if (!file) return setError('Choose a screenshot before starting the analysis.')
      const formData = new FormData()
      formData.append('image', file)
      return analyze(formData)
    }
    const trimmed = input.trim()
    if (!trimmed) return setError('Add something suspicious to analyze first.')
    analyze({ text: trimmed, input_type: tab === 'smart' ? 'text' : tab === 'url' ? 'url' : 'message' })
  }

  const score = firstValue(result ?? undefined, ['risk_score', 'score', 'risk.score'])
  const level = firstValue(result ?? undefined, ['threat_level', 'threatLevel', 'level', 'risk_level', 'risk.level'])
  const evidence = listValue(result ?? undefined, ['evidence', 'reasons', 'indicators', 'findings'])
  const recommendations = listValue(result ?? undefined, ['recommendations', 'recommended_actions', 'actions'])
  const attackStory = listValue(result ?? undefined, ['attack_story', 'attackStory', 'scenario', 'story'])
  const ai = firstValue(result ?? undefined, ['ai_investigation', 'ai_analysis', 'ai', 'investigation'])
  const screenshotIntel = firstValue(result ?? undefined, ['screenshot_intelligence', 'screenshotIntelligence', 'image_analysis'])
  const stats = useMemo(() => ({ total: history.length, high: history.filter((item) => ['high', 'critical', 'danger'].some((v) => String(firstValue(item, ['threat_level', 'level', 'risk_level'])).toLowerCase().includes(v))).length, suspicious: history.filter((item) => String(firstValue(item, ['threat_level', 'level', 'risk_level'])).toLowerCase().includes('susp')).length, low: history.filter((item) => String(firstValue(item, ['threat_level', 'level', 'risk_level'])).toLowerCase().includes('low')).length }), [history])

  function scrollTo(id: string) { setMobileOpen(false); document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' }) }

  return (
    <main className="app-shell">
      <header className="topbar">
        <button className="brand" onClick={() => scrollTo('home')} aria-label="Digital Guardian home"><span className="brand-mark"><Shield size={20} /></span><span><strong>DIGITAL</strong><strong>GUARDIAN</strong></span></button>
        <button className="menu-button" onClick={() => setMobileOpen((value) => !value)} aria-label="Toggle navigation"><Menu size={21} /></button>
        <nav className={mobileOpen ? 'nav-links open' : 'nav-links'} aria-label="Main navigation"><button onClick={() => scrollTo('home')}>Home</button><button onClick={() => scrollTo('scanner')}>Scan</button><button onClick={() => scrollTo('history')}>History</button><button onClick={() => scrollTo('how-it-works')}>How It Works</button><button onClick={() => scrollTo('about')}>About</button></nav>
        <div className="top-actions"><div className="status-pill"><span className={`status-dot ${status}`} />{status === 'online' ? 'System Operational' : status === 'offline' ? 'System Offline' : 'Checking status'}</div><button className="button button-primary compact" onClick={() => scrollTo('scanner')}>Start Scan <ArrowRight size={15} /></button></div>
      </header>

      <section id="home" className="hero section-wrap"><div className="hero-copy"><div className="eyebrow"><span className="eyebrow-line" /> TRUST NOTHING. VERIFY EVERYTHING.</div><h1>Check before<br /><em>you trust.</em></h1><p>Analyze suspicious links, messages, emails and screenshots before they become a threat.</p><div className="hero-actions"><button className="button button-primary" onClick={() => scrollTo('scanner')}>Start Security Scan <ArrowRight size={16} /></button><button className="button button-ghost" onClick={() => scrollTo('how-it-works')}>How It Works <ChevronRight size={16} /></button></div><div className="hero-meta"><span><CheckCircle2 size={15} /> No automatic actions</span><span><LockKeyhole size={15} /> Your data stays yours</span></div></div><div className="hero-visual" aria-label="Abstract security visualization"><div className="orbit orbit-a" /><div className="orbit orbit-b" /><div className="orbit orbit-c" /><div className="visual-core"><ShieldCheck size={61} strokeWidth={1.2} /><span>GUARDIAN<br /><b>ACTIVE</b></span></div><div className="signal signal-a"><span>URL</span><b>VERIFIED</b></div><div className="signal signal-b"><span>AI</span><b>ANALYZING</b></div><div className="visual-grid" /></div></section>

      <section className="trust-strip"><div><span className="strip-icon"><Radar size={18} /></span><span><b>Real-time threat analysis</b><small>Powered by your security backend</small></span></div><div><span className="strip-icon"><Network size={18} /></span><span><b>Multi-signal detection</b><small>URLs, messages, images and more</small></span></div><div><span className="strip-icon"><Sparkles size={18} /></span><span><b>Clear, actionable guidance</b><small>Understand what to do next</small></span></div></section>

      <section id="scanner" className="scanner-section section-wrap"><div className="section-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> SECURITY ANALYSIS</div><h2>Analyze something suspicious.</h2><p>Paste a link, message, email or upload a screenshot to investigate potential threats.</p></div><div className="live-badge"><span className="pulse" /> LIVE ANALYSIS</div></div><div className="scanner-card"><div className="tabs" role="tablist">{([['smart', 'Smart Scan', ScanSearch], ['url', 'URL', Link2], ['message', 'Message / Email', MessageSquare], ['screenshot', 'Screenshot', ImageIcon]] as const).map(([id, label, Icon]) => <button key={id} className={tab === id ? 'tab active' : 'tab'} onClick={() => { setTab(id); setError('') }} role="tab" aria-selected={tab === id}><Icon size={16} /> {label}</button>)}</div><div className="scanner-body">{tab === 'screenshot' ? <div className="upload-layout"><div className={`dropzone ${file ? 'has-file' : ''}`} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); chooseFile(event.dataTransfer.files[0]) }} onClick={() => fileInput.current?.click()} role="button" tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') fileInput.current?.click() }}><input ref={fileInput} type="file" accept="image/png,image/jpeg,image/webp" hidden onChange={(event) => chooseFile(event.target.files?.[0])} />{preview ? <img src={preview} alt="Selected screenshot preview" /> : <><span className="upload-icon"><CloudUpload size={25} /></span><b>Drop a suspicious screenshot here</b><span>or choose an image from your device</span><small>PNG, JPG, JPEG or WEBP · Max 8 MB</small></>}</div>{file && <div className="file-details"><div className="file-row"><div className="file-thumb">{preview && <img src={preview} alt="" />}</div><span><b>{file.name}</b><small>{(file.size / 1024 / 1024).toFixed(2)} MB</small></span><button className="icon-button" onClick={(event) => { event.stopPropagation(); setFile(null); setPreview('') }} aria-label="Remove screenshot"><X size={16} /></button></div><button className="button button-primary full" onClick={submit} disabled={isScanning}><ScanSearch size={16} /> Analyze Screenshot</button></div>}</div> : <div className="text-input-wrap"><label htmlFor="threat-input">{tab === 'url' ? 'Suspicious URL' : tab === 'message' ? 'Message or email content' : 'Suspicious content'}<span>{tab === 'smart' ? 'AUTO-DETECT' : tab === 'url' ? 'URL' : 'MESSAGE'}</span></label><textarea id="threat-input" value={input} onChange={(event) => setInput(event.target.value)} placeholder={tab === 'url' ? 'https://example.com/…' : tab === 'message' ? 'Paste the suspicious SMS, WhatsApp message, email or social media message…' : 'Paste a suspicious link, message, email or other content here…'} disabled={isScanning} /><div className="input-footer"><span><Info size={14} /> Never click suspicious links before analyzing</span><span>{input.length} characters</span></div><button className="button button-primary full" onClick={submit} disabled={isScanning}>{isScanning ? <><Loader2 className="spin" size={16} /> Analyzing threat</> : <><ScanSearch size={16} /> {tab === 'url' ? 'Check URL' : tab === 'message' ? 'Analyze Message' : 'Analyze Threat'}</>}</button></div>}</div></div>{error && <div className="error-banner" role="alert"><AlertTriangle size={17} /><span>{error}</span><button onClick={() => setError('')} aria-label="Dismiss error"><X size={15} /></button></div>}{isScanning && <div className="progress-card"><div className="progress-top"><span><Loader2 size={16} className="spin" /> Investigation in progress</span><b>{String(stage + 1).padStart(2, '0')} / 06</b></div><div className="progress-bar"><span style={{ width: `${((stage + 1) / 6) * 100}%` }} /></div><div className="stage-grid">{stages.map((item, index) => <div key={item} className={index <= stage ? 'stage done' : 'stage'}><span>{String(index + 1).padStart(2, '0')}</span>{item}{index < stage && <Check size={13} />}</div>)}</div></div>}</section>

      {result && <section id="results" className="results-section section-wrap"><div className="result-header"><div><div className="eyebrow"><span className="eyebrow-line" /> SECURITY ASSESSMENT</div><h2>Here&apos;s what we found.</h2><p>Risk score is an analytical indicator, not a probability of compromise.</p></div><div className={`threat-badge ${toneForLevel(level)}`}><span /><b>{labelForLevel(level)}</b><small>THREAT LEVEL</small></div></div><div className="assessment-grid"><div className="score-card"><div className="card-kicker">RISK SCORE <Info size={13} /></div><div className="score-ring" style={{ '--score': `${Math.min(100, Math.max(0, Number(score) || 0)) * 3.6}deg` } as React.CSSProperties}><div><strong>{score ?? '—'}</strong><span>/ 100</span></div></div><div className="score-caption"><span className={`legend-dot ${toneForLevel(level)}`} /> {labelForLevel(level)} assessment</div></div><div className="finding-card"><div className="card-kicker">WHY WE FLAGGED IT <span>{evidence.length} signals detected</span></div>{evidence.length ? <div className="evidence-list">{evidence.map((item, index) => <div className="evidence-item" key={index}><span className="evidence-icon"><AlertTriangle size={15} /></span><span>{typeof item === 'string' ? item : item?.reason ?? item?.description ?? item?.name ?? JSON.stringify(item)}</span></div>)}</div> : <div className="empty-state"><CheckCircle2 size={18} /> No evidence was returned for this assessment.</div>}</div></div>{attackStory.length > 0 && <div className="content-card"><div className="card-kicker">POSSIBLE ATTACK STORY</div><div className="story-list">{attackStory.map((item, index) => <div className="story-step" key={index}><span>{String(index + 1).padStart(2, '0')}</span><div><b>{typeof item === 'string' ? item : item?.title ?? item?.step ?? item?.description ?? JSON.stringify(item)}</b><small>Analytical scenario, not proof an attack occurred</small></div></div>)}</div></div>}{(ai || recommendations.length > 0) && <div className="two-column">{ai && <div className="content-card ai-card"><div className="card-kicker"><Sparkles size={14} /> AI-POWERED INVESTIGATION</div><div className="ai-copy">{typeof ai === 'string' ? ai : ai?.assessment ?? ai?.summary ?? ai?.reasoning ?? JSON.stringify(ai)}</div><small className="disclaimer">AI-generated analysis. AI analysis can contain mistakes. Verify important information independently.</small></div>}{recommendations.length > 0 && <div className="content-card"><div className="card-kicker">WHAT YOU SHOULD DO</div><ul className="action-list">{recommendations.map((item, index) => <li key={index}><CheckCircle2 size={16} /> {typeof item === 'string' ? item : item?.action ?? item?.description ?? JSON.stringify(item)}</li>)}</ul></div>}</div>}{screenshotIntel && <div className="content-card"><div className="card-kicker"><ImageIcon size={14} /> SCREENSHOT INTELLIGENCE</div><div className="intel-grid">{Object.entries(typeof screenshotIntel === 'object' ? screenshotIntel : { 'AI OBSERVATION': screenshotIntel }).filter(([, value]) => value !== undefined && value !== null && value !== '').map(([key, value]) => <div className="intel-item" key={key}><small>{key.replace(/_/g, ' ').toUpperCase()}</small><b>{Array.isArray(value) ? value.join(', ') : String(value)}</b></div>)}</div></div>}<div className="result-actions"><button className="button button-primary" onClick={() => { setResult(null); scrollTo('scanner') }}><RefreshCw size={16} /> Scan Another</button><button className="button button-ghost" onClick={() => scrollTo('history')}><History size={16} /> View History</button></div></section>}

      <section id="history" className="history-section section-wrap"><div className="section-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> ACTIVITY LOG</div><h2>Your scan history.</h2><p>Review assessments returned by the Digital Guardian backend.</p></div><button className="button button-ghost compact" onClick={getHistory}><RefreshCw size={15} /> Refresh</button></div><div className="stats-grid"><div><BarChart3 size={17} /><span><b>{stats.total}</b><small>Total scans</small></span></div><div><AlertTriangle size={17} /><span><b>{stats.high}</b><small>High risk</small></span></div><div><Zap size={17} /><span><b>{stats.suspicious}</b><small>Suspicious</small></span></div><div><CheckCircle2 size={17} /><span><b>{stats.low}</b><small>Low risk</small></span></div></div>{historyError ? <div className="empty-history"><AlertTriangle size={20} /><p>{historyError}</p></div> : history.length === 0 ? <div className="empty-history"><History size={22} /><p>No scans yet.</p><small>Completed analyses will appear here.</small></div> : <div className="history-table"><div className="history-head"><span>SCAN ID</span><span>TYPE</span><span>RISK SCORE</span><span>THREAT LEVEL</span><span>DATE</span></div>{history.map((item, index) => { const itemLevel = firstValue(item, ['threat_level', 'level', 'risk_level']); return <button className="history-row" key={index} onClick={() => { setResult(item); scrollTo('results') }}><span className="scan-id">#{firstValue(item, ['id', 'scan_id', 'scanId']) ?? String(index + 1).padStart(4, '0')}</span><span>{labelForLevel(firstValue(item, ['input_type', 'type', 'scan_type']))}</span><span className="row-score">{firstValue(item, ['risk_score', 'score', 'risk.score']) ?? '—'}<small>/100</small></span><span><i className={`table-dot ${toneForLevel(itemLevel)}`} />{labelForLevel(itemLevel)}</span><span>{formatDate(firstValue(item, ['created_at', 'timestamp', 'date', 'createdAt']))}</span></button> })}</div>}</section>

      <section id="how-it-works" className="how-section section-wrap"><div className="section-heading centered"><div><div className="eyebrow"><span className="eyebrow-line" /> THE METHOD</div><h2>Clarity before action.</h2><p>Digital Guardian turns suspicious content into a clear security decision.</p></div></div><div className="steps-grid">{[['01', 'INPUT', 'Submit a suspicious URL, message, email or screenshot.', Inbox], ['02', 'SIGNAL EXTRACTION', 'Relevant security indicators are extracted from the content.', Search], ['03', 'THREAT ANALYSIS', 'Suspicious patterns and indicators are evaluated.', Radar], ['04', 'AI INVESTIGATION', 'Contextual analysis helps explain what the signals mean.', Sparkles], ['05', 'SECURITY GUIDANCE', 'Receive an assessment and recommended next steps.', ShieldCheck]].map(([number, title, copy, Icon]) => <div className="method-step" key={String(number)}><span className="step-number">{String(number)}</span><div className="method-icon"><Icon size={19} /></div><h3>{String(title)}</h3><p>{String(copy)}</p></div>)}</div></section>

      <section className="features-section section-wrap"><div className="section-heading centered"><div><div className="eyebrow"><span className="eyebrow-line" /> BUILT FOR SIGNAL</div><h2>One place to pause.</h2><p>Understand the risk across the channels where threats arrive.</p></div></div><div className="feature-grid">{[['URL Analysis', 'Inspect links and domains for suspicious patterns.', Link2], ['Message Analysis', 'Surface urgency, impersonation and manipulation cues.', MessageSquare], ['Screenshot Intelligence', 'Extract and interpret visual signals from screenshots.', ImageIcon], ['OCR Extraction', 'Read text embedded in images without clicking through.', FileText], ['Threat Indicators', 'See the evidence behind every assessment.', AlertTriangle], ['AI Investigation', 'Get a contextual explanation of the findings.', Sparkles], ['Risk Scoring', 'Use a clear analytical indicator to guide your next move.', BarChart3], ['Scan History', 'Keep a private record of completed assessments.', History]].map(([title, copy, Icon]) => <div className="feature-card" key={String(title)}><div className="feature-icon"><Icon size={18} /></div><h3>{String(title)}</h3><p>{String(copy)}</p><ChevronRight size={16} className="feature-arrow" /></div>)}</div></section>

      <section className="safety-section section-wrap"><div className="safety-panel"><div className="safety-copy"><div className="eyebrow"><span className="eyebrow-line" /> TRUST & SAFETY</div><h2>Built to help you<br /><em>pause before you act.</em></h2><p>Digital Guardian is an analytical tool for better information—not a guarantee. You remain in control of every decision.</p></div><div className="safety-list"><div><ShieldCheck size={18} /><span><b>No automatic actions</b><small>We never open links or act on your behalf.</small></span></div><div><LockKeyhole size={18} /><span><b>You stay in control</b><small>Results are guidance, not instructions.</small></span></div><div><Info size={18} /><span><b>Verify important decisions</b><small>AI can make mistakes. Check independently.</small></span></div></div></div></section>

      <section id="about" className="about-section section-wrap"><div className="about-mark"><Shield size={34} /></div><div><div className="eyebrow"><span className="eyebrow-line" /> ABOUT DIGITAL GUARDIAN</div><h2>Security decisions should start with better information.</h2><p>Digital Guardian helps people inspect suspicious digital content before interacting with it—so a moment of verification can prevent a costly mistake.</p></div></section>

      <footer className="footer"><div className="brand footer-brand"><span className="brand-mark"><Shield size={18} /></span><span><strong>DIGITAL</strong><strong>GUARDIAN</strong></span></div><span>Check before you trust.</span><span>© 2026 Digital Guardian</span></footer><button className="back-top" onClick={() => scrollTo('home')} aria-label="Back to top"><ChevronDown size={17} /></button>
    </main>
  )
}
