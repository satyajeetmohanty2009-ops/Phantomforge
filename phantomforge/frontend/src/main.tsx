import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import Convert from 'ansi-to-html'
import { Activity, Database, FileText, Play, Radio, Search, ShieldCheck, Square, Terminal, Upload } from 'lucide-react'
import './styles.css'

type Run = { id: number; target: string; status: string; phase: string; created_at: string; html_report?: string }
type Finding = { id: number; run_id: number; phase: string; kind: string; title: string; severity: string; data: any }
type Cracked = { run_id: number; source: string; format: string; hash: string; password: string }
type LogEvent = { run_id: number; phase: string; line: string }

const ansi = new Convert({ fg: '#d6deeb', bg: '#0f141b', newline: false })

function api<T>(path: string, init?: RequestInit): Promise<T> {
  return fetch(path, { headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) }, ...init }).then(async r => {
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText)
    return r.json()
  })
}

function App() {
  const [tab, setTab] = useState('run')
  const [runs, setRuns] = useState<Run[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [cracked, setCracked] = useState<Cracked[]>([])
  const [logs, setLogs] = useState<Record<string, LogEvent[]>>({})
  const [activeRun, setActiveRun] = useState<number | null>(null)
  const [query, setQuery] = useState('')
  const [form, setForm] = useState({
    target: '192.0.2.10',
    scope: '192.0.2.0/24',
    nmapFlags: '-sV -sC -O --top-ports 1000',
    capture: true,
    sqlmap: true,
    beef: true,
    john: true,
    gates: true,
    iface: 'eth0',
    duration: 30,
  })

  const refresh = () => {
    api<Run[]>('/api/runs').then(setRuns).catch(console.error)
    api<Finding[]>('/api/findings').then(setFindings).catch(console.error)
    api<Cracked[]>('/api/cracked').then(setCracked).catch(console.error)
  }

  useEffect(() => {
    refresh()
    const timer = setInterval(refresh, 2500)
    const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`)
    ws.onmessage = e => {
      const event: LogEvent = JSON.parse(e.data)
      setActiveRun(event.run_id)
      setLogs(prev => ({ ...prev, [event.phase]: [...(prev[event.phase] || []), event].slice(-1000) }))
      if (['DONE', 'FAILED', 'STOPPED'].includes(event.phase)) refresh()
    }
    return () => { clearInterval(timer); ws.close() }
  }, [])

  const startRun = async () => {
    const res = await api<{ id: number }>('/api/runs', {
      method: 'POST',
      body: JSON.stringify({
        target: form.target,
        scope: form.scope,
        config: {
          auto_approve_gates: form.gates,
          capture_enabled: form.capture,
          sqlmap_enabled: form.sqlmap,
          beef_enabled: form.beef,
          john_enabled: form.john,
          gate_before_sqlmap: form.gates,
          gate_before_beef: form.gates,
          gate_before_crack: form.gates,
          nmap: { flags: form.nmapFlags },
          tshark: { interface: form.iface, duration: form.duration },
        }
      })
    })
    setActiveRun(res.id)
    refresh()
  }

  const stopRun = async () => {
    if (!activeRun) return
    await api(`/api/runs/${activeRun}/stop`, { method: 'POST' })
    refresh()
  }

  const filtered = useMemo(() => findings.filter(f => JSON.stringify(f).toLowerCase().includes(query.toLowerCase())), [findings, query])
  const phases = ['RECON', 'CAPTURE', 'WEBVULN', 'HOOK', 'CRACK', 'REPORT', 'DONE', 'FAILED', 'STOPPED']

  return <div className="app">
    <aside>
      <div className="brand"><ShieldCheck size={24}/><span>PhantomForge</span></div>
      {[
        ['run', Activity, 'Targets'],
        ['console', Terminal, 'Live Console'],
        ['findings', Search, 'Findings'],
        ['capture', Radio, 'Capture'],
        ['reports', FileText, 'Reports'],
      ].map(([id, Icon, label]: any) => <button key={id} className={tab === id ? 'active' : ''} onClick={() => setTab(id)}><Icon size={18}/>{label}</button>)}
      <div className="status">Active run<br/><strong>{activeRun ? `#${activeRun}` : 'none'}</strong></div>
    </aside>
    <main>
      {tab === 'run' && <section>
        <header><h1>Targets & Run Config</h1><div className="actions"><button onClick={startRun}><Play size={16}/>Start</button><button className="danger" onClick={stopRun}><Square size={16}/>Stop</button></div></header>
        <div className="grid two">
          <label>Target<input value={form.target} onChange={e => setForm({...form, target: e.target.value})}/></label>
          <label>Authorized target scope<input value={form.scope} onChange={e => setForm({...form, scope: e.target.value})}/></label>
          <label>Nmap flags<input value={form.nmapFlags} onChange={e => setForm({...form, nmapFlags: e.target.value})}/></label>
          <label>Capture interface<input value={form.iface} onChange={e => setForm({...form, iface: e.target.value})}/></label>
          <label>Capture duration<input type="number" value={form.duration} onChange={e => setForm({...form, duration: Number(e.target.value)})}/></label>
        </div>
        <div className="toggles">
          {(['capture','sqlmap','beef','john','gates'] as const).map(k => <label key={k} className="toggle"><input type="checkbox" checked={form[k] as boolean} onChange={e => setForm({...form, [k]: e.target.checked})}/><span>{k}</span></label>)}
        </div>
        <RunTable runs={runs}/>
      </section>}
      {tab === 'console' && <section>
        <header><h1>Live Console</h1></header>
        <div className="phaseTabs">{phases.map(p => <a href={`#${p}`} key={p}>{p}<small>{logs[p]?.length || 0}</small></a>)}</div>
        {phases.map(p => <div className="consoleBlock" id={p} key={p}><h2>{p}</h2><pre dangerouslySetInnerHTML={{__html: (logs[p] || []).map(e => `<span class="run">#${e.run_id}</span> ${ansi.toHtml(e.line)}`).join('\n')}} /></div>)}
      </section>}
      {tab === 'findings' && <section>
        <header><h1>Findings</h1><label className="search"><Search size={15}/><input placeholder="Search findings" value={query} onChange={e => setQuery(e.target.value)}/></label></header>
        <div className="cards">
          {filtered.map(f => <article key={f.id} className={`sev-${f.severity}`}><div><b>{f.title}</b><span>{f.phase} / {f.kind}</span></div><pre>{JSON.stringify(f.data, null, 2)}</pre></article>)}
        </div>
        <h2>Cracked Passwords</h2>
        <table><tbody>{cracked.map((c, i) => <tr key={i}><td>#{c.run_id}</td><td>{c.format}</td><td>{c.hash}</td><td><b>{c.password}</b></td></tr>)}</tbody></table>
      </section>}
      {tab === 'capture' && <CapturePanel findings={findings}/>}
      {tab === 'reports' && <section><header><h1>Reports</h1></header><RunTable runs={runs} reports/></section>}
    </main>
  </div>
}

function RunTable({runs, reports}: {runs: Run[], reports?: boolean}) {
  return <table><thead><tr><th>Run</th><th>Target</th><th>Status</th><th>Phase</th><th>Created</th>{reports && <th>Report</th>}</tr></thead><tbody>
    {runs.map(r => <tr key={r.id}><td>#{r.id}</td><td>{r.target}</td><td><span className={`pill ${r.status.toLowerCase()}`}>{r.status}</span></td><td>{r.phase}</td><td>{new Date(r.created_at).toLocaleString()}</td>{reports && <td><a href={`/api/reports/${r.id}/html`} target="_blank">Open HTML</a> · <a href={`/api/reports/${r.id}/md`}>Markdown</a></td>}</tr>)}
  </tbody></table>
}

function CapturePanel({findings}: {findings: Finding[]}) {
  const [upload, setUpload] = useState('')
  const summaries = findings.filter(f => f.phase === 'CAPTURE')
  const bars = ['HTTP', 'SMB', 'TLS', 'DNS'].map((name, i) => ({ name, value: Math.max(8, (summaries.length + 1) * (i + 2) * 9 % 90) }))
  const send = async (file?: File) => {
    if (!file) return
    const fd = new FormData(); fd.append('file', file)
    const r = await fetch('/api/pcaps', { method: 'POST', body: fd }).then(r => r.json())
    setUpload(r.path)
  }
  return <section><header><h1>Capture</h1><label className="upload"><Upload size={16}/>Upload pcap<input type="file" accept=".pcap,.pcapng" onChange={e => send(e.target.files?.[0])}/></label></header>
    {upload && <p className="notice">Uploaded: {upload}</p>}
    <svg viewBox="0 0 420 180" className="chart">{bars.map((b, i) => <g key={b.name}><text x="12" y={35 + i*35}>{b.name}</text><rect x="70" y={18 + i*35} width={b.value*3.2} height="20"/><text x={80 + b.value*3.2} y={34 + i*35}>{b.value}</text></g>)}</svg>
    <div className="cards">{summaries.map(f => <article key={f.id}><b>{f.title}</b><pre>{JSON.stringify(f.data, null, 2)}</pre></article>)}</div>
  </section>
}

createRoot(document.getElementById('root')!).render(<App />)
