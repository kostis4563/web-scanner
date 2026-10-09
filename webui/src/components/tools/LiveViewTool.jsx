import { useRef, useState } from 'react'
import ToolShell from './ToolShell.jsx'
import { Segmented } from './ui.jsx'
import { Icon } from '../Icon.jsx'
import { isNative, openExternal } from '../../bridge.js'

const DEVICES = [
  { id: 'desktop', label: 'Desktop', w: null, h: 720 },
  { id: 'tablet', label: 'Tablet', w: 768, h: 1024 },
  { id: 'phone', label: 'Phone', w: 390, h: 844 },
]

const normalize = (s) => {
  const t = s.trim()
  if (!t) return ''
  return /^https?:\/\//i.test(t) ? t : `https://${t}`
}

export default function LiveViewTool() {
  const [input, setInput] = useState('')
  const [url, setUrl] = useState('')
  const [device, setDevice] = useState('desktop')
  const [nonce, setNonce] = useState(0) // bump to force an iframe reload
  const frameRef = useRef(null)

  const dev = DEVICES.find((d) => d.id === device)

  const go = (e) => {
    e?.preventDefault()
    const u = normalize(input)
    if (u) {
      setUrl(u)
      setNonce((n) => n + 1)
    }
  }
  const reload = () => url && setNonce((n) => n + 1)
  const external = () => {
    if (!url) return
    if (isNative) openExternal(url)
    else window.open(url, '_blank', 'noopener')
  }

  return (
    <ToolShell toolId="liveview">
      <form onSubmit={go} className="flex flex-wrap items-center gap-2">
        <div className="flex min-w-[220px] flex-1 items-center gap-2 rounded-xl border border-line bg-surface px-3.5 focus-within:border-ink-strong/40">
          <Icon name="globe" className="h-4 w-4 shrink-0 text-ink-faint" />
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="example.com"
            spellCheck={false}
            autoComplete="off"
            className="h-10 w-full bg-transparent font-mono text-[13.5px] text-ink-strong outline-none placeholder:text-ink-faint"
          />
        </div>
        <button
          type="submit"
          className="flex h-10 items-center gap-1.5 rounded-xl bg-ink-strong px-4 text-[13.5px] font-semibold text-bg transition-opacity hover:opacity-90"
        >
          <Icon name="zap" className="h-4 w-4" strokeWidth={2} /> Load
        </button>
      </form>

      {url && (
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
          <Segmented options={DEVICES} value={device} onChange={setDevice} />
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={reload}
              className="flex h-9 w-9 items-center justify-center rounded-lg border border-line bg-surface text-ink-secondary transition-colors hover:border-line-strong hover:text-ink-strong"
              title="Reload"
            >
              <Icon name="refresh" className="h-4 w-4" />
            </button>
            <button
              type="button"
              onClick={external}
              className="flex h-9 items-center gap-1.5 rounded-lg border border-line bg-surface px-3.5 text-[13px] font-medium text-ink-secondary transition-colors hover:border-line-strong hover:text-ink-strong"
            >
              <Icon name="arrowUpRight" className="h-4 w-4" /> Open
            </button>
          </div>
        </div>
      )}

      {url ? (
        <div className="mt-3 overflow-hidden rounded-xl border border-line bg-surface-raised">
          <div className="flex items-center gap-1.5 border-b border-dashed border-line px-3 py-2">
            <span className="h-2.5 w-2.5 rounded-full bg-line-strong" />
            <span className="h-2.5 w-2.5 rounded-full bg-line-strong" />
            <span className="h-2.5 w-2.5 rounded-full bg-line-strong" />
            <code className="ml-2 truncate font-mono text-[11.5px] text-ink-muted">{url}</code>
          </div>
          <div className="flex justify-center overflow-auto bg-bg p-3" style={{ maxHeight: '70vh' }}>
            <iframe
              key={nonce}
              ref={frameRef}
              src={url}
              title="Live view"
              className="rounded-md border border-line bg-white"
              style={{ width: dev.w ? `${dev.w}px` : '100%', height: `${dev.h}px`, maxWidth: '100%' }}
              sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
              referrerPolicy="no-referrer"
            />
          </div>
        </div>
      ) : (
        <div className="mt-6 rounded-xl border border-dashed border-line px-4 py-12 text-center">
          <Icon name="monitor" className="mx-auto h-6 w-6 text-ink-faint" />
          <p className="mt-3 text-[13px] text-ink-subtle">Enter a URL to load it in a live, interactive frame.</p>
        </div>
      )}

      {url && (
        <p className="mt-3 text-[12px] leading-relaxed text-ink-subtle">
          It’s a real, scrollable page — click and navigate inside it. Some sites refuse to be framed
          (<code className="font-mono">X-Frame-Options</code> / CSP <code className="font-mono">frame-ancestors</code>);
          if the frame stays blank, use <span className="text-ink-secondary">Open</span> to view it directly.
        </p>
      )}
    </ToolShell>
  )
}
