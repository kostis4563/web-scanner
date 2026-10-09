import { useState } from 'react'
import { Icon } from '../Icon.jsx'

export function Label({ children }) {
  return (
    <span className="mb-2 block font-mono text-[10px] uppercase tracking-[0.2em] text-ink-subtle">
      {children}
    </span>
  )
}

export function CopyButton({ value, label = 'Copy', className = '' }) {
  const [done, setDone] = useState(false)
  const copy = async () => {
    if (!value) return
    try {
      await navigator.clipboard.writeText(value)
    } catch {
      // Fallback for restricted contexts (e.g. file:// / WKWebView).
      const ta = document.createElement('textarea')
      ta.value = value
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      try {
        document.execCommand('copy')
      } catch {
        /* no-op */
      }
      document.body.removeChild(ta)
    }
    setDone(true)
    setTimeout(() => setDone(false), 1200)
  }
  return (
    <button
      type="button"
      onClick={copy}
      disabled={!value}
      className={`flex h-9 items-center gap-1.5 rounded-lg border border-line bg-surface px-3.5 text-[13px] font-medium text-ink-secondary transition-colors hover:border-line-strong hover:text-ink-strong disabled:cursor-not-allowed disabled:opacity-40 ${className}`}
    >
      <Icon name={done ? 'check' : 'copy'} className="h-4 w-4" />
      {done ? 'Copied' : label}
    </button>
  )
}

export function Textarea({ value, onChange, placeholder, rows = 5, readOnly = false, mono = true }) {
  return (
    <textarea
      value={value}
      onChange={onChange ? (e) => onChange(e.target.value) : undefined}
      placeholder={placeholder}
      rows={rows}
      readOnly={readOnly}
      spellCheck={false}
      autoComplete="off"
      className={`w-full resize-y rounded-xl border border-line bg-surface px-3.5 py-3 text-[13px] leading-relaxed text-ink-strong outline-none transition-colors placeholder:text-ink-faint focus:border-ink-strong/40 ${
        mono ? 'font-mono' : 'font-sans'
      } ${readOnly ? 'text-ink-secondary' : ''}`}
    />
  )
}

// A segmented control (same look as the intensity picker in ScanForm).
export function Segmented({ options, value, onChange }) {
  return (
    <div className="inline-flex flex-wrap gap-1 rounded-xl border border-line bg-surface p-1">
      {options.map((o) => {
        const id = typeof o === 'string' ? o : o.id
        const label = typeof o === 'string' ? o : o.label
        const active = id === value
        return (
          <button
            key={id}
            type="button"
            onClick={() => onChange(id)}
            aria-pressed={active}
            className={`rounded-lg px-3 py-1.5 text-[12.5px] font-medium transition-colors duration-200 ${
              active ? 'bg-ink-strong text-bg' : 'text-ink-muted hover:text-ink-strong'
            }`}
          >
            {label}
          </button>
        )
      })}
    </div>
  )
}

export function ErrorNote({ children }) {
  if (!children) return null
  return (
    <div
      role="alert"
      className="mt-3 flex items-start gap-3 rounded-xl border border-dashed border-sev-critical/40 bg-sev-critical/[0.06] px-4 py-3"
    >
      <span className="mt-px font-mono text-[10px] font-semibold uppercase tracking-[0.2em] text-sev-critical">
        err
      </span>
      <p className="text-[13px] leading-relaxed text-ink-strong">{children}</p>
    </div>
  )
}
