import { useState } from 'react'
import { SEVERITY_META } from '../data/scanner.js'
import { Icon } from './Icon.jsx'

function Row({ label, children }) {
  if (!children || children === '—') return null
  return (
    <div className="grid grid-cols-[88px_1fr] gap-3 py-2 sm:grid-cols-[104px_1fr]">
      <dt className="font-mono text-[11px] uppercase tracking-wider text-ink-faint">{label}</dt>
      <dd className="text-[13px] leading-relaxed text-ink-secondary">{children}</dd>
    </div>
  )
}

export default function FindingCard({ finding }) {
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const sev = SEVERITY_META[finding.severity]

  const copyPoc = async () => {
    try {
      await navigator.clipboard.writeText(finding.reproduction)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch (e) {
    }
  }

  return (
    <div className="border-b border-dashed border-line last:border-b-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-3 px-4 py-4 text-left transition-colors duration-150 hover:bg-surface-hover/50 sm:px-6"
      >
        <span
          className="mt-0.5 h-2 w-2 shrink-0 rounded-full"
          style={{ background: sev.color, boxShadow: `0 0 10px ${sev.color}` }}
          aria-hidden
        />
        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-2">
            <span className="truncate text-[14px] font-semibold text-ink-strong">{finding.title}</span>
          </span>
          <span className="mt-0.5 flex items-center gap-2 font-mono text-[11.5px] text-ink-subtle">
            <span
              className="rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider"
              style={{ color: sev.color, background: `color-mix(in srgb, ${sev.color} 14%, transparent)` }}
            >
              {sev.label}
            </span>
            <span className="text-ink-faint">{finding.category}</span>
            <span className="truncate">{finding.location}</span>
          </span>
        </span>
        <Icon
          name="chevron"
          className={`h-4 w-4 shrink-0 text-ink-faint transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
        />
      </button>

      {open && (
        <div className="animate-rise px-4 pb-6 pl-9 sm:px-6 sm:pl-11">
          <dl className="divide-y divide-dashed divide-line/70">
            <Row label="Detail">{finding.detail}</Row>
            <Row label="Impact">{finding.exploit}</Row>
            <Row label="Fix">{finding.remediation}</Row>
            {finding.reference && <Row label="Ref">{finding.reference}</Row>}
          </dl>

          {finding.evidence && finding.evidence !== '—' && (
            <div className="mt-4">
              <p className="mb-1.5 font-mono text-[11px] uppercase tracking-wider text-ink-faint">Evidence</p>
              <pre className="overflow-x-auto rounded-lg border border-line bg-bg px-3.5 py-3 font-mono text-[12px] leading-5 text-ink-secondary">
                {finding.evidence}
              </pre>
            </div>
          )}

          {finding.reproduction && (
            <div className="mt-4">
              <div className="mb-1.5 flex items-center justify-between">
                <p className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-brand">
                  <Icon name="terminal" className="h-3.5 w-3.5" /> Proof of concept
                </p>
                <button
                  type="button"
                  onClick={copyPoc}
                  className="flex items-center gap-1.5 rounded-md px-2 py-1 font-mono text-[11px] text-ink-muted transition-colors hover:text-ink-strong"
                >
                  <Icon name={copied ? 'check' : 'copy'} className="h-3.5 w-3.5" />
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
              <pre className="overflow-x-auto rounded-lg border border-brand/25 bg-brand/5 px-3.5 py-3 font-mono text-[12px] leading-5 text-ink">
                {finding.reproduction}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
