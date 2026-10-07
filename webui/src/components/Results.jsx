import { useMemo, useState } from 'react'
import { SEVERITIES, SEVERITY_META, MODES } from '../data/scanner.js'
import FindingCard from './FindingCard.jsx'
import { Icon } from './Icon.jsx'

export default function Results({ mode, target, findings, onNewScan, onExport }) {
  const [filter, setFilter] = useState('all')
  const modeLabel = MODES.find((m) => m.id === mode)?.label || 'Scan'

  const counts = useMemo(() => {
    const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0]))
    findings.forEach((f) => (c[f.severity] += 1))
    return c
  }, [findings])

  const sorted = useMemo(
    () => [...findings].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)),
    [findings],
  )
  const visible = filter === 'all' ? sorted : sorted.filter((f) => f.severity === filter)

  const worst = SEVERITIES.find((s) => counts[s] > 0) || 'info'

  return (
    <div className="pb-14">
      <div className="border-b border-dashed border-line px-4 py-6 sm:px-8">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-ink-subtle">{modeLabel} · report</p>
            <h2 className="mt-1 truncate font-mono text-[18px] text-ink-strong">{target}</h2>
            <p className="mt-1 text-[13px] text-ink-subtle">
              {findings.length} findings · worst severity{' '}
              <span style={{ color: SEVERITY_META[worst].color }}>{SEVERITY_META[worst].label}</span>
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {onExport && findings.length > 0 && (
              <button
                type="button"
                onClick={onExport}
                className="flex h-9 items-center gap-1.5 rounded-lg border border-line bg-surface px-3.5 text-[13px] font-medium text-ink-secondary transition-colors hover:border-line-strong hover:text-ink-strong"
              >
                <Icon name="copy" className="h-4 w-4" /> Export
              </button>
            )}
            <button
              type="button"
              onClick={onNewScan}
              className="flex h-9 items-center gap-1.5 rounded-lg border border-line bg-surface px-3.5 text-[13px] font-medium text-ink-secondary transition-colors hover:border-line-strong hover:text-ink-strong"
            >
              <Icon name="x" className="h-4 w-4" /> New scan
            </button>
          </div>
        </div>

        <div className="mt-5 flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => setFilter('all')}
            className={`rounded-lg border px-3 py-1.5 text-[12px] font-medium transition-colors ${
              filter === 'all' ? 'border-ink-strong/30 bg-surface-hover text-ink-strong' : 'border-line text-ink-muted hover:text-ink-strong'
            }`}
          >
            All {findings.length}
          </button>
          {SEVERITIES.filter((s) => counts[s] > 0).map((s) => {
            const meta = SEVERITY_META[s]
            const active = filter === s
            return (
              <button
                key={s}
                type="button"
                onClick={() => setFilter(active ? 'all' : s)}
                className="flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-[12px] font-medium transition-colors"
                style={{
                  borderColor: active ? meta.color : 'var(--color-line)',
                  background: active ? `color-mix(in srgb, ${meta.color} 12%, transparent)` : 'transparent',
                  color: active ? meta.color : 'var(--color-ink-muted)',
                }}
              >
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: meta.color }} />
                {meta.label} {counts[s]}
              </button>
            )
          })}
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="px-4 py-16 text-center sm:px-8">
          <p className="font-serif text-[22px] italic text-ink-strong">All clear.</p>
          <p className="mt-2 text-[13px] text-ink-subtle">
            The scan finished without flagging anything on <span className="font-mono">{target}</span>.
          </p>
        </div>
      ) : (
        <div>
          {visible.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </div>
      )}
    </div>
  )
}
