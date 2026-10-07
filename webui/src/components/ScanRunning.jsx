import { useEffect, useRef, useState } from 'react'
import { Icon } from './Icon.jsx'

export default function ScanRunning({ log, target, onDone, live, progress, status, onStop }) {
  const [shown, setShown] = useState(live ? log.length : 0)
  const scroller = useRef(null)

  useEffect(() => {
    if (live) {
      setShown(log.length)
      return
    }
    setShown(0)
    let i = 0
    const timer = setInterval(() => {
      i += 1
      setShown(i)
      if (i >= log.length) {
        clearInterval(timer)
        setTimeout(onDone, 450)
      }
    }, 340)
    return () => clearInterval(timer)
  }, [log, onDone, live])

  useEffect(() => {
    if (scroller.current) scroller.current.scrollTop = scroller.current.scrollHeight
  }, [shown])

  const pct = live
    ? Math.round(Math.max(0, Math.min(1, progress || 0)) * 100)
    : Math.round((shown / Math.max(1, log.length)) * 100)

  const visible = live ? log : log.slice(0, shown)

  return (
    <div className="px-4 pb-14 pt-8 sm:px-8">
      <div className="flex items-center justify-between gap-4">
        <p className="min-w-0 truncate font-mono text-[13px] text-ink-secondary">
          scanning <span className="text-ink-strong">{target}</span>
          <span className="caret" />
        </p>
        <div className="flex shrink-0 items-center gap-3">
          <span className="font-mono text-[12px] tabular-nums text-ink-subtle">{pct}%</span>
          {onStop && (
            <button
              type="button"
              onClick={onStop}
              className="flex h-7 items-center gap-1.5 rounded-lg border border-line bg-surface px-2.5 font-mono text-[11px] text-ink-muted transition-colors hover:border-sev-critical/50 hover:text-sev-critical"
            >
              <Icon name="x" className="h-3.5 w-3.5" /> Stop
            </button>
          )}
        </div>
      </div>

      <div className="mt-3 h-1 w-full overflow-hidden rounded-full bg-surface-hover">
        <div
          className="h-full rounded-full bg-brand transition-[width] duration-300 ease-out"
          style={{ width: `${pct}%` }}
        />
      </div>

      {live && status && (
        <p className="mt-2 font-mono text-[11px] text-ink-subtle">{status}</p>
      )}

      <div
        ref={scroller}
        className="mt-5 h-64 overflow-y-auto rounded-xl border border-line bg-surface p-4 font-mono text-[12.5px] leading-6"
      >
        {visible.map((line, i) => (
          <div key={i} className="flex gap-2">
            <span className="select-none text-ink-faint">›</span>
            <span className={i === visible.length - 1 ? 'text-ink-strong' : 'text-ink-subtle'}>{line}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
