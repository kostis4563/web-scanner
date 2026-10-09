import { useEffect, useRef, useState } from 'react'
import { toolsByCategory, getTool } from '../data/tools.js'
import { Icon } from './Icon.jsx'

export default function ToolSwitcher({ value, onChange }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  const current = getTool(value)
  const groups = toolsByCategory()

  useEffect(() => {
    if (!open) return
    const onKey = (e) => e.key === 'Escape' && setOpen(false)
    const onClick = (e) => ref.current && !ref.current.contains(e.target) && setOpen(false)
    document.addEventListener('keydown', onKey)
    document.addEventListener('mousedown', onClick)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('mousedown', onClick)
    }
  }, [open])

  const pick = (id) => {
    onChange(id)
    setOpen(false)
  }

  return (
    <div className="border-b border-dashed border-line px-4 py-2 sm:px-8">
      <div ref={ref} className="relative inline-block">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-haspopup="menu"
          aria-expanded={open}
          className="group flex items-center gap-2 rounded-lg border border-line bg-surface py-1.5 pl-2.5 pr-2 text-[13px] font-medium text-ink-strong transition-colors hover:border-line-strong"
        >
          <Icon name={current?.icon || 'grid'} className="h-4 w-4 text-ink-secondary" />
          <span>{current?.name || 'Tools'}</span>
          <Icon
            name="chevron"
            className={`h-3.5 w-3.5 text-ink-faint transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
          />
        </button>

        {open && (
          <div
            role="menu"
            className="animate-rise absolute left-0 top-[calc(100%+6px)] z-40 w-[280px] overflow-hidden rounded-xl border border-line-strong bg-surface-raised p-1 shadow-[0_18px_40px_-16px_rgba(0,0,0,0.6)]"
          >
            {groups.map(({ category, tools }) => (
              <div key={category} className="px-1 pb-1">
                <p className="px-2 pb-1 pt-2 font-mono text-[9px] uppercase tracking-[0.2em] text-ink-faint">
                  {category}
                </p>
                {tools.map((t) => {
                  const active = t.id === value
                  return (
                    <button
                      key={t.id}
                      type="button"
                      role="menuitem"
                      onClick={() => pick(t.id)}
                      className={`flex w-full items-center gap-2.5 rounded-lg px-2 py-2 text-left transition-colors ${
                        active ? 'bg-surface-hover text-ink-strong' : 'text-ink-secondary hover:bg-surface-hover hover:text-ink-strong'
                      }`}
                    >
                      <Icon name={t.icon} className="h-4 w-4 shrink-0 text-ink-muted" />
                      <span className="min-w-0 flex-1 truncate text-[13px] font-medium">{t.name}</span>
                      {active && <Icon name="check" className="h-3.5 w-3.5 shrink-0 text-ink-strong" />}
                    </button>
                  )
                })}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
