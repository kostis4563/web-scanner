import { useCallback, useEffect, useState } from 'react'
import ToolShell from './ToolShell.jsx'
import { CopyButton, Label, Segmented } from './ui.jsx'
import { Icon } from '../Icon.jsx'

const uuidv4 = () => {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID()
  const b = new Uint8Array(16)
  globalThis.crypto.getRandomValues(b)
  b[6] = (b[6] & 0x0f) | 0x40
  b[8] = (b[8] & 0x3f) | 0x80
  const h = [...b].map((x) => x.toString(16).padStart(2, '0'))
  return `${h.slice(0, 4).join('')}-${h.slice(4, 6).join('')}-${h.slice(6, 8).join('')}-${h
    .slice(8, 10)
    .join('')}-${h.slice(10, 16).join('')}`
}

const COUNTS = [
  { id: 1, label: '1' },
  { id: 5, label: '5' },
  { id: 10, label: '10' },
  { id: 25, label: '25' },
]

export default function UuidTool() {
  const [count, setCount] = useState(5)
  const [upper, setUpper] = useState(false)
  const [hyphens, setHyphens] = useState(true)
  const [list, setList] = useState([])

  const generate = useCallback(() => {
    setList(Array.from({ length: count }, uuidv4))
  }, [count])

  useEffect(() => {
    generate()
  }, [generate])

  const format = (u) => {
    let v = hyphens ? u : u.replace(/-/g, '')
    return upper ? v.toUpperCase() : v
  }
  const formatted = list.map(format)

  return (
    <ToolShell
      toolId="uuid"
      right={<CopyButton value={formatted.join('\n')} label="Copy all" />}
    >
      <div className="flex flex-wrap items-center gap-3">
        <div>
          <Label>Count</Label>
          <Segmented options={COUNTS} value={count} onChange={setCount} />
        </div>
        <div>
          <Label>Format</Label>
          <div className="flex gap-1.5">
            <button
              type="button"
              onClick={() => setUpper(!upper)}
              aria-pressed={upper}
              className={`rounded-lg border px-3 py-1.5 text-[12.5px] font-medium transition-colors ${
                upper ? 'border-ink-strong/30 bg-surface-hover text-ink-strong' : 'border-line text-ink-muted hover:text-ink-strong'
              }`}
            >
              Uppercase
            </button>
            <button
              type="button"
              onClick={() => setHyphens(!hyphens)}
              aria-pressed={hyphens}
              className={`rounded-lg border px-3 py-1.5 text-[12.5px] font-medium transition-colors ${
                hyphens ? 'border-ink-strong/30 bg-surface-hover text-ink-strong' : 'border-line text-ink-muted hover:text-ink-strong'
              }`}
            >
              Hyphens
            </button>
          </div>
        </div>
        <button
          type="button"
          onClick={generate}
          className="mt-auto flex h-9 items-center gap-1.5 rounded-lg border border-line bg-surface px-3.5 text-[13px] font-medium text-ink-secondary transition-colors hover:border-line-strong hover:text-ink-strong"
        >
          <Icon name="refresh" className="h-4 w-4" /> Regenerate
        </button>
      </div>

      <div className="mt-5 divide-y divide-dashed divide-line overflow-hidden rounded-xl border border-line bg-surface">
        {formatted.map((u, i) => (
          <div key={i} className="group flex items-center justify-between gap-3 px-3.5 py-2.5">
            <code className="min-w-0 break-all font-mono text-[13px] text-ink-strong">{u}</code>
            <CopyButton value={u} label="" className="h-7 px-2 opacity-0 transition-opacity group-hover:opacity-100" />
          </div>
        ))}
      </div>
    </ToolShell>
  )
}
