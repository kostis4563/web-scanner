import { useMemo, useState } from 'react'
import ToolShell from './ToolShell.jsx'
import { CopyButton, ErrorNote, Label } from './ui.jsx'

function parseColor(input) {
  const s = input.trim()
  if (!s) return null
  const el = document.createElement('div')
  el.style.color = ''
  el.style.color = s
  if (!el.style.color) return null 
  document.body.appendChild(el)
  const computed = getComputedStyle(el).color
  document.body.removeChild(el)
  const m = computed.match(/rgba?\(([^)]+)\)/)
  if (!m) return null
  const parts = m[1].split(',').map((x) => parseFloat(x))
  return { r: parts[0], g: parts[1], b: parts[2], a: parts[3] ?? 1 }
}

const toHex = ({ r, g, b, a }) => {
  const h = (n) => Math.round(n).toString(16).padStart(2, '0')
  return `#${h(r)}${h(g)}${h(b)}${a < 1 ? h(a * 255) : ''}`.toUpperCase()
}

function toHsl({ r, g, b }) {
  r /= 255
  g /= 255
  b /= 255
  const max = Math.max(r, g, b)
  const min = Math.min(r, g, b)
  const l = (max + min) / 2
  let h = 0
  let s = 0
  if (max !== min) {
    const d = max - min
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min)
    if (max === r) h = (g - b) / d + (g < b ? 6 : 0)
    else if (max === g) h = (b - r) / d + 2
    else h = (r - g) / d + 4
    h /= 6
  }
  return { h: Math.round(h * 360), s: Math.round(s * 100), l: Math.round(l * 100) }
}

const luminance = ({ r, g, b }) => {
  const f = (c) => {
    c /= 255
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  }
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)
}
const contrast = (a, b) => {
  const l1 = luminance(a)
  const l2 = luminance(b)
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05)
}

function Row({ label, value }) {
  return (
    <div className="flex items-center justify-between gap-3 px-3.5 py-2.5">
      <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-ink-subtle">{label}</span>
      <div className="flex items-center gap-2">
        <code className="font-mono text-[13px] text-ink-strong">{value}</code>
        <CopyButton value={value} label="" className="h-7 px-2" />
      </div>
    </div>
  )
}

function Badge({ ok, children }) {
  return (
    <span
      className="rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wide"
      style={{
        color: ok ? 'var(--color-sev-info)' : 'var(--color-sev-high)',
        background: `color-mix(in srgb, ${ok ? 'var(--color-sev-info)' : 'var(--color-sev-high)'} 14%, transparent)`,
      }}
    >
      {children}
    </span>
  )
}

export default function ColorTool() {
  const [input, setInput] = useState('#8b5cf6')
  const [bg, setBg] = useState('#ffffff')

  const color = useMemo(() => parseColor(input), [input])
  const bgColor = useMemo(() => parseColor(bg), [bg])

  const hsl = color && toHsl(color)
  const ratio = color && bgColor ? contrast(color, bgColor) : null

  return (
    <ToolShell toolId="color">
      <div className="grid gap-3 sm:grid-cols-[120px_1fr]">
        <div
          className="h-24 rounded-xl border border-line sm:h-auto"
          style={{ background: color ? toHex(color) : 'transparent' }}
        />
        <div>
          <Label>Color</Label>
          <div className="flex items-center gap-2">
            <input
              type="color"
              value={color ? toHex(color).slice(0, 7) : '#000000'}
              onChange={(e) => setInput(e.target.value)}
              className="h-10 w-12 shrink-0 cursor-pointer rounded-lg border border-line bg-surface"
            />
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              spellCheck={false}
              placeholder="#8b5cf6, rebeccapurple, rgb(139 92 246)…"
              className="h-10 w-full rounded-xl border border-line bg-surface px-3.5 font-mono text-[13.5px] text-ink-strong outline-none transition-colors placeholder:text-ink-faint focus:border-ink-strong/40"
            />
          </div>
        </div>
      </div>

      {input.trim() && !color && <ErrorNote>Not a valid CSS color.</ErrorNote>}

      {color && (
        <div className="mt-4 divide-y divide-dashed divide-line overflow-hidden rounded-xl border border-line bg-surface">
          <Row label="HEX" value={toHex(color)} />
          <Row label="RGB" value={`rgb(${Math.round(color.r)}, ${Math.round(color.g)}, ${Math.round(color.b)})`} />
          <Row label="HSL" value={`hsl(${hsl.h}, ${hsl.s}%, ${hsl.l}%)`} />
          {color.a < 1 && <Row label="Alpha" value={color.a.toFixed(2)} />}
        </div>
      )}

      <div className="mt-6">
        <Label>Contrast against</Label>
        <div className="flex items-center gap-2">
          <input
            type="color"
            value={bgColor ? toHex(bgColor).slice(0, 7) : '#ffffff'}
            onChange={(e) => setBg(e.target.value)}
            className="h-10 w-12 shrink-0 cursor-pointer rounded-lg border border-line bg-surface"
          />
          <input
            type="text"
            value={bg}
            onChange={(e) => setBg(e.target.value)}
            spellCheck={false}
            className="h-10 w-full rounded-xl border border-line bg-surface px-3.5 font-mono text-[13.5px] text-ink-strong outline-none transition-colors focus:border-ink-strong/40"
          />
        </div>

        {ratio && (
          <div className="mt-3 rounded-xl border border-line bg-surface p-4">
            <div className="flex items-center justify-between">
              <span className="text-[13px] text-ink-subtle">Contrast ratio</span>
              <span className="font-mono text-[18px] text-ink-strong">{ratio.toFixed(2)}:1</span>
            </div>
            <div
              className="mt-3 flex items-center justify-center rounded-lg py-4 text-[15px] font-semibold"
              style={{ background: toHex(bgColor), color: toHex(color) }}
            >
              Sample text
            </div>
            <div className="mt-3 flex flex-wrap gap-2 text-[12px] text-ink-muted">
              <span className="flex items-center gap-1.5">Normal AA <Badge ok={ratio >= 4.5}>{ratio >= 4.5 ? 'pass' : 'fail'}</Badge></span>
              <span className="flex items-center gap-1.5">Normal AAA <Badge ok={ratio >= 7}>{ratio >= 7 ? 'pass' : 'fail'}</Badge></span>
              <span className="flex items-center gap-1.5">Large AA <Badge ok={ratio >= 3}>{ratio >= 3 ? 'pass' : 'fail'}</Badge></span>
              <span className="flex items-center gap-1.5">Large AAA <Badge ok={ratio >= 4.5}>{ratio >= 4.5 ? 'pass' : 'fail'}</Badge></span>
            </div>
          </div>
        )}
      </div>
    </ToolShell>
  )
}
