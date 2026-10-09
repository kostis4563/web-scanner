import { useCallback, useEffect, useState } from 'react'
import ToolShell from './ToolShell.jsx'
import { CopyButton, Label } from './ui.jsx'
import { Icon } from '../Icon.jsx'

const SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.<>?',
}
const AMBIGUOUS = /[O0Il1|`'"]/g

const randomInt = (max) => {
  const limit = Math.floor(0x100000000 / max) * max
  const buf = new Uint32Array(1)
  let x
  do {
    globalThis.crypto.getRandomValues(buf)
    x = buf[0]
  } while (x >= limit)
  return x % max
}

function strength(pw) {
  if (!pw) return { label: '—', pct: 0, color: 'var(--color-ink-faint)' }
  let pool = 0
  if (/[a-z]/.test(pw)) pool += 26
  if (/[A-Z]/.test(pw)) pool += 26
  if (/[0-9]/.test(pw)) pool += 10
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 24
  const bits = pw.length * Math.log2(pool || 1)
  const pct = Math.min(100, Math.round((bits / 128) * 100))
  const [label, color] =
    bits < 40 ? ['Weak', 'var(--color-sev-high)']
    : bits < 70 ? ['Fair', 'var(--color-sev-medium)']
    : bits < 110 ? ['Strong', 'var(--color-sev-low)']
    : ['Excellent', 'var(--color-sev-info)']
  return { label: `${label} · ${Math.round(bits)} bits`, pct, color }
}

function Toggle({ checked, onChange, children }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      aria-pressed={checked}
      className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-[12.5px] font-medium transition-colors ${
        checked
          ? 'border-ink-strong/30 bg-surface-hover text-ink-strong'
          : 'border-line text-ink-muted hover:text-ink-strong'
      }`}
    >
      <span
        className="flex h-3.5 w-3.5 items-center justify-center rounded border"
        style={{
          borderColor: checked ? 'currentColor' : 'var(--color-line-strong)',
          background: checked ? 'currentColor' : 'transparent',
        }}
      >
        {checked && <Icon name="check" className="h-2.5 w-2.5 text-bg" strokeWidth={3} />}
      </span>
      {children}
    </button>
  )
}

export default function PasswordTool() {
  const [length, setLength] = useState(20)
  const [opts, setOpts] = useState({ lower: true, upper: true, digits: true, symbols: true, noAmbiguous: false })
  const [pw, setPw] = useState('')

  const generate = useCallback(() => {
    let pool = ['lower', 'upper', 'digits', 'symbols']
      .filter((k) => opts[k])
      .map((k) => SETS[k])
      .join('')
    if (opts.noAmbiguous) pool = pool.replace(AMBIGUOUS, '')
    if (!pool) {
      setPw('')
      return
    }
    let out = ''
    for (let i = 0; i < length; i++) out += pool[randomInt(pool.length)]
    setPw(out)
  }, [length, opts])

  useEffect(() => {
    generate()
  }, [generate])

  const noneSelected = !opts.lower && !opts.upper && !opts.digits && !opts.symbols
  const s = strength(pw)

  return (
    <ToolShell toolId="password">
      <div className="rounded-xl border border-line bg-surface px-4 py-4">
        <div className="flex items-center justify-between gap-3">
          <code className="min-w-0 flex-1 break-all font-mono text-[16px] text-ink-strong">
            {pw || <span className="text-ink-faint">select at least one character set</span>}
          </code>
          <div className="flex shrink-0 items-center gap-2">
            <button
              type="button"
              onClick={generate}
              className="flex h-9 w-9 items-center justify-center rounded-lg border border-line bg-surface text-ink-secondary transition-colors hover:border-line-strong hover:text-ink-strong"
              title="Regenerate"
            >
              <Icon name="refresh" className="h-4 w-4" />
            </button>
            <CopyButton value={pw} />
          </div>
        </div>
        <div className="mt-3.5 h-1 overflow-hidden rounded-full bg-line">
          <div
            className="h-full rounded-full transition-all duration-300"
            style={{ width: `${s.pct}%`, background: s.color }}
          />
        </div>
        <p className="mt-2 font-mono text-[11px] uppercase tracking-[0.15em]" style={{ color: s.color }}>
          {s.label}
        </p>
      </div>

      <div className="mt-6">
        <div className="mb-2 flex items-center justify-between">
          <Label>Length</Label>
          <span className="font-mono text-[13px] text-ink-strong">{length}</span>
        </div>
        <input
          type="range"
          min={6}
          max={64}
          value={length}
          onChange={(e) => setLength(Number(e.target.value))}
          className="w-full accent-[var(--color-ink-strong)]"
        />
      </div>

      <div className="mt-6">
        <Label>Character sets</Label>
        <div className="flex flex-wrap gap-1.5">
          <Toggle checked={opts.lower} onChange={(v) => setOpts({ ...opts, lower: v })}>a–z</Toggle>
          <Toggle checked={opts.upper} onChange={(v) => setOpts({ ...opts, upper: v })}>A–Z</Toggle>
          <Toggle checked={opts.digits} onChange={(v) => setOpts({ ...opts, digits: v })}>0–9</Toggle>
          <Toggle checked={opts.symbols} onChange={(v) => setOpts({ ...opts, symbols: v })}>!@#$</Toggle>
          <Toggle checked={opts.noAmbiguous} onChange={(v) => setOpts({ ...opts, noAmbiguous: v })}>
            No look-alikes
          </Toggle>
        </div>
        {noneSelected && (
          <p className="mt-2 text-[12px] text-sev-high">Pick at least one set to generate a password.</p>
        )}
      </div>
    </ToolShell>
  )
}
