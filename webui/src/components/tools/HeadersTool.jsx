import { useMemo, useState } from 'react'
import ToolShell from './ToolShell.jsx'
import { Label, Textarea } from './ui.jsx'

const SAMPLE = `HTTP/2 200
server: nginx/1.21.0
x-powered-by: PHP/8.1
content-type: text/html; charset=utf-8
strict-transport-security: max-age=31536000
set-cookie: session=abc; Path=/; HttpOnly`
function parseHeaders(raw) {
  const map = {}
  const cookies = []
  for (const line of raw.split(/\r?\n/)) {
    const i = line.indexOf(':')
    if (i < 1) continue
    const key = line.slice(0, i).trim().toLowerCase()
    const val = line.slice(i + 1).trim()
    if (key === 'set-cookie') cookies.push(val)
    else map[key] = val
  }
  return { map, cookies }
}

function grade(raw) {
  const { map, cookies } = parseHeaders(raw)
  const checks = []
  const add = (name, status, note, weight = 1) => checks.push({ name, status, note, weight })

  const hsts = map['strict-transport-security']
  if (!hsts) add('Strict-Transport-Security', 'bad', 'Missing — HTTPS is not enforced by the browser.', 2)
  else {
    const age = +(hsts.match(/max-age=(\d+)/i)?.[1] || 0)
    if (age < 15768000) add('Strict-Transport-Security', 'warn', `max-age is ${age}s; aim for ≥ 6 months.`, 2)
    else add('Strict-Transport-Security', 'good', hsts, 2)
  }

  const csp = map['content-security-policy']
  if (!csp) add('Content-Security-Policy', 'bad', 'Missing — no defense-in-depth against XSS/injection.', 2)
  else if (/unsafe-inline|unsafe-eval|(^|\s)\*(\s|;|$)/i.test(csp)) add('Content-Security-Policy', 'warn', 'Present but weakened by unsafe-inline / unsafe-eval / wildcard.', 2)
  else add('Content-Security-Policy', 'good', 'Present and reasonably strict.', 2)

  const xfo = map['x-frame-options']
  if (xfo || /frame-ancestors/i.test(csp || '')) add('Clickjacking protection', 'good', xfo ? `X-Frame-Options: ${xfo}` : 'CSP frame-ancestors set.')
  else add('Clickjacking protection', 'bad', 'No X-Frame-Options or CSP frame-ancestors.')

  const xcto = map['x-content-type-options']
  if (/nosniff/i.test(xcto || '')) add('X-Content-Type-Options', 'good', 'nosniff')
  else add('X-Content-Type-Options', 'bad', 'Missing nosniff — MIME-sniffing allowed.')

  const ref = map['referrer-policy']
  if (ref) add('Referrer-Policy', 'good', ref)
  else add('Referrer-Policy', 'warn', 'Not set — browser default may leak full URLs.')

  if (map['permissions-policy']) add('Permissions-Policy', 'good', map['permissions-policy'])
  else add('Permissions-Policy', 'warn', 'Not set — powerful features are not restricted.')

  // Information disclosure.
  if (map['server'] && /[0-9]/.test(map['server'])) add('Server banner', 'warn', `Reveals version: ${map['server']}`)
  if (map['x-powered-by']) add('X-Powered-By', 'warn', `Reveals stack: ${map['x-powered-by']}`)

  // Cookie flags.
  cookies.forEach((c) => {
    const name = c.split('=')[0]
    const flags = []
    if (!/;\s*secure/i.test(c)) flags.push('Secure')
    if (!/;\s*httponly/i.test(c)) flags.push('HttpOnly')
    if (!/;\s*samesite/i.test(c)) flags.push('SameSite')
    if (flags.length) add(`Cookie “${name}”`, 'warn', `Missing ${flags.join(', ')}.`)
    else add(`Cookie “${name}”`, 'good', 'Secure, HttpOnly and SameSite all set.')
  })

  const scored = checks.filter((c) => c.status !== 'good' || c.weight)
  const max = scored.reduce((s, c) => s + c.weight, 0) || 1
  const got = scored.reduce((s, c) => s + (c.status === 'good' ? c.weight : c.status === 'warn' ? c.weight * 0.5 : 0), 0)
  const pct = Math.round((got / max) * 100)
  const letter = pct >= 90 ? 'A' : pct >= 75 ? 'B' : pct >= 55 ? 'C' : pct >= 35 ? 'D' : 'F'
  return { checks, pct, letter }
}

const COLOR = { good: 'var(--color-sev-info)', warn: 'var(--color-sev-medium)', bad: 'var(--color-sev-critical)' }

export default function HeadersTool() {
  const [raw, setRaw] = useState('')
  const result = useMemo(() => (raw.trim() ? grade(raw) : null), [raw])
  const gradeColor = result ? (result.pct >= 75 ? COLOR.good : result.pct >= 45 ? COLOR.warn : COLOR.bad) : COLOR.warn

  return (
    <ToolShell toolId="headers">
      <div className="mb-2 flex items-center justify-between">
        <Label>Raw response headers</Label>
        <button
          type="button"
          onClick={() => setRaw(SAMPLE)}
          className="font-mono text-[11px] text-ink-subtle underline-offset-2 transition-colors hover:text-ink-strong hover:underline"
        >
          load sample
        </button>
      </div>
      <Textarea
        value={raw}
        onChange={setRaw}
        rows={8}
        placeholder={'Paste headers, one per line:\nstrict-transport-security: max-age=31536000\ncontent-security-policy: ...'}
      />
      <p className="mt-2 text-[12px] text-ink-subtle">
        Tip: grab these with <code className="font-mono">curl -sI https://example.com</code>.
      </p>

      {result && (
        <div className="mt-5">
          <div className="flex items-center gap-4 rounded-xl border border-line bg-surface p-4">
            <div
              className="flex h-16 w-16 shrink-0 items-center justify-center rounded-xl font-serif text-[32px] italic"
              style={{ color: gradeColor, background: `color-mix(in srgb, ${gradeColor} 12%, transparent)` }}
            >
              {result.letter}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between">
                <span className="text-[13px] text-ink-subtle">Header hygiene</span>
                <span className="font-mono text-[15px] text-ink-strong">{result.pct}%</span>
              </div>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-line">
                <div className="h-full rounded-full transition-all duration-500" style={{ width: `${result.pct}%`, background: gradeColor }} />
              </div>
            </div>
          </div>

          <div className="mt-4 divide-y divide-dashed divide-line overflow-hidden rounded-xl border border-line bg-surface">
            {result.checks.map((c, i) => (
              <div key={i} className="flex items-start gap-3 px-3.5 py-3">
                <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: COLOR[c.status] }} />
                <div className="min-w-0">
                  <p className="text-[13px] font-medium text-ink-strong">{c.name}</p>
                  <p className="mt-0.5 break-words text-[12.5px] leading-relaxed text-ink-subtle">{c.note}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </ToolShell>
  )
}
