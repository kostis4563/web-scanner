import { useState } from 'react'
import ToolShell from './ToolShell.jsx'
import { Label, Segmented, Textarea } from './ui.jsx'
import { Icon } from '../Icon.jsx'

const METHODS = ['POST', 'GET', 'PUT', 'PATCH', 'DELETE']
const CONTENT_TYPES = [
  { id: 'application/json', label: 'JSON' },
  { id: 'text/plain', label: 'Text' },
  { id: 'application/x-www-form-urlencoded', label: 'Form' },
]
const SAMPLES = {
  'application/json': '{\n  "text": "Hello from WebScanner"\n}',
  'text/plain': 'Hello from WebScanner',
  'application/x-www-form-urlencoded': 'text=Hello+from+WebScanner',
}

// Parse "Key: value" lines into a headers object.
function parseHeaderLines(raw) {
  const out = {}
  for (const line of raw.split(/\r?\n/)) {
    const i = line.indexOf(':')
    if (i < 1) continue
    out[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  return out
}

const normalizeUrl = (s) => {
  const t = s.trim()
  return /^https?:\/\//i.test(t) ? t : t ? `https://${t}` : ''
}

export default function WebhookTool() {
  const [url, setUrl] = useState('')
  const [method, setMethod] = useState('POST')
  const [contentType, setContentType] = useState('application/json')
  const [body, setBody] = useState(SAMPLES['application/json'])
  const [headersRaw, setHeadersRaw] = useState('')
  const [sending, setSending] = useState(false)
  const [result, setResult] = useState(null)

  const hasBody = method !== 'GET' && method !== 'DELETE'
  const jsonInvalid =
    hasBody && contentType === 'application/json' && body.trim() && (() => {
      try {
        JSON.parse(body)
        return false
      } catch {
        return true
      }
    })()

  const setType = (t) => {
    // Swap in the matching sample if the body is still a known sample / empty.
    if (!body.trim() || Object.values(SAMPLES).includes(body.trim())) setBody(SAMPLES[t])
    setContentType(t)
  }

  const send = async (e) => {
    e?.preventDefault()
    const target = normalizeUrl(url)
    if (!target) return
    setSending(true)
    setResult(null)
    const headers = { ...parseHeaderLines(headersRaw) }
    if (hasBody && !Object.keys(headers).some((h) => h.toLowerCase() === 'content-type'))
      headers['Content-Type'] = contentType

    const started = performance.now()
    try {
      const res = await fetch(target, {
        method,
        headers,
        body: hasBody ? body : undefined,
        redirect: 'follow',
      })
      const ms = Math.round(performance.now() - started)
      let text = ''
      try {
        text = await res.text()
      } catch {
        /* opaque */
      }
      const resHeaders = []
      res.headers.forEach((v, k) => resHeaders.push(`${k}: ${v}`))
      setResult({
        ok: res.ok,
        status: res.status,
        statusText: res.statusText,
        ms,
        headers: resHeaders.join('\n'),
        body: text,
        opaque: res.type === 'opaque',
      })
    } catch (err) {
      const ms = Math.round(performance.now() - started)
      setResult({
        error: true,
        ms,
        message:
          'Request failed, or the response was hidden by the browser’s cross-origin (CORS) policy. ' +
          'The webhook may well have fired — many endpoints just don’t return CORS headers a browser can read.',
        detail: String(err?.message || err),
      })
    } finally {
      setSending(false)
    }
  }

  return (
    <ToolShell toolId="webhook">
      <form onSubmit={send}>
        <Label>Webhook URL</Label>
        <div className="flex flex-wrap items-center gap-2">
          <Segmented options={METHODS} value={method} onChange={setMethod} />
          <div className="flex min-w-[200px] flex-1 items-center gap-2 rounded-xl border border-line bg-surface px-3.5 focus-within:border-ink-strong/40">
            <Icon name="link" className="h-4 w-4 shrink-0 text-ink-faint" />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://hooks.example.com/services/…"
              spellCheck={false}
              autoComplete="off"
              className="h-10 w-full bg-transparent font-mono text-[13px] text-ink-strong outline-none placeholder:text-ink-faint"
            />
          </div>
        </div>

        {hasBody && (
          <div className="mt-5">
            <div className="mb-2 flex items-center justify-between">
              <Label>Message / body</Label>
              <Segmented options={CONTENT_TYPES} value={contentType} onChange={setType} />
            </div>
            <Textarea value={body} onChange={setBody} rows={6} placeholder="Payload to send…" />
            {jsonInvalid && <p className="mt-2 text-[12px] text-sev-medium">Heads up: this isn’t valid JSON — sending it anyway.</p>}
          </div>
        )}

        <details className="mt-4 rounded-xl border border-line bg-surface">
          <summary className="cursor-pointer px-3.5 py-2.5 font-mono text-[11px] uppercase tracking-[0.15em] text-ink-subtle">
            Custom headers (optional)
          </summary>
          <div className="px-3.5 pb-3.5">
            <Textarea
              value={headersRaw}
              onChange={setHeadersRaw}
              rows={3}
              placeholder={'Authorization: Bearer …\nX-Signature: …'}
            />
          </div>
        </details>

        <button
          type="submit"
          disabled={!url.trim() || sending}
          className="mt-5 flex h-11 w-full items-center justify-center gap-2 rounded-xl bg-ink-strong text-[13.5px] font-semibold text-bg transition-all hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Icon name="zap" className="h-4 w-4" strokeWidth={2} />
          {sending ? 'Sending…' : `Send ${method}`}
        </button>
      </form>

      {result && (
        <div className="mt-5">
          {result.error ? (
            <div className="rounded-xl border border-dashed border-sev-critical/40 bg-sev-critical/[0.06] p-4">
              <div className="flex items-center gap-2">
                <Icon name="x" className="h-4 w-4 text-sev-critical" />
                <span className="text-[13px] font-semibold text-ink-strong">Could not read a response · {result.ms} ms</span>
              </div>
              <p className="mt-2 text-[12.5px] leading-relaxed text-ink-subtle">{result.message}</p>
              <p className="mt-1.5 font-mono text-[11.5px] text-ink-faint">{result.detail}</p>
            </div>
          ) : (
            <>
              <div
                className="flex flex-wrap items-center gap-3 rounded-xl border p-4"
                style={{
                  borderColor: result.ok ? 'var(--color-sev-info)' : 'var(--color-sev-high)',
                  background: `color-mix(in srgb, ${result.ok ? 'var(--color-sev-info)' : 'var(--color-sev-high)'} 8%, transparent)`,
                }}
              >
                <Icon
                  name={result.ok ? 'check' : 'x'}
                  className="h-5 w-5"
                  strokeWidth={2.4}
                />
                <span className="font-mono text-[18px] text-ink-strong">
                  {result.status} {result.statusText}
                </span>
                <span
                  className="rounded px-2 py-0.5 font-mono text-[11px] font-semibold uppercase"
                  style={{
                    color: result.ok ? 'var(--color-sev-info)' : 'var(--color-sev-high)',
                    background: `color-mix(in srgb, ${result.ok ? 'var(--color-sev-info)' : 'var(--color-sev-high)'} 16%, transparent)`,
                  }}
                >
                  {result.ok ? 'success' : 'error'}
                </span>
                <span className="ml-auto font-mono text-[12px] text-ink-subtle">{result.ms} ms</span>
              </div>

              {result.headers && (
                <div className="mt-3">
                  <Label>Response headers</Label>
                  <pre className="overflow-x-auto rounded-xl border border-line bg-surface px-3.5 py-3 font-mono text-[12px] leading-relaxed text-ink-secondary">
                    {result.headers}
                  </pre>
                </div>
              )}
              {result.body && (
                <div className="mt-3">
                  <Label>Response body</Label>
                  <pre className="max-h-[320px] overflow-auto rounded-xl border border-line bg-surface px-3.5 py-3 font-mono text-[12px] leading-relaxed text-ink-strong">
                    {result.body}
                  </pre>
                </div>
              )}
            </>
          )}
        </div>
      )}

      <p className="mt-4 text-[12px] leading-relaxed text-ink-subtle">
        Fires straight from the app. Endpoints that don’t return CORS headers (many do, e.g. Slack/Discord)
        will still receive the request, but the browser won’t let us read their reply — you’ll see a notice instead of a status.
      </p>
    </ToolShell>
  )
}
