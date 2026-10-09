import { useMemo, useState } from 'react'
import ToolShell from './ToolShell.jsx'
import { ErrorNote, Label, Textarea } from './ui.jsx'

const b64urlDecode = (seg) => {
  const pad = seg.length % 4 === 0 ? '' : '='.repeat(4 - (seg.length % 4))
  const bin = atob(seg.replace(/-/g, '+').replace(/_/g, '/') + pad)
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
}

const TIME_CLAIMS = { exp: 'expires', iat: 'issued', nbf: 'not before' }

function decodeJwt(token) {
  const t = token.trim()
  if (!t) return { empty: true }
  const parts = t.split('.')
  if (parts.length < 2 || parts.length > 3) throw new Error('A JWT has two or three dot-separated parts.')
  const header = JSON.parse(b64urlDecode(parts[0]))
  const payload = JSON.parse(b64urlDecode(parts[1]))
  return { header, payload, signature: parts[2] || '' }
}

function Panel({ label, json }) {
  return (
    <div>
      <Label>{label}</Label>
      <pre className="overflow-x-auto rounded-xl border border-line bg-surface px-3.5 py-3 font-mono text-[12.5px] leading-relaxed text-ink-strong">
        {JSON.stringify(json, null, 2)}
      </pre>
    </div>
  )
}

export default function JwtTool() {
  const [token, setToken] = useState('')

  const { data, error } = useMemo(() => {
    try {
      return { data: decodeJwt(token), error: null }
    } catch (e) {
      return { data: null, error: e.message || 'Not a valid JWT.' }
    }
  }, [token])

  const claims = data?.payload || {}
  const now = Math.floor(Date.now() / 1000)
  const expired = typeof claims.exp === 'number' && claims.exp < now

  return (
    <ToolShell toolId="jwt">
      <div>
        <Label>Token</Label>
        <Textarea
          value={token}
          onChange={setToken}
          placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.…"
          rows={4}
        />
      </div>

      {token.trim() && <ErrorNote>{error}</ErrorNote>}

      {data && !data.empty && (
        <div className="mt-5 space-y-4">
          {typeof claims.exp === 'number' && (
            <div
              className="flex items-center gap-2 rounded-xl border border-dashed px-4 py-2.5 text-[12.5px]"
              style={{
                borderColor: expired ? 'var(--color-sev-critical)' : 'var(--color-sev-info)',
                color: expired ? 'var(--color-sev-critical)' : 'var(--color-sev-info)',
              }}
            >
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: 'currentColor' }} />
              {expired ? 'Expired' : 'Valid'} — exp {new Date(claims.exp * 1000).toLocaleString()}
            </div>
          )}

          <Panel label="Header" json={data.header} />
          <Panel label="Payload" json={data.payload} />

          {Object.keys(TIME_CLAIMS).some((k) => typeof claims[k] === 'number') && (
            <div>
              <Label>Timestamps</Label>
              <div className="rounded-xl border border-line bg-surface px-3.5 py-3 font-mono text-[12.5px] text-ink-secondary">
                {Object.entries(TIME_CLAIMS)
                  .filter(([k]) => typeof claims[k] === 'number')
                  .map(([k, name]) => (
                    <div key={k} className="flex flex-wrap gap-x-2 py-0.5">
                      <span className="text-ink-faint">{k}</span>
                      <span className="text-ink-subtle">({name})</span>
                      <span>{new Date(claims[k] * 1000).toLocaleString()}</span>
                    </div>
                  ))}
              </div>
            </div>
          )}

          <div>
            <Label>Signature</Label>
            <div className="rounded-xl border border-line bg-surface px-3.5 py-3 font-mono text-[12.5px] text-ink-muted break-all">
              {data.signature || '—'}
            </div>
            <p className="mt-2 text-[12px] leading-relaxed text-ink-subtle">
              The signature is not verified — decoding a JWT does not prove it is authentic or untampered.
            </p>
          </div>
        </div>
      )}
    </ToolShell>
  )
}
