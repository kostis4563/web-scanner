import { useCallback, useEffect, useState } from 'react'
import ToolShell from './ToolShell.jsx'
import { CopyButton, Label } from './ui.jsx'
import { Icon } from '../Icon.jsx'
import { isNative, openExternal } from '../../bridge.js'

async function fetchPublicIp(target = '') {
  const t = target.trim()
  const seg = t ? encodeURIComponent(t) : ''
  try {
    const d = await (await fetch(`https://ipwho.is/${seg}`)).json()
    if (d && d.success !== false) {
      return {
        ip: d.ip,
        type: d.type,
        city: d.city,
        region: d.region,
        country: d.country,
        flag: d.flag?.emoji,
        postal: d.postal,
        lat: d.latitude,
        lon: d.longitude,
        timezone: d.timezone?.id,
        localTime: d.timezone?.current_time,
        asn: d.connection?.asn ? `AS${d.connection.asn}` : undefined,
        isp: d.connection?.isp,
        org: d.connection?.org,
      }
    }
  } catch {
  }
  const d = await (await fetch(t ? `https://ipapi.co/${seg}/json/` : 'https://ipapi.co/json/')).json()
  if (d.error) throw new Error(d.reason || 'Lookup failed.')
  return {
    ip: d.ip,
    type: d.version,
    city: d.city,
    region: d.region,
    country: d.country_name,
    postal: d.postal,
    lat: d.latitude,
    lon: d.longitude,
    timezone: d.timezone,
    asn: d.asn,
    isp: d.org,
    org: d.org,
  }
}
function probeWebRtc(onFound, onDone) {
  let pc
  try {
    pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] })
  } catch {
    onDone()
    return () => {}
  }
  const seen = new Set()
  pc.createDataChannel('x')
  pc.onicecandidate = (e) => {
    if (!e.candidate) {
      onDone()
      return
    }
    const m = e.candidate.candidate.match(/([0-9a-f.:]+\.[0-9a-f.:]+|[0-9a-f:]{6,})\s\d+\styp/i)
    const ip = m?.[1]
    if (ip && !seen.has(ip)) {
      seen.add(ip)
      onFound(ip)
    }
  }
  pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(onDone)
  const t = setTimeout(onDone, 4000)
  return () => {
    clearTimeout(t)
    try {
      pc.close()
    } catch {
    }
  }
}

function browserInfo() {
  const n = navigator
  const conn = n.connection || n.mozConnection || n.webkitConnection
  const rows = [
    ['User agent', n.userAgent],
    ['Platform', n.platform || n.userAgentData?.platform],
    ['Languages', (n.languages || [n.language]).join(', ')],
    ['Timezone', Intl.DateTimeFormat().resolvedOptions().timeZone],
    ['Screen', `${screen.width}×${screen.height} @ ${window.devicePixelRatio}x`],
    ['Viewport', `${window.innerWidth}×${window.innerHeight}`],
    ['Color scheme', window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'],
    ['CPU cores', n.hardwareConcurrency],
    ['Device memory', n.deviceMemory ? `${n.deviceMemory} GB` : undefined],
    ['Touch points', n.maxTouchPoints],
    ['Connection', conn ? `${conn.effectiveType || '?'}${conn.downlink ? ` · ${conn.downlink} Mb/s` : ''}` : undefined],
    ['Cookies enabled', String(n.cookieEnabled)],
    ['Do Not Track', n.doNotTrack || 'unset'],
    ['Online', String(n.onLine)],
  ]
  return rows.filter(([, v]) => v !== undefined && v !== null && v !== '')
}

function Section({ title, right, children }) {
  return (
    <div className="mt-5">
      <div className="mb-2 flex items-center justify-between">
        <Label>{title}</Label>
        {right}
      </div>
      {children}
    </div>
  )
}

function KV({ k, v }) {
  return (
    <div className="flex items-start justify-between gap-3 px-3.5 py-2.5">
      <span className="shrink-0 font-mono text-[11px] uppercase tracking-[0.12em] text-ink-subtle">{k}</span>
      <span className="min-w-0 break-words text-right font-mono text-[12.5px] text-ink-strong">{v}</span>
    </div>
  )
}

export default function IpInfoTool() {
  const [input, setInput] = useState('')
  const [query, setQuery] = useState('') 
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [rtc, setRtc] = useState([])
  const [rtcDone, setRtcDone] = useState(false)

  const isSelf = query.trim() === ''

  const load = useCallback((target) => {
    setLoading(true)
    setError(null)
    setData(null)
    fetchPublicIp(target)
      .then(setData)
      .catch((e) =>
        setError(
          e?.message && !/fetch/i.test(e.message)
            ? e.message
            : 'Could not reach an IP service — check the target, the network, or a blocker in the way.',
        ),
      )
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    load(query)
  }, [query, load])

  useEffect(() => {
    if (!isSelf) return
    setRtc([])
    setRtcDone(false)
    const stop = probeWebRtc(
      (ip) => setRtc((prev) => (prev.includes(ip) ? prev : [...prev, ip])),
      () => setRtcDone(true),
    )
    return stop
  }, [isSelf])

  const submit = (e) => {
    e.preventDefault()
    setQuery(input)
  }
  const clear = () => {
    setInput('')
    setQuery('')
  }

  const info = browserInfo()
  const mapUrl = data?.lat != null ? `https://www.openstreetmap.org/?mlat=${data.lat}&mlon=${data.lon}#map=11/${data.lat}/${data.lon}` : null

  return (
    <ToolShell
      toolId="ipinfo"
      right={
        <button
          type="button"
          onClick={() => load(query)}
          className="flex h-9 items-center gap-1.5 rounded-lg border border-line bg-surface px-3.5 text-[13px] font-medium text-ink-secondary transition-colors hover:border-line-strong hover:text-ink-strong"
        >
          <Icon name="refresh" className="h-4 w-4" /> Refresh
        </button>
      }
    >
      <form onSubmit={submit} className="mb-4 flex flex-wrap items-center gap-2">
        <div className="flex min-w-[200px] flex-1 items-center gap-2 rounded-xl border border-line bg-surface px-3.5 focus-within:border-ink-strong/40">
          <Icon name="search" className="h-4 w-4 shrink-0 text-ink-faint" />
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Any IP or host — e.g. 8.8.8.8, github.com (blank = you)"
            spellCheck={false}
            autoComplete="off"
            className="h-10 w-full bg-transparent font-mono text-[13.5px] text-ink-strong outline-none placeholder:text-ink-faint"
          />
        </div>
        <button
          type="submit"
          className="flex h-10 items-center gap-1.5 rounded-xl bg-ink-strong px-4 text-[13.5px] font-semibold text-bg transition-opacity hover:opacity-90"
        >
          <Icon name="search" className="h-4 w-4" strokeWidth={2} /> Look up
        </button>
        {!isSelf && (
          <button
            type="button"
            onClick={clear}
            className="flex h-10 items-center gap-1.5 rounded-xl border border-line bg-surface px-3.5 text-[13px] font-medium text-ink-secondary transition-colors hover:border-line-strong hover:text-ink-strong"
          >
            <Icon name="x" className="h-4 w-4" /> Me
          </button>
        )}
      </form>

      <div className="rounded-xl border border-line bg-surface p-5">
        <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-ink-subtle">
          {isSelf ? 'Your public IP' : `IP info · ${query.trim()}`}
        </p>
        {loading ? (
          <p className="mt-1.5 font-mono text-[22px] text-ink-faint">resolving…</p>
        ) : error ? (
          <p className="mt-1.5 text-[14px] text-sev-high">{error}</p>
        ) : (
          <div className="mt-1.5 flex items-center gap-3">
            <code className="font-mono text-[22px] text-ink-strong">{data.ip}</code>
            {data.type && <span className="rounded border border-line px-1.5 py-0.5 font-mono text-[11px] text-ink-muted">{String(data.type).toUpperCase()}</span>}
            <CopyButton value={data.ip} label="" className="h-7 px-2" />
          </div>
        )}
      </div>

      {data && !error && (
        <Section
          title="Location & network"
          right={mapUrl && (
            <a
              href={mapUrl}
              target="_blank"
              rel="noreferrer"
              onClick={(e) => {
                if (isNative) {
                  e.preventDefault()
                  openExternal(mapUrl)
                }
              }}
              className="flex items-center gap-1 font-mono text-[11px] text-ink-subtle transition-colors hover:text-ink-strong"
            >
              <Icon name="link" className="h-3.5 w-3.5" /> map
            </a>
          )}
        >
          <div className="divide-y divide-dashed divide-line overflow-hidden rounded-xl border border-line bg-surface">
            {data.city && <KV k="City" v={`${data.city}${data.region ? `, ${data.region}` : ''}`} />}
            {data.country && <KV k="Country" v={`${data.flag ? data.flag + ' ' : ''}${data.country}`} />}
            {data.postal && <KV k="Postal" v={data.postal} />}
            {data.lat != null && <KV k="Coordinates" v={`${data.lat}, ${data.lon}`} />}
            {data.timezone && <KV k="Timezone" v={data.timezone} />}
            {data.localTime && <KV k="Local time" v={new Date(data.localTime).toLocaleString()} />}
            {data.asn && <KV k="ASN" v={data.asn} />}
            {data.isp && <KV k="ISP" v={data.isp} />}
            {data.org && data.org !== data.isp && <KV k="Org" v={data.org} />}
          </div>
        </Section>
      )}

      {isSelf && (
      <Section title="WebRTC local-IP leak">
        <div className="rounded-xl border border-line bg-surface px-3.5 py-3">
          {rtc.length ? (
            <div className="flex flex-wrap gap-2">
              {rtc.map((ip) => (
                <code key={ip} className="rounded border border-line bg-surface-raised px-2 py-1 font-mono text-[12.5px] text-ink-strong">
                  {ip}
                </code>
              ))}
            </div>
          ) : (
            <p className="font-mono text-[12.5px] text-ink-subtle">
              {rtcDone ? 'No local IPs exposed (masked by mDNS or blocked).' : 'probing…'}
            </p>
          )}
          <p className="mt-2 text-[12px] leading-relaxed text-ink-subtle">
            These are addresses a site could learn via WebRTC without permission. Modern browsers mask them behind
            random <code className="font-mono">.local</code> names.
          </p>
        </div>
      </Section>
      )}

      {isSelf && (
      <Section title="This browser & device">
        <div className="divide-y divide-dashed divide-line overflow-hidden rounded-xl border border-line bg-surface">
          {info.map(([k, v]) => (
            <KV key={k} k={k} v={String(v)} />
          ))}
        </div>
      </Section>
      )}
    </ToolShell>
  )
}
