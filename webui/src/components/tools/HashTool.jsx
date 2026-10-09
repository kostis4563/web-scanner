import { useEffect, useState } from 'react'
import ToolShell from './ToolShell.jsx'
import { CopyButton, Label, Segmented, Textarea } from './ui.jsx'

const ALGOS = [
  { id: 'SHA-1', label: 'SHA-1' },
  { id: 'SHA-256', label: 'SHA-256' },
  { id: 'SHA-384', label: 'SHA-384' },
  { id: 'SHA-512', label: 'SHA-512' },
]

const toHex = (buf) =>
  Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')

export default function HashTool() {
  const [algo, setAlgo] = useState('SHA-256')
  const [input, setInput] = useState('')
  const [digest, setDigest] = useState('')

  useEffect(() => {
    let cancelled = false
    if (!input) {
      setDigest('')
      return
    }
    const subtle = globalThis.crypto?.subtle
    if (!subtle) {
      setDigest('Web Crypto is unavailable in this context.')
      return
    }
    subtle
      .digest(algo, new TextEncoder().encode(input))
      .then((buf) => !cancelled && setDigest(toHex(buf)))
      .catch(() => !cancelled && setDigest('Could not compute digest.'))
    return () => {
      cancelled = true
    }
  }, [algo, input])

  return (
    <ToolShell toolId="hash">
      <Segmented options={ALGOS} value={algo} onChange={setAlgo} />

      <div className="mt-5">
        <Label>Input</Label>
        <Textarea value={input} onChange={setInput} placeholder="Type or paste text to hash…" rows={6} />
      </div>

      <div className="mt-5">
        <div className="mb-2 flex items-center justify-between">
          <Label>{algo} digest</Label>
          <CopyButton value={input ? digest : ''} />
        </div>
        <div className="min-h-[52px] rounded-xl border border-line bg-surface px-3.5 py-3 font-mono text-[13px] leading-relaxed text-ink-strong break-all">
          {input ? digest : <span className="text-ink-faint">Digest appears here</span>}
        </div>
        {input && digest && !digest.includes(' ') && (
          <p className="mt-2 font-mono text-[11px] text-ink-subtle">{digest.length / 2} bytes · {digest.length} hex chars</p>
        )}
      </div>
    </ToolShell>
  )
}
