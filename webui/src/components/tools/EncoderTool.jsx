import { useMemo, useState } from 'react'
import ToolShell from './ToolShell.jsx'
import { CopyButton, ErrorNote, Label, Segmented, Textarea } from './ui.jsx'
import { Icon } from '../Icon.jsx'

const SCHEMES = [
  { id: 'base64', label: 'Base64' },
  { id: 'url', label: 'URL' },
  { id: 'hex', label: 'Hex' },
  { id: 'html', label: 'HTML' },
]

const utf8ToBytes = (str) => new TextEncoder().encode(str)
const bytesToUtf8 = (bytes) => new TextDecoder('utf-8', { fatal: true }).decode(bytes)

const codecs = {
  base64: {
    encode: (s) => {
      let bin = ''
      utf8ToBytes(s).forEach((b) => (bin += String.fromCharCode(b)))
      return btoa(bin)
    },
    decode: (s) => {
      const bin = atob(s.trim())
      const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
      return bytesToUtf8(bytes)
    },
  },
  url: {
    encode: (s) => encodeURIComponent(s),
    decode: (s) => decodeURIComponent(s),
  },
  hex: {
    encode: (s) =>
      Array.from(utf8ToBytes(s))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(''),
    decode: (s) => {
      const clean = s.replace(/[^0-9a-fA-F]/g, '')
      if (clean.length % 2) throw new Error('Hex needs an even number of digits.')
      const bytes = new Uint8Array(clean.length / 2)
      for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.substr(i * 2, 2), 16)
      return bytesToUtf8(bytes)
    },
  },
  html: {
    encode: (s) =>
      s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
    decode: (s) => {
      const el = document.createElement('textarea')
      el.innerHTML = s
      return el.value
    },
  },
}

export default function EncoderTool() {
  const [scheme, setScheme] = useState('base64')
  const [dir, setDir] = useState('encode')
  const [input, setInput] = useState('')

  const { output, error } = useMemo(() => {
    if (!input) return { output: '', error: null }
    try {
      return { output: codecs[scheme][dir](input), error: null }
    } catch (e) {
      return { output: '', error: e.message || `Could not ${dir} this as ${scheme}.` }
    }
  }, [scheme, dir, input])

  return (
    <ToolShell toolId="encoder">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented options={SCHEMES} value={scheme} onChange={setScheme} />
        <Segmented
          options={[
            { id: 'encode', label: 'Encode' },
            { id: 'decode', label: 'Decode' },
          ]}
          value={dir}
          onChange={setDir}
        />
        <button
          type="button"
          onClick={() => {
            setDir((d) => (d === 'encode' ? 'decode' : 'encode'))
            if (output) setInput(output)
          }}
          className="flex h-9 items-center gap-1.5 rounded-lg border border-line bg-surface px-3 text-[12.5px] font-medium text-ink-muted transition-colors hover:border-line-strong hover:text-ink-strong"
          title="Swap input and output"
        >
          <Icon name="swap" className="h-4 w-4" /> Swap
        </button>
      </div>

      <div className="mt-5">
        <Label>Input</Label>
        <Textarea value={input} onChange={setInput} placeholder="Type or paste text…" rows={6} />
      </div>

      <ErrorNote>{error}</ErrorNote>

      <div className="mt-5">
        <div className="mb-2 flex items-center justify-between">
          <Label>Output</Label>
          <CopyButton value={output} />
        </div>
        <Textarea value={output} readOnly rows={6} placeholder="Result appears here" />
      </div>
    </ToolShell>
  )
}
