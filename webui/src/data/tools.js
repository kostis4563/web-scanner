export const CATEGORY_ORDER = ['Security', 'Encoding', 'Generators', 'Network']

export const TOOLS = [
  {
    id: 'webscanner',
    name: 'WebScanner',
    category: 'Security',
    icon: 'shield',
    blurb: 'Point it at a URL or host and get back findings with evidence and a copy-paste proof of concept — headers, TLS, secrets, injection, ports.',
    tag: 'scanner',
  },
  {
    id: 'encoder',
    name: 'Encoder / Decoder',
    category: 'Encoding',
    icon: 'code',
    blurb: 'Encode and decode Base64, URL components, hex and HTML entities. Switches direction in one click.',
    tag: 'base64 · url · hex · html',
  },
  {
    id: 'hash',
    name: 'Hash Generator',
    category: 'Encoding',
    icon: 'hash',
    blurb: 'Hash any text with SHA-1, SHA-256, SHA-384 or SHA-512 using the browser’s Web Crypto engine.',
    tag: 'sha-1 · sha-256/384/512',
  },
  {
    id: 'jwt',
    name: 'JWT Decoder',
    category: 'Encoding',
    icon: 'key',
    blurb: 'Decode a JSON Web Token’s header and payload, pretty-print the claims, and flag expiry — all locally, nothing leaves the app.',
    tag: 'header · payload · claims',
  },
  {
    id: 'password',
    name: 'Password Generator',
    category: 'Generators',
    icon: 'refresh',
    blurb: 'Generate strong, cryptographically-random passwords with length and character-set controls plus a live strength read-out.',
    tag: 'crypto-random',
  },
  {
    id: 'uuid',
    name: 'UUID Generator',
    category: 'Generators',
    icon: 'id',
    blurb: 'Mint RFC 4122 v4 UUIDs in bulk, uppercase or hyphen-free, straight from the platform crypto source.',
    tag: 'v4 · rfc 4122',
  },
  {
    id: 'color',
    name: 'Color Converter',
    category: 'Encoding',
    icon: 'palette',
    blurb: 'Convert any CSS color between HEX, RGB and HSL, and check WCAG contrast against a background.',
    tag: 'hex · rgb · hsl · wcag',
  },
  {
    id: 'headers',
    name: 'Security Headers Grader',
    category: 'Security',
    icon: 'gauge',
    blurb: 'Paste a response’s raw headers and get a graded report — HSTS, CSP, frame options, cookie flags and info leaks.',
    tag: 'grade · hsts · csp',
  },
  {
    id: 'ipinfo',
    name: 'IP Lookup',
    category: 'Network',
    icon: 'wifi',
    blurb: 'Look up any IP or host — geolocation, ASN and ISP — or leave it blank for your own, plus your browser fingerprint and a WebRTC leak check.',
    tag: 'ip · geo · asn · fingerprint',
  },
  {
    id: 'liveview',
    name: 'Live Website View',
    category: 'Network',
    icon: 'monitor',
    blurb: 'Load any site in a live, interactive frame — scroll and click around at desktop, tablet or phone widths.',
    tag: 'live · responsive',
  },
  {
    id: 'webhook',
    name: 'Webhook Sender',
    category: 'Network',
    icon: 'inbox',
    blurb: 'Point it at a webhook URL, type a message or JSON payload, send it, and see the response — status, timing and body.',
    tag: 'send · test · response',
  },
]

export const toolsByCategory = () => {
  const groups = Object.fromEntries(CATEGORY_ORDER.map((c) => [c, []]))
  for (const t of TOOLS) (groups[t.category] ||= []).push(t)
  return CATEGORY_ORDER.filter((c) => groups[c]?.length).map((c) => ({
    category: c,
    tools: groups[c],
  }))
}

export const getTool = (id) => TOOLS.find((t) => t.id === id)
