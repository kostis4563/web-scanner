import { Icon } from './Icon.jsx'
import { isNative, openExternal } from '../bridge.js'

const LINKS = [
  { href: 'https://blxr.net', label: 'blxr.net', icon: 'globe' },
  { href: 'https://github.com/kostis4563', label: 'GitHub', icon: 'github' },
]

export default function Footer() {
  return (
    <footer className="border-t border-dashed border-line px-6 py-6 text-center">
      <nav aria-label="Links" className="flex items-center justify-center gap-2">
        {LINKS.map((l) => (
          <a
            key={l.href}
            href={l.href}
            target="_blank"
            rel="noreferrer"
            onClick={(e) => {
              if (isNative) {
                e.preventDefault()
                openExternal(l.href)
              }
            }}
            className="group inline-flex h-8 items-center gap-1.5 rounded-lg border border-line bg-surface px-3 text-[12.5px] font-medium text-ink-muted transition-colors duration-200 hover:border-line-strong hover:text-ink-strong"
          >
            <Icon name={l.icon} className="h-3.5 w-3.5" />
            {l.label}
            <Icon
              name="arrowUpRight"
              className="h-3 w-3 text-ink-faint transition-transform duration-200 group-hover:-translate-y-px group-hover:translate-x-px group-hover:text-ink-strong"
            />
          </a>
        ))}
      </nav>
    </footer>
  )
}
