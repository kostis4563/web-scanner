const PATHS = {
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>,
  moon: <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />,
  arrowUpRight: <path d="M7 17 17 7M8 7h9v9" />,
  chevron: <path d="m6 9 6 6 6-6" />,
  shield: <path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" />,
  terminal: <><path d="m4 17 6-5-6-5" /><path d="M12 19h8" /></>,
  copy: <><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" /></>,
  check: <path d="M20 6 9 17l-5-5" />,
  search: <><circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" /></>,
  zap: <path d="M13 2 4 14h7l-1 8 9-12h-7l1-8z" />,
  x: <path d="M18 6 6 18M6 6l12 12" />,
  globe: <><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" /></>,
  dot: <circle cx="12" cy="12" r="4" />,
  github: <path d="M12 2a10 10 0 0 0-3.2 19.5c.5.1.7-.2.7-.5v-1.7c-2.8.6-3.4-1.3-3.4-1.3-.5-1.2-1.1-1.5-1.1-1.5-.9-.6.1-.6.1-.6 1 .1 1.5 1 1.5 1 .9 1.5 2.3 1.1 2.9.8.1-.6.3-1.1.6-1.3-2.2-.3-4.6-1.1-4.6-5 0-1.1.4-2 1-2.7-.1-.3-.4-1.3.1-2.6 0 0 .8-.3 2.7 1a9.4 9.4 0 0 1 5 0c1.9-1.3 2.7-1 2.7-1 .5 1.3.2 2.3.1 2.6.6.7 1 1.6 1 2.7 0 3.9-2.4 4.7-4.6 5 .3.3.6.9.6 1.8v2.7c0 .3.2.6.7.5A10 10 0 0 0 12 2z" />,
  code: <><path d="m8 6-6 6 6 6" /><path d="m16 6 6 6-6 6" /></>,
  hash: <path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18" />,
  key: <><circle cx="7.5" cy="15.5" r="4.5" /><path d="m10.7 12.3 8-8M15.5 4.5l4 4M13 7l2.5 2.5" /></>,
  id: <><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M7 9h4M7 13h8M7 16h5" /></>,
  grid: <><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></>,
  arrowLeft: <path d="M19 12H5M12 19l-7-7 7-7" />,
  refresh: <path d="M21 12a9 9 0 1 1-2.6-6.4M21 3v5.4h-5.4" />,
  swap: <><path d="M7 4 3 8l4 4" /><path d="M3 8h14M17 20l4-4-4-4" /><path d="M21 16H7" /></>,
  palette: <><path d="M12 3a9 9 0 1 0 0 18c1.1 0 2-.9 2-2 0-.5-.2-.9-.5-1.3-.3-.3-.5-.8-.5-1.2 0-1.1.9-2 2-2h2.3A4.4 4.4 0 0 0 21 9.5C21 5.9 16.9 3 12 3z" /><circle cx="7.5" cy="11.5" r="1" /><circle cx="12" cy="8" r="1" /><circle cx="16" cy="11" r="1" /></>,
  wifi: <><path d="M2 8.8a16 16 0 0 1 20 0M5.5 12.3a11 11 0 0 1 13 0M9 15.8a6 6 0 0 1 6 0" /><circle cx="12" cy="19" r="1" /></>,
  monitor: <><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4" /></>,
  inbox: <><path d="M3 12h5l2 3h4l2-3h5" /><path d="M4 12 6 5h12l2 7v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z" /></>,
  gauge: <><path d="M12 14 16 9" /><path d="M4 18a8 8 0 1 1 16 0" /><circle cx="12" cy="14" r="1.2" /></>,
  link: <><path d="M9 15l6-6" /><path d="M10.5 6.5 13 4a4 4 0 0 1 6 6l-2.5 2.5" /><path d="M13.5 17.5 11 20a4 4 0 0 1-6-6l2.5-2.5" /></>,
}

export function Icon({ name, className = 'h-4 w-4', strokeWidth = 1.8 }) {
  const fillIcons = ['github']
  const filled = fillIcons.includes(name)
  return (
    <svg
      viewBox="0 0 24 24"
      className={className}
      fill={filled ? 'currentColor' : 'none'}
      stroke={filled ? 'none' : 'currentColor'}
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {PATHS[name]}
    </svg>
  )
}
