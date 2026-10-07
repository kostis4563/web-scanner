const CORNERS = ['tl', 'tr', 'br', 'bl']

export default function LiveSelect({ children, name }) {
  return (
    <span className="live-select">
      {children}
      <span aria-hidden="true" className="live-select-frame">
        <span className="live-select-box" />
        {CORNERS.map((corner, i) => (
          <span key={corner} className="fig-handle live-select-handle" data-corner={corner} style={{ '--i': i }} />
        ))}
      </span>
      <span aria-hidden="true" className="live-select-ripple" />
      <span aria-hidden="true" className="live-select-track">
        <span className="live-select-cursor">
          <span className="live-select-pointer">
            <svg viewBox="0 0 16 16" className="fig-arrow live-select-arrow">
              <path d="M2.5 1.5v12l3.6-3.2 5.9-.4z" />
            </svg>
            <span className="fig-tag">{name}</span>
          </span>
        </span>
      </span>
    </span>
  )
}
