import { MODES, INTENSITIES, TARGET_HINTS } from '../data/scanner.js'
import { Icon } from './Icon.jsx'

export default function ScanForm({ mode, setMode, intensity, setIntensity, target, setTarget, onRun, refusal }) {
  const activeMode = MODES.find((m) => m.id === mode) || MODES[0]
  const activeIntensity = INTENSITIES.find((i) => i.id === intensity) || INTENSITIES[0]
  const hint = TARGET_HINTS[activeMode.target]

  const submit = (e) => {
    e.preventDefault()
    if (target.trim()) onRun()
  }

  return (
    <form onSubmit={submit} className="px-4 pb-10 pt-6 sm:px-8">
      <fieldset id="modes" className="scroll-mt-20">
        <legend className="mb-2.5 font-mono text-[10px] uppercase tracking-[0.2em] text-ink-subtle">
          Scan mode
        </legend>
        <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3 lg:grid-cols-5">
          {MODES.map((m) => {
            const active = m.id === mode
            return (
              <button
                key={m.id}
                type="button"
                onClick={() => setMode(m.id)}
                aria-pressed={active}
                className={`rounded-lg border px-3 py-2 text-left text-[12.5px] font-medium transition-all duration-200 ${
                  active
                    ? 'border-ink-strong/30 bg-surface-hover text-ink-strong shadow-[inset_0_1px_0_var(--color-line-strong)]'
                    : 'border-line bg-surface text-ink-muted hover:border-line-strong hover:text-ink-secondary'
                }`}
              >
                {m.label}
              </button>
            )
          })}
        </div>
        <p className="mt-2 text-[12px] leading-relaxed text-ink-subtle">{activeMode.blurb}</p>
      </fieldset>

      <div className="mt-5">
        <label htmlFor="target" className="mb-2 block font-mono text-[10px] uppercase tracking-[0.2em] text-ink-subtle">
          {hint.label}
        </label>
        <div
          key={refusal || 'ok'}
          className={`group flex items-center gap-2 rounded-xl border bg-surface px-3.5 transition-colors duration-200 ${
            refusal
              ? 'animate-shake border-sev-critical/50'
              : 'border-line focus-within:border-ink-strong/40 hover:border-line-strong'
          }`}
        >
          <Icon name="search" className="h-4 w-4 shrink-0 text-ink-faint" />
          <input
            id="target"
            type="text"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={hint.placeholder}
            autoFocus
            className="h-10 w-full bg-transparent font-mono text-[13.5px] text-ink-strong outline-none placeholder:text-ink-faint"
          />
        </div>
      </div>

      <div className="mt-5">
        <span className="mb-2 block font-mono text-[10px] uppercase tracking-[0.2em] text-ink-subtle">Intensity</span>
        <div className="inline-flex flex-wrap gap-1 rounded-xl border border-line bg-surface p-1">
          {INTENSITIES.map((i) => {
            const active = i.id === intensity
            return (
              <button
                key={i.id}
                type="button"
                onClick={() => setIntensity(i.id)}
                aria-pressed={active}
                className={`rounded-lg px-3 py-1.5 text-[12.5px] font-medium transition-colors duration-200 ${
                  active ? 'bg-ink-strong text-bg' : 'text-ink-muted hover:text-ink-strong'
                }`}
              >
                {i.label}
              </button>
            )
          })}
        </div>
        <p className="mt-2 text-[12px] leading-relaxed text-ink-subtle">{activeIntensity.blurb}</p>
      </div>

      <button
        type="submit"
        disabled={!target.trim()}
        className="group mt-6 flex h-11 w-full items-center justify-center gap-2 rounded-xl bg-ink-strong text-[13.5px] font-semibold text-bg transition-all duration-200 hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
      >
        <Icon name="zap" className="h-4 w-4" strokeWidth={2} />
        Run scan
      </button>

      {refusal && (
        <div
          key={refusal}
          role="alert"
          className="animate-rise mt-3 flex items-start gap-3 rounded-xl border border-dashed border-sev-critical/40 bg-sev-critical/[0.06] px-4 py-3"
        >
          <span className="mt-px font-mono text-[10px] font-semibold uppercase tracking-[0.2em] text-sev-critical">403</span>
          <p className="text-[13px] leading-relaxed text-ink-strong">{refusal}</p>
        </div>
      )}
    </form>
  )
}
