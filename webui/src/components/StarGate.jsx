import { useState } from 'react'
import { Icon } from './Icon.jsx'
import { ErrorNote } from './tools/ui.jsx'
import { isNative, openExternal } from '../bridge.js'
import { GH_OWNER, GH_REPO, REPO_URL, PROFILE_URL, USERNAME_RE, verifyGithub } from '../data/github.js'

const STEPS = [
  { key: 'starred', title: `Star ${GH_OWNER}/${GH_REPO}`, href: REPO_URL, action: 'Star' },
  { key: 'follows', title: `Follow @${GH_OWNER}`, href: PROFILE_URL, action: 'Follow' },
]

function StepMark({ index, state }) {
  if (state === true) {
    return (
      <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-sev-info/40 bg-sev-info/10 text-sev-info">
        <Icon name="check" className="h-3.5 w-3.5" strokeWidth={2.4} />
      </span>
    )
  }
  if (state === false) {
    return (
      <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-sev-critical/40 bg-sev-critical/[0.06] text-sev-critical">
        <Icon name="x" className="h-3.5 w-3.5" strokeWidth={2.4} />
      </span>
    )
  }
  return (
    <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-line font-mono text-[10.5px] text-ink-subtle">
      {String(index + 1).padStart(2, '0')}
    </span>
  )
}

export default function StarGate({ initial, onUnlock }) {
  const [user, setUser] = useState(initial?.login ?? '')
  const [result, setResult] = useState(initial ?? null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const handle = user.trim().replace(/^@/, '')
  const valid = USERNAME_RE.test(handle)

  const editUser = (v) => {
    setUser(v)
    setResult(null)
    setError(null)
  }

  const verify = async (e) => {
    e.preventDefault()
    if (!valid || busy) return
    setBusy(true)
    setError(null)
    try {
      const r = await verifyGithub(handle)
      setResult(r)
      if (r.starred && r.follows) onUnlock(r.login)
    } catch (err) {
      setResult(null)
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="animate-rise">
      <section className="border-b border-dashed border-line px-4 py-7 sm:px-8">
        <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-ink-subtle">Unlock the scanner</p>
        <h1 className="mt-2.5 text-[24px] font-semibold leading-[1.1] tracking-tight text-ink-strong sm:text-[28px]">
          Free to use — for a <span className="font-serif font-normal italic">star</span> and a follow.
        </h1>
        <p className="mt-2 max-w-[56ch] text-[13px] leading-relaxed text-ink-subtle">
          Star the repo and follow @{GH_OWNER} on GitHub, then enter your username to unlock WebScanner. The other
          tools stay open either way.
        </p>
      </section>

      <form onSubmit={verify} className="px-4 py-6 sm:px-8">
        <ol className="divide-y divide-dashed divide-line rounded-xl border border-line bg-surface">
          {STEPS.map((s, i) => (
            <li key={s.key} className="flex items-center gap-3 px-3.5 py-3">
              <StepMark index={i} state={result ? result[s.key] : null} />
              <div className="min-w-0 flex-1">
                <p className="text-[13.5px] font-medium text-ink-strong">{s.title}</p>
                <p className="truncate font-mono text-[11.5px] text-ink-subtle">{s.href.replace(/^https:\/\//, '')}</p>
              </div>
              <a
                href={s.href}
                target="_blank"
                rel="noreferrer"
                onClick={(e) => {
                  if (isNative) {
                    e.preventDefault()
                    openExternal(s.href)
                  }
                }}
                className="group inline-flex h-8 shrink-0 items-center gap-1.5 rounded-lg border border-line bg-surface-raised px-3 text-[12.5px] font-medium text-ink-muted transition-colors duration-200 hover:border-line-strong hover:text-ink-strong"
              >
                <Icon name="github" className="h-3.5 w-3.5" />
                {s.action}
                <Icon
                  name="arrowUpRight"
                  className="h-3 w-3 text-ink-faint transition-transform duration-200 group-hover:-translate-y-px group-hover:translate-x-px group-hover:text-ink-strong"
                />
              </a>
            </li>
          ))}
        </ol>

        <div className="mt-5">
          <label htmlFor="gh-user" className="mb-2 block font-mono text-[10px] uppercase tracking-[0.2em] text-ink-subtle">
            Your GitHub username
          </label>
          <div className="group flex items-center gap-2 rounded-xl border border-line bg-surface px-3.5 transition-colors duration-200 focus-within:border-ink-strong/40 hover:border-line-strong">
            <Icon name="github" className="h-4 w-4 shrink-0 text-ink-faint" />
            <input
              id="gh-user"
              type="text"
              autoComplete="username"
              autoCapitalize="off"
              spellCheck={false}
              value={user}
              onChange={(e) => editUser(e.target.value)}
              placeholder="octocat"
              autoFocus
              className="h-10 w-full bg-transparent font-mono text-[13.5px] text-ink-strong outline-none placeholder:text-ink-faint"
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={!valid || busy}
          className="group mt-6 flex h-11 w-full items-center justify-center gap-2 rounded-xl bg-ink-strong text-[13.5px] font-semibold text-bg transition-all duration-200 hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Icon name={busy ? 'refresh' : 'key'} className={`h-4 w-4 ${busy ? 'animate-spin' : ''}`} strokeWidth={2} />
          {busy ? 'Checking GitHub…' : 'Verify & unlock'}
        </button>

        <ErrorNote>{error}</ErrorNote>

        {result && !(result.starred && result.follows) && (
          <p className="mt-3 text-[12px] leading-relaxed text-ink-subtle">
            Not there yet for @{result.login}. Just did it? GitHub can take a few seconds to catch up — verify again.
          </p>
        )}
      </form>
    </div>
  )
}
