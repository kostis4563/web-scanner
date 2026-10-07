import { useCallback, useEffect, useState } from 'react'
import Header from './components/Header.jsx'
import Footer from './components/Footer.jsx'
import ScanForm from './components/ScanForm.jsx'
import ScanRunning from './components/ScanRunning.jsx'
import Results from './components/Results.jsx'
import LiveSelect from './components/LiveSelect.jsx'
import { mockFindings, mockLog, pickRefusal } from './data/scanner.js'
import {
  isNative,
  onUpdate,
  signalReady,
  startScan as nativeStart,
  stopScan as nativeStop,
  exportReport as nativeExport,
} from './bridge.js'

export default function App() {
  const [mode, setMode] = useState('siteScan')
  const [intensity, setIntensity] = useState('standard')
  const [target, setTarget] = useState('')
  const [refusal, setRefusal] = useState(null)

  const [mockStage, setMockStage] = useState('idle')
  const [mockLogLines, setMockLogLines] = useState([])
  const [mockResults, setMockResults] = useState([])

  const [snap, setSnap] = useState(null)
  const [forceIdle, setForceIdle] = useState(false)

  useEffect(() => {
    if (!isNative) return
    const off = onUpdate(setSnap)
    signalReady()
    return off
  }, [])

  useEffect(() => {
    if (isNative && snap && !snap.running && !snap.done && snap.target && !target) {
      setTarget(snap.target)
      if (snap.mode) setMode(snap.mode)
      if (snap.intensity) setIntensity(snap.intensity)
    }
  }, [snap?.target])

  const hostOf = (t) => t.replace(/^https?:\/\//, '').replace(/\/.*$/, '') || t

  const isCreatorSite = (t) => {
    const host = t.trim().replace(/^[a-z]+:\/\//i, '').split(/[/?#]/)[0].replace(/:\d+$/, '')
    return /(^|\.)blxr\.net\.?$/i.test(host)
  }

  const editTarget = (t) => {
    setTarget(t)
    setRefusal(null)
  }

  const run = () => {
    if (!target.trim()) return
    if (isCreatorSite(target)) {
      setRefusal((r) => pickRefusal(r))
      return
    }
    if (isNative) {
      setForceIdle(false)
      nativeStart({ target, mode, intensity })
      return
    }
    setMockLogLines(mockLog(mode, hostOf(target)))
    setMockStage('running')
  }

  const finishMock = useCallback(() => {
    setMockResults(mockFindings(mode))
    setMockStage('results')
  }, [mode])

  const reset = () => {
    if (isNative) {
      setForceIdle(true)
      return
    }
    setMockStage('idle')
    setMockResults([])
  }

  let stage, log, findings, progress
  if (isNative) {
    if (snap?.running) stage = 'running'
    else if (snap?.done && !forceIdle) stage = 'results'
    else stage = 'idle'
    log = snap?.log ?? []
    findings = snap?.findings ?? []
    progress = snap?.progress ?? 0
  } else {
    stage = mockStage
    log = mockLogLines
    findings = mockResults
    progress = 0
  }

  const resultHost = isNative ? snap?.host || hostOf(target) : hostOf(target)
  const resultMode = isNative ? snap?.mode || mode : mode

  return (
    <div className="flex min-h-screen flex-col bg-bg font-sans text-ink antialiased">
      <Header />

      <main className="mx-auto w-full max-w-[960px] flex-1 rule-x pt-[var(--header-h)]">
        {stage === 'idle' && (
          <div className="animate-rise">
            <section className="border-b border-dashed border-line px-4 py-7 sm:px-8">
              <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-ink-subtle">
                Web security scanner
              </p>
              <h1 className="mt-2.5 text-[24px] font-semibold leading-[1.1] tracking-tight text-ink-strong sm:text-[28px]">
                Find what a site is <LiveSelect name="scanner">
                  <span className="font-serif font-normal italic">leaking</span>
                </LiveSelect>
                .
              </h1>
              <p className="mt-2 max-w-[56ch] text-[13px] leading-relaxed text-ink-subtle">
                Point it at a URL or host — headers, TLS, secrets, injection, exposed ports — and get back
                findings with evidence and a copy-paste proof of concept.
              </p>
            </section>

            <ScanForm
              mode={mode}
              setMode={setMode}
              intensity={intensity}
              setIntensity={setIntensity}
              target={target}
              setTarget={editTarget}
              refusal={refusal}
              onRun={run}
            />
          </div>
        )}

        {stage === 'running' && (
          <ScanRunning
            log={log}
            target={resultHost}
            status={isNative ? snap?.status : undefined}
            live={isNative}
            progress={progress}
            onStop={isNative ? nativeStop : undefined}
            onDone={isNative ? undefined : finishMock}
          />
        )}

        {stage === 'results' && (
          <Results
            mode={resultMode}
            target={resultHost}
            findings={findings}
            onNewScan={reset}
            onExport={isNative ? () => nativeExport('markdown') : undefined}
          />
        )}
      </main>

      <div className="mx-auto w-full max-w-[960px] rule-x">
        <Footer />
      </div>
    </div>
  )
}
