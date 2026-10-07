
const handler =
  typeof window !== 'undefined' && window.webkit?.messageHandlers?.scanner

export const isNative = !!handler

let listeners = []

export function onUpdate(cb) {
  listeners.push(cb)
  return () => {
    listeners = listeners.filter((l) => l !== cb)
  }
}

if (typeof window !== 'undefined') {
  window.__wsBridge = {
    emit(snapshot) {
      listeners.forEach((l) => {
        try {
          l(snapshot)
        } catch (e) {
        }
      })
    },
  }
}

function post(msg) {
  if (handler) handler.postMessage(msg)
}

export function startScan({ target, mode, intensity }) {
  post({ type: 'start', target, mode, intensity })
}

export function stopScan() {
  post({ type: 'stop' })
}

export function exportReport(format = 'markdown') {
  post({ type: 'export', format })
}

export function openExternal(url) {
  post({ type: 'openExternal', url })
}

export function signalReady() {
  post({ type: 'ready' })
}
