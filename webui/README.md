# WebScanner UI

A fresh React frontend for WebScanner, styled to match [blxr.net](https://blxr.net)
(dark `#090909`, dashed hairline column, Plus Jakarta Sans + Playfair Display italic,
mono accents, light/dark themes).

This is a **UI preview with sample data** — it does not run real scans yet. It mirrors the
native Swift scanner's model: 10 scan modes, 5 intensity levels, and findings with severity,
evidence, and a copy-paste proof of concept.

The native Swift app in `../Sources/WebScanner` is untouched.

## Stack
- React 19 + Vite + Tailwind CSS v4
- Packaged as a native macOS `.app` via a ~90-line Swift WKWebView launcher (no Electron)

## Develop
```bash
npm install
npm run dev        # http://localhost:5173
```

## Build a double-clickable app
```bash
npm run app        # builds the bundle + "WebScanner UI.app"
npm run app -- --run   # ...and opens it
```
The script runs `vite build`, compiles the Swift launcher with `swiftc`, and assembles the
`.app`. The web build is served inside the WebView over a custom `app://` scheme (WKWebView
blocks ES-module scripts loaded from `file://`).

## Layout
- `src/App.jsx` — stages: idle (hero + form) → running → results
- `src/components/` — Header, ScanForm, ScanRunning, Results, FindingCard, ThemeToggle, Icon
- `src/data/scanner.js` — modes, intensities, and the mock findings
- `src/index.css` — blxr design tokens (`@theme`) + fonts
- `build-app.sh` — the packaging script
