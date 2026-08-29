# Contributing

Thanks for your interest in Web Scanner.

## Ground rules

Only ever point the scanner at hosts you own or have written permission to test.
Pull requests that add scan modes must document what requests they generate.

## Getting set up

```bash
git clone https://github.com/kostis4563/web-scanner.git
cd web-scanner
./build.sh
```

Requires macOS 13+ and Swift 5.9.

## Pull requests

- One logical change per pull request.
- Match the existing code style (see `.editorconfig`).
- Describe the security impact of the change, if any.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md).
