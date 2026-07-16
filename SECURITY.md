# Security Policy

## Supported Versions

This project is developed on a rolling basis. Security fixes land on the latest
release and the `main` branch.

| Version | Supported |
| --- | --- |
| Latest release | ✅ |
| `main` (development) | ✅ |
| Older releases | ❌ |

## Reporting a Vulnerability

If you find a security issue **in Web Scanner itself** (for example, a way it
could damage a target it shouldn't, mishandle a scanned secret, or be abused),
please report it privately rather than opening a public issue.


- **Email:** Kostisnomikos@gmail.com
- Or use GitHub's **[Report a vulnerability](../../security/advisories/new)**
  (private advisory) if enabled on the repository.

Please include:

- A description of the issue and its impact.
- Steps to reproduce (a minimal proof of concept if possible).
- The version or commit you tested against.

**What to expect:**

- An acknowledgement within a few days.
- An honest assessment of severity and a fix timeline.
- Credit in the release notes once a fix ships, if you'd like it.

Please give a reasonable window to release a fix before disclosing publicly.

## Responsible Use

Web Scanner is a security-testing tool that sends real requests to a target.
It is intended **only** for systems you own or have explicit written permission
to test. Using it against systems you do not control may be illegal.

Reports that amount to "the tool successfully scanned a site I was not
authorized to scan" are **not** vulnerabilities in this project — that is a use
of the tool outside its intended scope, and the responsibility of the operator.

## Scope

**In scope**

- Bugs that cause the scanner to behave unsafely against a target (for example,
  sending a state-changing request when it claims to be read-only).
- Mishandling of secrets discovered during a scan (unintended logging, leaking,
  or exporting).
- Crashes, memory issues, or logic flaws in the scanning engine.

**Out of scope**

- Findings the tool reports about third-party websites.
- Use of the tool against unauthorized targets.
- Vulnerabilities in the sites you choose to scan.
