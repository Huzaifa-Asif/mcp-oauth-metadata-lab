# Threat model

## Assets and boundaries

Assets are developer attention, local metadata fixtures, and report integrity. Input crosses from an untrusted file or paste into local code. The app intentionally has no credential, token, network, account, or storage boundary.

## Misuse and controls

- **Secrets pasted by mistake:** flag secret-like keys and never echo values; documentation says use synthetic metadata. Pattern coverage is incomplete.
- **Maliciously large input:** reject serialized documents above 256 KB. JSON parsing still occurs before the semantic bound in the browser/CLI, so operating-system memory remains a limit.
- **URL-triggered SSRF:** URLs are parsed only; they are never fetched or rendered as links.
- **Report injection:** output uses `textContent`; Markdown formatter removes control/bidirectional characters and escapes backticks.
- **Supply-chain exposure:** no runtime or development dependencies; actions are pinned to commit SHAs.
- **False assurance:** every report states that checks are partial and offline.

Out of scope: compromised host/browser, live endpoint behavior, DNS rebinding, TLS, full RFC conformance, authorization-server security, and identity verification.
