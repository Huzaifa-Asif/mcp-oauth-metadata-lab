# Security policy

Report suspected vulnerabilities privately through GitHub Security Advisories. Do not include real credentials or production metadata. Maintainers will acknowledge a credible report when practical, assess supported `main` and the latest release, and coordinate a fix before public detail.

The tool treats fixtures as untrusted data, bounds them to 256 KB, does not fetch URLs, flags secret-like keys, escapes Markdown control characters, serves restrictive security headers locally, and has no runtime dependencies. These controls do not make arbitrary input safe for other tools.
