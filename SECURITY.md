# Security Policy

Peekaboo analyzes **untrusted patch artifacts and binaries** as part of
CVE root-cause work. Failures that turn hostile input into process
compromise, silent wrong conclusions presented as high confidence, or
filesystem damage are security issues.

## Reporting

Please **do not** file public issues for:

- Crashes / memory unsafety in download, extract, or RE glue code
- Path traversal or overwrite bugs in export packs (`report.md`,
  `cinema.html`, `poc/`, `repro.sh`)
- Accidental leakage of API keys or local paths into exported HTML/JSON
- Prompt / tool output that exfiltrates secrets from the operator environment

Use a private GitHub security advisory instead:

https://github.com/eddinos2/Peekaboo/security/advisories/new

Include the CVE id (if any), platform pipeline, and a minimal reproducer.

## Out of scope

- Quality of LLM root-cause prose
- Missing coverage for a specific vendor advisory feed
- Feature requests for additional RE backends

## Also out of scope

- LLM prose quality debates
- Missing vendor advisory feeds
