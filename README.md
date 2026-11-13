# cra-readiness

Cyber Resilience Act readiness for manufacturers, importers and distributors. Check an SBOM, self-assess against Annex I, find the conformity route for your product class and run the Article 14 reporting clock. Zero runtime dependencies. Nothing is uploaded.

**Live demo:** https://jvch0512.github.io/cra-readiness/

## Why

Reporting under Article 14 of Regulation (EU) 2024/2847 has applied since 11 September 2026, and it covers products already on the market. The rest of the Regulation applies from 11 December 2027. Most teams know the second date and miss the first. This tool turns both into a checklist you can run in a pre-sales workshop or in CI.

## What you get

| Command | Output |
|---|---|
| `sbom` | NTIA minimum elements coverage, duplicates, a 0 to 100 quality score, optional matching against your advisories, a CI gate (`--min-score`, fails on actively exploited vulnerabilities) |
| `assess` | Annex I readiness (21 requirements, weighted), conformity route by product class, duties by role, a prioritised "do first" list that puts an exploited vulnerability in your SBOM at the top |
| `clock` | Article 14 deadlines from the moment you became aware: early warning 24 h, notification 72 h, final report after the fix (vulnerability) or one month after notification (incident) |

```
npm install && npm run build
node dist/src/cli.js sbom examples/sbom-gateway.cdx.json --vulns examples/advisories.json
node dist/src/cli.js assess examples/profile-gateway.json --sbom examples/sbom-gateway.cdx.json --vulns examples/advisories.json
node dist/src/cli.js clock --type vulnerability --aware 2026-11-13T10:00:00Z --fix 2026-11-20T10:00:00Z
npm start      # browser UI on http://127.0.0.1:8787
```

Sample outputs are committed in `docs/` and CI fails if they drift.

## Inputs

- **SBOM**: CycloneDX JSON or SPDX 2.x JSON.
- **Advisories**: a JSON object keyed by package URL, each entry `{ "id", "severity", "exploited", "fixedIn?" }`. Bring your own feed (OSV export, a KEV join, your tracker). The bundled sample uses synthetic IDs, not real CVEs.
- **Profile**: product name, role, class (`default`, `important-1`, `important-2`, `critical`), support period in years and `yes`/`partial`/`no` answers keyed by requirement id (see `src/obligations.ts`). Missing answers count as `no`.

## Limits

- It is a readiness aid, not a conformity assessment and not legal advice. Dates and article references were checked against public sources in November 2026. Verify them against the Official Journal before you rely on them.
- Vulnerability matching only works for components with a package URL, and the report says how many it could not match.
- The "one month" in the incident final report is modelled as 30 days.
- Product class (important or critical) is your input. The tool does not decide it from the product description.

## Security

The browser UI runs under a strict Content Security Policy (no inline script or style), parses everything locally and writes user text only with `textContent`. The CLI reads files you name and nothing else.

MIT licence.
