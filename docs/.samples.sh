node dist/src/cli.js sbom examples/sbom-gateway.cdx.json --vulns examples/advisories.json > /tmp/sbom.md || test $? -eq 1
diff /tmp/sbom.md docs/sample-sbom.md
node dist/src/cli.js assess examples/profile-gateway.json --sbom examples/sbom-gateway.cdx.json --vulns examples/advisories.json --today 2026-11-13 > /tmp/assess.md
diff /tmp/assess.md docs/sample-assess.md
node dist/src/cli.js clock --type vulnerability --aware 2026-11-13T10:00:00Z --fix 2026-11-20T10:00:00Z --now 2026-11-13T12:00:00Z > /tmp/clock.md
diff /tmp/clock.md docs/sample-clock.md
node dist/src/cli.js sbom examples/sbom-clean.cdx.json --min-score 90 > /dev/null
test "$(node dist/src/cli.js sbom examples/sbom-gateway.cdx.json --vulns examples/advisories.json >/dev/null; echo $?)" = "1"
