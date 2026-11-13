#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { assess, parseProfile } from "./assess.js";
import { ClockError, ReportKind, reportingClock } from "./clock.js";
import { assessmentMarkdown, clockMarkdown, sbomMarkdown } from "./report.js";
import { AdvisoryError, SbomError, parseAdvisories, parseSbom, sbomQuality, matchAdvisories } from "./sbom.js";
import { ProfileError } from "./assess.js";

const USAGE = `cra-readiness

  cra-readiness sbom <sbom.json> [--vulns advisories.json] [--min-score N]
  cra-readiness assess <profile.json> [--sbom sbom.json] [--vulns advisories.json] [--today YYYY-MM-DD]
  cra-readiness clock --type vulnerability|incident --aware <ISO> [--fix <ISO>] [--now <ISO>]

Exit codes: 0 ok, 1 gate failed (sbom below --min-score or exploited vulnerability found), 2 bad input.`;

function opt(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function main(argv: string[]): number {
  const [cmd, ...rest] = argv;
  try {
    if (cmd === "sbom") {
      const file = rest[0];
      if (!file) { console.error(USAGE); return 2; }
      const doc = parseSbom(readFileSync(file, "utf8"));
      const q = sbomQuality(doc);
      process.stdout.write(sbomMarkdown(q, doc.format));
      let fail = false;
      const vf = opt(rest, "--vulns");
      if (vf) {
        const { hits } = matchAdvisories(doc, parseAdvisories(readFileSync(vf, "utf8")));
        process.stdout.write(`\n${hits.length} known vulnerabilit${hits.length === 1 ? "y" : "ies"} matched, ${hits.filter((h) => h.advisory.exploited).length} actively exploited.\n`);
        if (hits.some((h) => h.advisory.exploited)) fail = true;
      }
      const min = opt(rest, "--min-score");
      if (min !== undefined && q.score < Number(min)) { process.stdout.write(`\nGate: score ${q.score} is below ${min}.\n`); fail = true; }
      return fail ? 1 : 0;
    }
    if (cmd === "assess") {
      const file = rest[0];
      if (!file) { console.error(USAGE); return 2; }
      const today = opt(rest, "--today") ?? new Date().toISOString().slice(0, 10);
      const sf = opt(rest, "--sbom");
      const vf = opt(rest, "--vulns");
      const a = assess(parseProfile(readFileSync(file, "utf8")), today, sf ? parseSbom(readFileSync(sf, "utf8")) : undefined, vf ? parseAdvisories(readFileSync(vf, "utf8")) : undefined);
      process.stdout.write(assessmentMarkdown(a));
      return 0;
    }
    if (cmd === "clock") {
      const type = opt(rest, "--type");
      const aware = opt(rest, "--aware");
      if ((type !== "vulnerability" && type !== "incident") || !aware) { console.error(USAGE); return 2; }
      const now = opt(rest, "--now");
      const fix = opt(rest, "--fix");
      const ms = reportingClock(type as ReportKind, aware, { ...(fix ? { fixAvailable: fix } : {}), ...(now ? { now } : {}) });
      process.stdout.write(clockMarkdown(type, aware, ms, now));
      return 0;
    }
    console.error(USAGE);
    return 2;
  } catch (e) {
    if (e instanceof SbomError || e instanceof AdvisoryError || e instanceof ProfileError || e instanceof ClockError) { console.error(`error: ${e.message}`); return 2; }
    if ((e as NodeJS.ErrnoException).code === "ENOENT") { console.error(`error: cannot read ${(e as NodeJS.ErrnoException).path}`); return 2; }
    throw e;
  }
}

process.exitCode = main(process.argv.slice(2));
