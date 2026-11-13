import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { assess, parseProfile, ProfileError } from "../src/assess.js";
import { ClockError, reportingClock } from "../src/clock.js";
import { REQUIREMENTS, daysUntil, isReportingLive } from "../src/obligations.js";
import { AdvisoryError, SbomError, matchAdvisories, parseAdvisories, parseSbom, sbomQuality } from "../src/sbom.js";

const ex = (n: string): string => readFileSync(new URL(`../../examples/${n}`, import.meta.url), "utf8");

test("CycloneDX: parses components and scores quality", () => {
  const d = parseSbom(ex("sbom-gateway.cdx.json"));
  assert.equal(d.format, "cyclonedx");
  assert.equal(d.components.length, 12);
  const q = sbomQuality(d);
  assert.ok(q.score < 100 && q.score > 40);
  assert.deepEqual(q.duplicates, ["jsonwebtoken@8.5.1"]);
  assert.ok(q.withSupplier < 100 && q.withIdentifier < 100);
  assert.ok(q.hasRelationships && q.hasAuthor && q.hasTimestamp);
});

test("a clean SBOM scores 100", () => {
  const q = sbomQuality(parseSbom(ex("sbom-clean.cdx.json")));
  assert.equal(q.score, 100);
  assert.deepEqual(q.issues, []);
});

test("SPDX JSON is understood", () => {
  const spdx = JSON.stringify({
    spdxVersion: "SPDX-2.3", creationInfo: { created: "2026-01-01T00:00:00Z", creators: ["Tool: x"] },
    packages: [{ name: "a", versionInfo: "1", supplier: "Organization: Acme", licenseConcluded: "MIT", externalRefs: [{ referenceType: "purl", referenceLocator: "pkg:npm/a@1" }] }, { name: "b", supplier: "NOASSERTION", licenseConcluded: "NOASSERTION" }],
    relationships: [{ relationshipType: "DEPENDS_ON" }],
  });
  const d = parseSbom(spdx);
  assert.equal(d.format, "spdx");
  assert.equal(d.components[0]!.supplier, "Acme");
  assert.equal(d.components[1]!.supplier, "");
  assert.equal(d.relationships, 1);
  assert.equal(sbomQuality(d).withIdentifier, 50);
});

test("rejects garbage SBOMs", () => {
  assert.throws(() => parseSbom("nope"), SbomError);
  assert.throws(() => parseSbom("[]"), SbomError);
  assert.throws(() => parseSbom('{"hello":1}'), /unrecognised/);
});

test("advisories match by purl and exploited ones sort first", () => {
  const d = parseSbom(ex("sbom-gateway.cdx.json"));
  const { hits, unmatchable } = matchAdvisories(d, parseAdvisories(ex("advisories.json")));
  assert.equal(hits.length, 3);
  assert.equal(hits[0]!.advisory.exploited, true);
  assert.equal(unmatchable, 1);
});

test("advisory validation", () => {
  assert.throws(() => parseAdvisories("[]"), AdvisoryError);
  assert.throws(() => parseAdvisories('{"pkg:x":[{"id":"a","severity":"bad"}]}'), /severity/);
  assert.throws(() => parseAdvisories('{"pkg:x":[{"severity":"low"}]}'), /id/);
});

test("clock: vulnerability gives 24h, 72h and a final report 14 days after the fix", () => {
  const m = reportingClock("vulnerability", "2026-11-13T10:00:00Z", { fixAvailable: "2026-11-20T10:00:00Z" });
  assert.equal(m[0]!.due, "2026-11-14T10:00:00Z");
  assert.equal(m[1]!.due, "2026-11-16T10:00:00Z");
  assert.equal(m[2]!.due, "2026-12-04T10:00:00Z");
});

test("clock: without a fix date the vulnerability final report is open", () => {
  assert.equal(reportingClock("vulnerability", "2026-11-13T10:00:00Z")[2]!.due, null);
});

test("clock: incident final report follows the notification", () => {
  const m = reportingClock("incident", "2026-11-13T10:00:00Z");
  assert.equal(m[2]!.due, "2026-12-16T10:00:00Z");
});

test("clock: flags overdue steps and rejects bad timestamps", () => {
  const m = reportingClock("incident", "2026-11-13T10:00:00Z", { now: "2026-11-15T00:00:00Z" });
  assert.match(m[0]!.note, /^OVERDUE/);
  assert.doesNotMatch(m[2]!.note, /^OVERDUE/);
  assert.throws(() => reportingClock("incident", "yesterday"), ClockError);
});

test("dates: reporting live from 2026-09-11, full application 2027-12-11", () => {
  assert.equal(isReportingLive("2026-09-10"), false);
  assert.equal(isReportingLive("2026-09-11"), true);
  assert.equal(daysUntil("2027-12-10", "2027-12-11"), 1);
});

test("profile validation", () => {
  assert.throws(() => parseProfile("{}"), ProfileError);
  assert.throws(() => parseProfile('{"name":"x","role":"king"}'), /role/);
  assert.throws(() => parseProfile('{"name":"x","answers":{"nope":"yes"}}'), /unknown requirement/);
  assert.throws(() => parseProfile('{"name":"x","answers":{"p1-updates":"maybe"}}'), /yes, partial or no/);
});

test("assessment: readiness weighs requirements and missing answers count as no", () => {
  const none = assess(parseProfile('{"name":"x"}'), "2026-11-13");
  assert.equal(none.readiness, 0);
  const all: Record<string, string> = {};
  for (const r of REQUIREMENTS) all[r.id] = "yes";
  const full = assess(parseProfile(JSON.stringify({ name: "x", answers: all })), "2026-11-13");
  assert.equal(full.readiness, 100);
  assert.equal(full.gaps.length, 0);
});

test("assessment: exploited vulnerability in the SBOM comes first in the action list", () => {
  const a = assess(parseProfile(ex("profile-gateway.json")), "2026-11-13", parseSbom(ex("sbom-gateway.cdx.json")), parseAdvisories(ex("advisories.json")));
  assert.match(a.actions[0]!, /Article 14 clock/);
  assert.match(a.actions[0]!, /EXAMPLE-2026-0001/);
  assert.equal(a.reportingLive, true);
  assert.equal(a.route.module, "Harmonised standard, or third-party assessment otherwise");
});

test("assessment: a short support period is called out", () => {
  const a = assess(parseProfile(ex("profile-gateway.json")), "2026-11-13");
  assert.ok(a.actions.some((x) => /five years/.test(x)));
});

test("importers and distributors get their own duties", () => {
  const a = assess(parseProfile('{"name":"x","role":"importer"}'), "2026-11-13");
  assert.ok(a.duties.every((d) => d.id.startsWith("i-")));
});
