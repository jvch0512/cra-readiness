import { Assessment } from "./assess.js";
import { Milestone, hoursLeft } from "./clock.js";
import { Advisory, SbomQuality } from "./sbom.js";
import { DATES } from "./obligations.js";

const cell = (s: string): string => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");

export function sbomMarkdown(q: SbomQuality, format: string): string {
  const L = [`# SBOM quality (${format})`, "", `Quality score: **${q.score}/100** across ${q.total} components (NTIA minimum elements).`, ""];
  L.push("| Element | Coverage |", "|---|---|");
  L.push(`| Component version | ${q.withVersion}% |`, `| Supplier name | ${q.withSupplier}% |`, `| Unique identifier (purl) | ${q.withIdentifier}% |`);
  L.push(`| Licence (not an NTIA element, useful for CRA due diligence) | ${q.withLicense}% |`, `| Hash | ${q.withHash}% |`);
  L.push(`| Dependency relationships | ${q.hasRelationships ? "present" : "missing"} |`, `| Author of SBOM data | ${q.hasAuthor ? "present" : "missing"} |`, `| Timestamp | ${q.hasTimestamp ? "present" : "missing"} |`, "");
  if (q.issues.length) { L.push("## Issues", ""); for (const i of q.issues) L.push(`- ${i}`); L.push(""); }
  return L.join("\n");
}

export function assessmentMarkdown(a: Assessment): string {
  const L: string[] = [];
  L.push(`# CRA readiness: ${a.profile.name}`, "");
  L.push(`Role: **${a.profile.role}**. Product class: **${a.profile.productClass}**. Assessed on ${a.today}.`, "");
  L.push(`Readiness against Annex I: **${a.readiness}%**.`);
  L.push(a.reportingLive
    ? `Article 14 reporting has applied since ${DATES.reporting}, including to products already on the market. The remaining obligations apply from ${DATES.fullApplication} (${a.daysToFullApplication} days away).`
    : `Article 14 reporting applies from ${DATES.reporting}. The remaining obligations apply from ${DATES.fullApplication} (${a.daysToFullApplication} days away).`, "");
  if (a.actions.length) { L.push("## Do first", ""); a.actions.forEach((x, i) => L.push(`${i + 1}. ${x}`)); L.push(""); }
  L.push("## Conformity route", "", `**${a.route.module}.** ${a.route.summary}`, "");
  L.push(`## Duties as ${a.profile.role}`, "");
  for (const d of a.duties) L.push(`- ${d.text} (${d.ref})`);
  L.push("");
  L.push("## Annex I self-assessment", "", "| Requirement | Reference | Answer |", "|---|---|---|");
  for (const r of a.results) L.push(`| ${cell(r.req.text)} | ${r.req.ref} | ${r.answer} |`);
  L.push("");
  if (a.sbom) {
    L.push(sbomMarkdown(a.sbom.quality, "see above").replace("# SBOM quality (see above)", "## SBOM"));
    if (a.sbom.hits.length) {
      L.push("### Known vulnerabilities in the SBOM", "", "| Component | Advisory | Severity | Exploited | Fixed in |", "|---|---|---|---|---|");
      for (const h of a.sbom.hits) L.push(`| ${cell(h.component)} | ${h.advisory.id} | ${h.advisory.severity} | ${h.advisory.exploited ? "**yes**" : "no"} | ${h.advisory.fixedIn ?? "-"} |`);
      L.push("");
    } else L.push("No advisories matched the SBOM components.", "");
    if (a.sbom.unmatchable) L.push(`${a.sbom.unmatchable} component(s) have no package URL and could not be matched.`, "");
  }
  L.push("_Dates and thresholds are encoded from Regulation (EU) 2024/2847. This is a readiness aid, not legal advice._", "");
  return L.join("\n");
}

export function clockMarkdown(kind: string, aware: string, ms: Milestone[], now?: string): string {
  const L = [`# Article 14 clock: ${kind}`, "", `Aware at ${aware}.`, "", "| Step | Due (UTC) | Left | What to send |", "|---|---|---|---|"];
  for (const m of ms) {
    const left = m.due && now ? `${hoursLeft(m.due, now)} h` : "-";
    L.push(`| ${m.label} | ${m.due ?? "set --fix"} | ${left} | ${cell(m.note)} |`);
  }
  L.push("");
  return L.join("\n");
}

export type { Advisory };
