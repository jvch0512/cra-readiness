import { Answer, CLASS_ROUTE, DATES, REQUIREMENTS, ProductClass, ROLE_DUTIES, Requirement, Role, Route, RoleDuty, daysUntil, isReportingLive } from "./obligations.js";
import { AdvisoryMap, Hit, SbomDoc, SbomQuality, matchAdvisories, sbomQuality } from "./sbom.js";

export interface Profile {
  name: string;
  role: Role;
  productClass: ProductClass;
  supportYears: number;
  /** missing answers count as "no" */
  answers: Partial<Record<string, Answer>>;
}

export class ProfileError extends Error {}

const ROLES: Role[] = ["manufacturer", "importer", "distributor"];
const CLASSES: ProductClass[] = ["default", "important-1", "important-2", "critical"];
const ANSWERS: Answer[] = ["yes", "partial", "no"];

export function parseProfile(text: string): Profile {
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { throw new ProfileError("profile is not valid JSON"); }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new ProfileError("profile must be an object");
  const r = raw as Record<string, unknown>;
  const name = typeof r["name"] === "string" && r["name"].trim() ? r["name"].slice(0, 120) : "";
  if (!name) throw new ProfileError("name is required");
  const role = r["role"] ?? "manufacturer";
  if (!ROLES.includes(role as Role)) throw new ProfileError(`role must be one of ${ROLES.join(", ")}`);
  const cls = r["productClass"] ?? "default";
  if (!CLASSES.includes(cls as ProductClass)) throw new ProfileError(`productClass must be one of ${CLASSES.join(", ")}`);
  const sy = r["supportYears"] ?? 5;
  if (typeof sy !== "number" || !Number.isFinite(sy) || sy < 0 || sy > 50) throw new ProfileError("supportYears must be a number from 0 to 50");
  const answers: Partial<Record<string, Answer>> = {};
  const a = r["answers"];
  if (a !== undefined) {
    if (typeof a !== "object" || a === null || Array.isArray(a)) throw new ProfileError("answers must be an object");
    const known = new Set(REQUIREMENTS.map((x) => x.id));
    for (const [k, v] of Object.entries(a)) {
      if (!known.has(k)) throw new ProfileError(`unknown requirement id: ${k}`);
      if (!ANSWERS.includes(v as Answer)) throw new ProfileError(`${k} must be yes, partial or no`);
      answers[k] = v as Answer;
    }
  }
  return { name, role: role as Role, productClass: cls as ProductClass, supportYears: sy, answers };
}

export interface RequirementResult { req: Requirement; answer: Answer }

export interface Assessment {
  profile: Profile;
  today: string;
  reportingLive: boolean;
  daysToFullApplication: number;
  route: Route;
  duties: RoleDuty[];
  results: RequirementResult[];
  readiness: number;
  gaps: RequirementResult[];
  sbom: { quality: SbomQuality; hits: Hit[]; unmatchable: number } | null;
  actions: string[];
}

const POINTS: Record<Answer, number> = { yes: 1, partial: 0.5, no: 0 };

export function assess(profile: Profile, today: string, sbom?: SbomDoc, adv?: AdvisoryMap): Assessment {
  const results = REQUIREMENTS.map((req) => ({ req, answer: profile.answers[req.id] ?? "no" }));
  const max = results.reduce((s, r) => s + r.req.weight, 0);
  const got = results.reduce((s, r) => s + r.req.weight * POINTS[r.answer], 0);
  const gaps = results.filter((r) => r.answer !== "yes").sort((a, b) => b.req.weight * (1 - POINTS[b.answer]) - a.req.weight * (1 - POINTS[a.answer]) || a.req.id.localeCompare(b.req.id));
  let sb: Assessment["sbom"] = null;
  if (sbom) {
    const { hits, unmatchable } = matchAdvisories(sbom, adv ?? {});
    sb = { quality: sbomQuality(sbom), hits, unmatchable };
  }
  const actions: string[] = [];
  const exploited = sb?.hits.filter((h) => h.advisory.exploited) ?? [];
  if (exploited.length) actions.push(`Start the Article 14 clock now: ${exploited.length} actively exploited vulnerabilit${exploited.length === 1 ? "y" : "ies"} found in the SBOM (${[...new Set(exploited.map((h) => h.advisory.id))].join(", ")}). Early warning is due within 24 hours of awareness.`);
  if (profile.role === "manufacturer" && isReportingLive(today) && (profile.answers["p2-contact"] ?? "no") !== "yes") actions.push("Publish a vulnerability contact address and register for the single reporting platform: Article 14 duties already apply.");
  if (profile.role === "manufacturer" && (profile.answers["p2-cvd"] ?? "no") === "no") actions.push("Write a coordinated vulnerability disclosure policy (Annex I Part II (5)).");
  if (profile.role === "manufacturer" && profile.supportYears < 5) actions.push("Support period is under five years: document why the product is expected to be used for less (Art. 13(8)), or extend it.");
  if (sb && sb.quality.score < 80) actions.push(`Raise the SBOM quality score from ${sb.quality.score} to 80 or more: ${sb.quality.issues[0] ?? "fill the missing elements"}`);
  const covered = new Set(["p2-contact", "p2-cvd"]);
  for (const g of gaps.filter((x) => !(profile.role === "manufacturer" && covered.has(x.req.id) && actions.length > 0)).slice(0, 3)) actions.push(`Close ${g.req.ref}: ${g.req.text}.`);
  return {
    profile, today, reportingLive: isReportingLive(today), daysToFullApplication: daysUntil(today, DATES.fullApplication),
    route: CLASS_ROUTE[profile.productClass], duties: ROLE_DUTIES[profile.role], results,
    readiness: Math.round((got / max) * 100), gaps, sbom: sb, actions: actions.slice(0, 8),
  };
}
