/** SBOM parsing and quality checks. Accepts CycloneDX JSON and SPDX 2.x JSON. Pure functions, no I/O. */

export interface Component {
  name: string;
  version: string;
  purl: string;
  supplier: string;
  licenses: string[];
  hash: boolean;
}

export interface SbomDoc {
  format: "cyclonedx" | "spdx";
  specVersion: string;
  timestamp: string;
  author: string;
  components: Component[];
  /** number of dependency relationships recorded */
  relationships: number;
}

export class SbomError extends Error {}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string => (typeof v === "string" ? v : "");

function cdxLicenses(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const x of v) {
    if (!isObj(x)) continue;
    if (typeof x["expression"] === "string") out.push(x["expression"]);
    const lic = x["license"];
    if (isObj(lic)) { const id = str(lic["id"]) || str(lic["name"]); if (id) out.push(id); }
  }
  return out;
}

function parseCdx(raw: Record<string, unknown>): SbomDoc {
  const meta = isObj(raw["metadata"]) ? raw["metadata"] : {};
  let author = "";
  if (Array.isArray(meta["authors"]) && isObj(meta["authors"][0])) author = str(meta["authors"][0]["name"]);
  if (!author && isObj(meta["manufacture"])) author = str(meta["manufacture"]["name"]);
  if (!author && isObj(meta["supplier"])) author = str(meta["supplier"]["name"]);
  const list = Array.isArray(raw["components"]) ? raw["components"] : [];
  const components: Component[] = [];
  for (const c of list) {
    if (!isObj(c)) continue;
    const sup = isObj(c["supplier"]) ? str(c["supplier"]["name"]) : str(c["publisher"]) || str(c["author"]);
    components.push({
      name: str(c["name"]),
      version: str(c["version"]),
      purl: str(c["purl"]),
      supplier: sup,
      licenses: cdxLicenses(c["licenses"]),
      hash: Array.isArray(c["hashes"]) && c["hashes"].length > 0,
    });
  }
  const deps = Array.isArray(raw["dependencies"]) ? raw["dependencies"] : [];
  let relationships = 0;
  for (const d of deps) if (isObj(d) && Array.isArray(d["dependsOn"])) relationships += d["dependsOn"].length;
  return { format: "cyclonedx", specVersion: str(raw["specVersion"]), timestamp: str(meta["timestamp"]), author, components, relationships };
}

function parseSpdx(raw: Record<string, unknown>): SbomDoc {
  const info = isObj(raw["creationInfo"]) ? raw["creationInfo"] : {};
  const creators = Array.isArray(info["creators"]) ? info["creators"].map(str).filter(Boolean) : [];
  const pk = Array.isArray(raw["packages"]) ? raw["packages"] : [];
  const components: Component[] = [];
  for (const p of pk) {
    if (!isObj(p)) continue;
    const refs = Array.isArray(p["externalRefs"]) ? p["externalRefs"] : [];
    let purl = "";
    for (const r of refs) if (isObj(r) && str(r["referenceType"]) === "purl") purl = str(r["referenceLocator"]);
    const lic = str(p["licenseConcluded"]) || str(p["licenseDeclared"]);
    const sup = str(p["supplier"]).replace(/^(Organization|Person):\s*/, "");
    components.push({
      name: str(p["name"]),
      version: str(p["versionInfo"]),
      purl,
      supplier: sup === "NOASSERTION" ? "" : sup,
      licenses: lic && lic !== "NOASSERTION" && lic !== "NONE" ? [lic] : [],
      hash: Array.isArray(p["checksums"]) && p["checksums"].length > 0,
    });
  }
  const rel = Array.isArray(raw["relationships"]) ? raw["relationships"].filter((r) => isObj(r) && /DEPEND/i.test(str(r["relationshipType"]))).length : 0;
  return { format: "spdx", specVersion: str(raw["spdxVersion"]), timestamp: str(info["created"]), author: creators.join(", "), components, relationships: rel };
}

export function parseSbom(text: string): SbomDoc {
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { throw new SbomError("not valid JSON"); }
  if (!isObj(raw)) throw new SbomError("expected a JSON object");
  if (raw["bomFormat"] === "CycloneDX") return parseCdx(raw);
  if (typeof raw["spdxVersion"] === "string") return parseSpdx(raw);
  throw new SbomError("unrecognised format: expected CycloneDX or SPDX JSON");
}

export interface SbomQuality {
  total: number;
  /** share of components (0..100) that carry each NTIA minimum element */
  withVersion: number;
  withSupplier: number;
  withIdentifier: number;
  withLicense: number;
  withHash: number;
  hasTimestamp: boolean;
  hasAuthor: boolean;
  hasRelationships: boolean;
  duplicates: string[];
  score: number;
  issues: string[];
}

const pct = (n: number, d: number): number => (d === 0 ? 0 : Math.round((n / d) * 100));

export function sbomQuality(doc: SbomDoc): SbomQuality {
  const c = doc.components;
  const total = c.length;
  const withVersion = pct(c.filter((x) => x.version !== "").length, total);
  const withSupplier = pct(c.filter((x) => x.supplier !== "").length, total);
  const withIdentifier = pct(c.filter((x) => x.purl !== "").length, total);
  const withLicense = pct(c.filter((x) => x.licenses.length > 0).length, total);
  const withHash = pct(c.filter((x) => x.hash).length, total);
  const seen = new Map<string, number>();
  for (const x of c) { const k = `${x.name}@${x.version}`; seen.set(k, (seen.get(k) ?? 0) + 1); }
  const duplicates = [...seen].filter(([, n]) => n > 1).map(([k]) => k).sort();
  const hasTimestamp = doc.timestamp !== "";
  const hasAuthor = doc.author !== "";
  const hasRelationships = doc.relationships > 0;
  const issues: string[] = [];
  if (total === 0) issues.push("The SBOM lists no components.");
  if (withVersion < 100 && total > 0) issues.push(`Only ${withVersion}% of components carry a version.`);
  if (withSupplier < 100 && total > 0) issues.push(`Only ${withSupplier}% of components name a supplier.`);
  if (withIdentifier < 100 && total > 0) issues.push(`Only ${withIdentifier}% of components have a package URL, so vulnerability matching will miss them.`);
  if (withLicense < 100 && total > 0) issues.push(`Only ${withLicense}% of components declare a licence.`);
  if (!hasTimestamp) issues.push("No creation timestamp.");
  if (!hasAuthor) issues.push("No author of the SBOM data.");
  if (!hasRelationships) issues.push("No dependency relationships recorded; CRA Annex I Part II (1) asks for at least the top-level dependencies.");
  if (duplicates.length) issues.push(`Duplicate entries: ${duplicates.join(", ")}.`);
  // NTIA minimum elements: supplier, name, version, identifier, relationship, author, timestamp
  const parts = [withSupplier, withVersion, withIdentifier, hasRelationships ? 100 : 0, hasAuthor ? 100 : 0, hasTimestamp ? 100 : 0];
  const score = total === 0 ? 0 : Math.round(parts.reduce((a, b) => a + b, 0) / parts.length);
  return { total, withVersion, withSupplier, withIdentifier, withLicense, withHash, hasTimestamp, hasAuthor, hasRelationships, duplicates, score, issues };
}

export interface Advisory { id: string; severity: "low" | "medium" | "high" | "critical"; exploited: boolean; fixedIn?: string; summary?: string }
export type AdvisoryMap = Record<string, Advisory[]>;

export class AdvisoryError extends Error {}

/** Advisories are supplied by the user, keyed by package URL (bring your own feed: OSV export, KEV join, internal tracker). */
export function parseAdvisories(text: string): AdvisoryMap {
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { throw new AdvisoryError("advisories file is not valid JSON"); }
  if (!isObj(raw)) throw new AdvisoryError("advisories must be an object keyed by package URL");
  const out: AdvisoryMap = {};
  for (const [purl, list] of Object.entries(raw)) {
    if (!Array.isArray(list)) throw new AdvisoryError(`advisories for ${purl} must be a list`);
    out[purl] = list.map((a, i) => {
      if (!isObj(a) || typeof a["id"] !== "string") throw new AdvisoryError(`${purl}[${i}] needs an id`);
      const sev = str(a["severity"]);
      if (!["low", "medium", "high", "critical"].includes(sev)) throw new AdvisoryError(`${purl}[${i}] severity must be low, medium, high or critical`);
      const adv: Advisory = { id: a["id"], severity: sev as Advisory["severity"], exploited: a["exploited"] === true };
      if (typeof a["fixedIn"] === "string") adv.fixedIn = a["fixedIn"];
      if (typeof a["summary"] === "string") adv.summary = a["summary"];
      return adv;
    });
  }
  return out;
}

export interface Hit { component: string; purl: string; advisory: Advisory }

export function matchAdvisories(doc: SbomDoc, adv: AdvisoryMap): { hits: Hit[]; unmatchable: number } {
  const hits: Hit[] = [];
  let unmatchable = 0;
  for (const c of doc.components) {
    if (!c.purl) { unmatchable++; continue; }
    for (const a of adv[c.purl] ?? []) hits.push({ component: `${c.name}@${c.version}`, purl: c.purl, advisory: a });
  }
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  hits.sort((a, b) => Number(b.advisory.exploited) - Number(a.advisory.exploited) || order[a.advisory.severity] - order[b.advisory.severity] || a.advisory.id.localeCompare(b.advisory.id));
  return { hits, unmatchable };
}
