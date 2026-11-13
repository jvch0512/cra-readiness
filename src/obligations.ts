/** CRA (Regulation (EU) 2024/2847) obligations encoded as data. Dates: Art. 71. Verify against the Official Journal before relying on them. */

export type Role = "manufacturer" | "importer" | "distributor";
export type ProductClass = "default" | "important-1" | "important-2" | "critical";
export type Answer = "yes" | "partial" | "no";

export const DATES = {
  entryIntoForce: "2024-12-10",
  notifiedBodies: "2026-06-11",
  reporting: "2026-09-11",
  fullApplication: "2027-12-11",
} as const;

export interface Requirement { id: string; part: "I" | "II"; ref: string; text: string; weight: number }

export const REQUIREMENTS: Requirement[] = [
  { id: "p1-no-known-vulns", part: "I", ref: "Annex I Part I (2)(a)", text: "Placed on the market without known exploitable vulnerabilities", weight: 3 },
  { id: "p1-secure-default", part: "I", ref: "Annex I Part I (2)(b)", text: "Secure by default configuration, with the ability to reset to the original state", weight: 2 },
  { id: "p1-updates", part: "I", ref: "Annex I Part I (2)(c)", text: "Security updates, automatic by default with an opt-out", weight: 3 },
  { id: "p1-access", part: "I", ref: "Annex I Part I (2)(d)", text: "Protection against unauthorised access: authentication, identity and access management", weight: 3 },
  { id: "p1-confidentiality", part: "I", ref: "Annex I Part I (2)(e)", text: "Confidentiality of data: encryption at rest and in transit", weight: 3 },
  { id: "p1-integrity", part: "I", ref: "Annex I Part I (2)(f)", text: "Integrity of data, commands, programs and configuration", weight: 2 },
  { id: "p1-minimisation", part: "I", ref: "Annex I Part I (2)(g)", text: "Data minimisation: only adequate, relevant and necessary data", weight: 1 },
  { id: "p1-availability", part: "I", ref: "Annex I Part I (2)(h)", text: "Availability of essential functions, including resilience against denial of service", weight: 2 },
  { id: "p1-side-effects", part: "I", ref: "Annex I Part I (2)(i)", text: "Minimised negative impact on other devices or networks", weight: 1 },
  { id: "p1-attack-surface", part: "I", ref: "Annex I Part I (2)(j)", text: "Limited attack surfaces, including external interfaces", weight: 2 },
  { id: "p1-mitigation", part: "I", ref: "Annex I Part I (2)(k)", text: "Exploitation mitigation mechanisms to reduce the impact of incidents", weight: 2 },
  { id: "p1-logging", part: "I", ref: "Annex I Part I (2)(l)", text: "Security logging and monitoring with an opt-out for the user", weight: 2 },
  { id: "p1-data-removal", part: "I", ref: "Annex I Part I (2)(m)", text: "Secure and easy removal of all data and settings", weight: 1 },
  { id: "p2-sbom", part: "II", ref: "Annex I Part II (1)", text: "Vulnerabilities identified and documented, including an SBOM covering at least the top-level dependencies", weight: 3 },
  { id: "p2-remediate", part: "II", ref: "Annex I Part II (2)", text: "Vulnerabilities addressed without delay, including through security updates", weight: 3 },
  { id: "p2-testing", part: "II", ref: "Annex I Part II (3)", text: "Effective and regular tests and reviews of the security of the product", weight: 2 },
  { id: "p2-disclosure", part: "II", ref: "Annex I Part II (4)", text: "Public disclosure of fixed vulnerabilities once an update is available", weight: 2 },
  { id: "p2-cvd", part: "II", ref: "Annex I Part II (5)", text: "A coordinated vulnerability disclosure policy", weight: 3 },
  { id: "p2-contact", part: "II", ref: "Annex I Part II (6)", text: "A contact address for reporting vulnerabilities", weight: 3 },
  { id: "p2-secure-distribution", part: "II", ref: "Annex I Part II (7)", text: "Secure distribution of updates", weight: 2 },
  { id: "p2-free-patches", part: "II", ref: "Annex I Part II (8)", text: "Security patches disseminated without delay and free of charge, with advisory messages", weight: 2 },
];

export interface Route { module: string; summary: string }

export const CLASS_ROUTE: Record<ProductClass, Route> = {
  default: { module: "Internal control (Module A)", summary: "Self-assessment by the manufacturer. Most products fall here." },
  "important-1": { module: "Harmonised standard, or third-party assessment otherwise", summary: "Important product class I (Annex III). Internal control is available only if harmonised standards, common specifications or a certification scheme are applied in full." },
  "important-2": { module: "Third-party assessment", summary: "Important product class II (Annex III). A notified body must assess conformity." },
  critical: { module: "European cybersecurity certification", summary: "Critical product (Annex IV). A certification scheme at least at 'substantial' assurance level is required where one is mandated by the Commission." },
};

export interface RoleDuty { id: string; text: string; ref: string }

export const ROLE_DUTIES: Record<Role, RoleDuty[]> = {
  manufacturer: [
    { id: "m-assess", ref: "Art. 13", text: "Carry out and document a cybersecurity risk assessment for the product" },
    { id: "m-techdoc", ref: "Art. 13(12), Annex VII", text: "Draw up technical documentation and keep it for at least 10 years or the support period" },
    { id: "m-support", ref: "Art. 13(8)", text: "Set a support period of at least five years unless the product is expected to be used for less" },
    { id: "m-doc", ref: "Art. 28", text: "Issue the EU declaration of conformity and affix the CE marking" },
    { id: "m-report", ref: "Art. 14", text: "Report actively exploited vulnerabilities and severe incidents through the single reporting platform" },
    { id: "m-info", ref: "Art. 13(18), Annex II", text: "Provide user information and instructions, including the security contact" },
  ],
  importer: [
    { id: "i-verify", ref: "Art. 19", text: "Verify the manufacturer did the conformity assessment, documentation and CE marking before placing on the market" },
    { id: "i-name", ref: "Art. 19(4)", text: "Put your name and contact address on the product or packaging" },
    { id: "i-inform", ref: "Art. 19(7)", text: "Inform the manufacturer and authorities about vulnerabilities in the product" },
    { id: "i-docs", ref: "Art. 19(5)", text: "Keep a copy of the declaration of conformity for 10 years" },
  ],
  distributor: [
    { id: "d-check", ref: "Art. 20", text: "Verify the CE marking, documents and manufacturer or importer details before making a product available" },
    { id: "d-stop", ref: "Art. 20(3)", text: "Do not supply a product you believe does not conform, and alert the manufacturer and authorities" },
  ],
};

export function isReportingLive(today: string): boolean { return today >= DATES.reporting; }
export function daysUntil(from: string, to: string): number { return Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / 86_400_000); }
