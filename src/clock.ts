/** Article 14 reporting clock. All times are UTC. */

export type ReportKind = "vulnerability" | "incident";

export interface Milestone { id: string; label: string; due: string | null; note: string }

const H = 3_600_000;
const D = 24 * H;
const iso = (ms: number): string => new Date(ms).toISOString().replace(".000Z", "Z");

export class ClockError extends Error {}

function parse(s: string, field: string): number {
  const ms = Date.parse(s);
  if (!Number.isFinite(ms)) throw new ClockError(`${field} is not a valid ISO timestamp: ${s}`);
  return ms;
}

/**
 * Early warning within 24 hours and notification within 72 hours of becoming aware (Art. 14(2)(a), (b)).
 * Final report: for a vulnerability, 14 days after a corrective or mitigating measure is available; for an incident, one month after the notification.
 */
export function reportingClock(kind: ReportKind, aware: string, opts: { fixAvailable?: string; now?: string } = {}): Milestone[] {
  const t0 = parse(aware, "aware");
  const out: Milestone[] = [
    { id: "early", label: "Early warning", due: iso(t0 + 24 * H), note: "Via the single reporting platform to the CSIRT coordinator and ENISA. Indicate whether malicious action is suspected and the Member States affected." },
    { id: "notification", label: "Vulnerability or incident notification", due: iso(t0 + 72 * H), note: "General information, nature of the exploit, corrective measures taken and mitigations users can apply." },
  ];
  if (kind === "vulnerability") {
    if (opts.fixAvailable) {
      out.push({ id: "final", label: "Final report", due: iso(parse(opts.fixAvailable, "fix") + 14 * D), note: "Within 14 days after a corrective or mitigating measure is available: severity, impact, exploit details, and the security update." });
    } else {
      out.push({ id: "final", label: "Final report", due: null, note: "Due 14 days after a corrective or mitigating measure is available. Pass --fix once you have a date." });
    }
  } else {
    const notif = t0 + 72 * H;
    out.push({ id: "final", label: "Final report", due: iso(notif + 30 * D), note: "Within one month after the incident notification (30 days used here as a safe proxy): description, severity, root cause, and the mitigations applied." });
  }
  if (opts.now) {
    const now = parse(opts.now, "now");
    for (const m of out) if (m.due !== null) m.note = `${Date.parse(m.due) < now ? "OVERDUE. " : ""}${m.note}`;
  }
  return out;
}

export function hoursLeft(due: string, now: string): number { return Math.round(((Date.parse(due) - Date.parse(now)) / H) * 10) / 10; }
