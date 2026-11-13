import { assess, parseProfile } from "/lib/assess.js";
import { reportingClock } from "/lib/clock.js";
import { assessmentMarkdown, clockMarkdown, sbomMarkdown } from "/lib/report.js";
import { matchAdvisories, parseAdvisories, parseSbom, sbomQuality } from "/lib/sbom.js";

const $ = (id) => document.getElementById(id);
function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function table(headers, rows, classes = []) {
  const t = document.createElement("table");
  const h = document.createElement("tr");
  headers.forEach((x) => h.append(el("th", x)));
  t.append(h);
  rows.forEach((r) => { const tr = document.createElement("tr"); r.forEach((c, i) => tr.append(el("td", String(c), classes[i] ? classes[i](c) : undefined))); t.append(tr); });
  return t;
}
function cards(items) {
  const box = el("div", undefined, "cards");
  for (const [label, value, cls] of items) { const c = el("div", undefined, `card ${cls ?? ""}`); c.append(el("b", String(value)), el("span", label)); box.append(c); }
  return box;
}
function panel(title, ...kids) { const p = el("div", undefined, "panel"); p.append(el("h2", title), ...kids); return p; }
function copyButton(getMd) {
  const b = el("button", "Copy markdown");
  b.type = "button";
  b.addEventListener("click", async () => { try { await navigator.clipboard.writeText(getMd()); b.textContent = "Copied"; setTimeout(() => { b.textContent = "Copy markdown"; }, 1500); } catch { /* clipboard blocked */ } });
  return b;
}
function downloadButton(getMd, name) {
  const b = el("button", "Download .md");
  b.type = "button";
  b.addEventListener("click", () => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([getMd()], { type: "text/markdown" })); a.download = name; a.click(); URL.revokeObjectURL(a.href); });
  return b;
}
async function sample(name) { return (await fetch(`/examples/${name}`)).text(); }
function showError(box, e) { box.replaceChildren(el("p", String(e.message ?? e), "err")); }
function setupTabs() {
  document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("on", x === b));
    document.querySelectorAll(".tab").forEach((s) => { s.hidden = s.id !== `p-${b.dataset.tab}`; });
  }));
}
const cls = (map) => (v) => map[v] ?? "";


const TODAY = new Date().toISOString().slice(0, 10);

function currentSbom() {
  const t = $("sbom-text").value.trim();
  if (!t) return undefined;
  return parseSbom(t);
}
function currentAdv() {
  const t = $("adv-text").value.trim();
  return t ? parseAdvisories(t) : undefined;
}

function runSbom() {
  const out = $("sbom-out");
  out.replaceChildren();
  try {
    const doc = currentSbom();
    if (!doc) return;
    const q = sbomQuality(doc);
    const md = sbomMarkdown(q, doc.format);
    const sc = q.score >= 80 ? "ok" : q.score >= 60 ? "warn" : "bad";
    out.append(cards([["Quality score", q.score, sc], ["Components", q.total], ["With purl", q.withIdentifier + "%", q.withIdentifier === 100 ? "ok" : "warn"], ["With supplier", q.withSupplier + "%", q.withSupplier === 100 ? "ok" : "warn"]]));
    const parts = [panel("Issues", ...(q.issues.length ? q.issues.map((i) => el("p", i)) : [el("p", "No issues found.")]))];
    const adv = currentAdv();
    let extra = "";
    if (adv) {
      const { hits } = matchAdvisories(doc, adv);
      extra = `\n${hits.length} known vulnerabilities matched, ${hits.filter((h) => h.advisory.exploited).length} actively exploited.\n`;
      parts.push(panel("Known vulnerabilities", hits.length ? table(["Component", "Advisory", "Severity", "Exploited", "Fixed in"], hits.map((h) => [h.component, h.advisory.id, h.advisory.severity, h.advisory.exploited ? "yes" : "no", h.advisory.fixedIn ?? "-"]), [null, null, cls({ critical: "s-high", high: "s-high", medium: "s-medium", low: "s-low" }), cls({ yes: "s-high" })]) : el("p", "No advisories matched.")));
    }
    const row = el("div", undefined, "row");
    row.append(copyButton(() => md + extra), downloadButton(() => md + extra, "sbom-quality.md"));
    out.append(...parts, row);
  } catch (e) { showError(out, e); }
}

function runAssess() {
  const out = $("assess-out");
  out.replaceChildren();
  try {
    const t = $("prof-text").value.trim();
    if (!t) return;
    const a = assess(parseProfile(t), TODAY, currentSbom(), currentAdv());
    const md = assessmentMarkdown(a);
    out.append(cards([["Annex I readiness", a.readiness + "%", a.readiness >= 80 ? "ok" : a.readiness >= 50 ? "warn" : "bad"], ["Gaps", a.gaps.length, a.gaps.length ? "warn" : "ok"], ["Reporting live", a.reportingLive ? "yes" : "no", a.reportingLive ? "bad" : "ok"], ["Days to full application", a.daysToFullApplication]]));
    out.append(panel("Do first", ...a.actions.map((x, i) => el("p", `${i + 1}. ${x}`))));
    out.append(panel("Conformity route", el("p", a.route.module), el("p", a.route.summary, "hint")));
    out.append(panel("Annex I self-assessment", table(["Requirement", "Reference", "Answer"], a.results.map((r) => [r.req.text, r.req.ref, r.answer]), [null, null, cls({ yes: "s-low", partial: "s-medium", no: "s-high" })])));
    const row = el("div", undefined, "row");
    row.append(copyButton(() => md), downloadButton(() => md, "cra-readiness.md"));
    out.append(row);
  } catch (e) { showError(out, e); }
}

function runClock() {
  const out = $("clock-out");
  out.replaceChildren();
  const aware = $("clk-aware").value;
  if (!aware) { out.append(el("p", "Set the moment you became aware.", "hint")); return; }
  try {
    const fix = $("clk-fix").value;
    const ms = reportingClock($("clk-kind").value, aware + ":00Z", fix ? { fixAvailable: fix + ":00Z" } : {});
    const md = clockMarkdown($("clk-kind").value, aware + ":00Z", ms);
    out.append(panel("Deadlines (UTC)", table(["Step", "Due", "What to send"], ms.map((m) => [m.label, m.due ?? "set the fix date", m.note])), copyButton(() => md)));
  } catch (e) { showError(out, e); }
}

setupTabs();
$("sbom-sample").addEventListener("click", async () => { $("sbom-text").value = await sample("sbom-gateway.cdx.json"); runSbom(); });
$("adv-sample").addEventListener("click", async () => { $("adv-text").value = await sample("advisories.json"); runSbom(); });
$("prof-sample").addEventListener("click", async () => { $("prof-text").value = await sample("profile-gateway.json"); runAssess(); });
for (const id of ["sbom-text", "adv-text"]) $(id).addEventListener("input", () => { runSbom(); runAssess(); });
$("prof-text").addEventListener("input", runAssess);
for (const id of ["clk-kind", "clk-aware", "clk-fix"]) $(id).addEventListener("input", runClock);
runClock();
