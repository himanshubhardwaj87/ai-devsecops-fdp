/* Builds AI-Driven-DevSecOps.pptx (16:9) with speaker notes.
 *
 *   node slides/build_pptx.js [folder holding the slide .html files] [path to apply_theme.js]
 *   (defaults to slides/web-deck/slides, a copy of the web deck this file was built from)
 *
 * Slide text lives in this file. Speaker notes are read from the <aside> of each
 * source slide so they stay identical to the web deck.
 */
const fs = require("fs");
const path = require("path");
const pptxgen = require("pptxgenjs");

const NOTES_DIR = process.argv[2] || path.join(__dirname, "web-deck", "slides");
const APPLY_THEME = process.argv[3];
const OUT = path.join(__dirname, "AI-Driven-DevSecOps.pptx");

const THEME = {
  name: "DevSecOps FDP",
  headFontFace: "Arial",
  bodyFontFace: "Arial",
  colors: {
    dk1: "0F1B2D", lt1: "FFFFFF", dk2: "44505F", lt2: "F5F3EE",
    accent1: "166B62", accent2: "E9A23B", accent3: "B3261E", accent4: "1B6E3C",
    accent5: "5B6676", accent6: "C5D0DC", hlink: "166B62", folHlink: "5B6676",
  },
};
const HEX = { ink: "0F1B2D", paper: "F5F3EE", line: "D9D5CC", white: "FFFFFF", muted: "44505F",
  amber: "E9A23B", light: "C5D0DC", bad: "B3261E", good: "1B6E3C", warn: "8A5A00", panel: "1A2A42", panelLine: "2E4160" };
const MONO = "Courier New";

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.333 x 7.5 in
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
pres.title = "AI-Driven DevSecOps";
pres.author = "Himanshu Bhardwaj";
// Plain hex colours, so the file looks right without any post-processing step.
const C = { text1: THEME.colors.dk1, text2: THEME.colors.dk2, background1: THEME.colors.lt1, background2: THEME.colors.lt2,
  accent1: THEME.colors.accent1, accent2: THEME.colors.accent2, accent3: THEME.colors.accent3, accent4: THEME.colors.accent4,
  accent5: THEME.colors.accent5, accent6: THEME.colors.accent6 };

const M = 0.89, W = 13.333 - 2 * M, TOP = 2.25, FOOT = 6.92;
const FOOTER = "AI-Driven DevSecOps · ATAL FDP 2026";

function layout(name, bg, eyebrowColor, titleColor, footColor) {
  pres.defineSlideMaster({
    title: name,
    background: { color: bg },
    objects: [
      { placeholder: { options: { name: "eyebrow", type: "body", x: M, y: 0.82, w: W, h: 0.3, margin: 0,
          fontFace: MONO, fontSize: 12, charSpacing: 1.5, color: eyebrowColor, valign: "top" }, text: "" } },
      { placeholder: { options: { name: "title", type: "title", x: M, y: 1.18, w: W, h: 0.75, margin: 0,
          fontSize: 32, bold: true, color: titleColor, valign: "top", align: "left" }, text: "" } },
      { text: { text: FOOTER, options: { x: M, y: FOOT, w: 5, h: 0.25, margin: 0, fontSize: 10, color: footColor } } },
    ],
  });
}
layout("Content light", HEX.paper, C.accent1, C.text1, C.accent5);
layout("Content dark", HEX.ink, C.accent2, C.background2, C.accent6);
pres.defineSlideMaster({ title: "Statement dark", background: { color: HEX.ink } });
pres.defineSlideMaster({ title: "Statement amber", background: { color: HEX.amber } });

// ---------------------------------------------------------------- helpers
function notesFor(id) {
  const html = fs.readFileSync(path.join(NOTES_DIR, id + ".html"), "utf8");
  const match = html.match(/<aside>([\s\S]*?)<\/aside>/);
  if (!match) throw new Error("no speaker notes found for slide " + id);
  return match[1].replace(/&amp;/g, "&").replace(/&#160;/g, " ").replace(/&lt;/g, "<").replace(/&gt;/g, ">").trim();
}
let section = "";
function startSection(title) { section = title; pres.addSection({ title }); }
function slideOn(masterName, id) {
  const s = pres.addSlide({ masterName, sectionTitle: section });
  s.addNotes(notesFor(id));
  return s;
}
function content(id, eyebrow, title, dark) {
  const s = slideOn(dark ? "Content dark" : "Content light", id);
  s.addText(eyebrow.toUpperCase(), { placeholder: "eyebrow" });
  s.addText(title, { placeholder: "title" });
  return s;
}
function T(s, text, x, y, w, h, o) {
  s.addText(text, Object.assign({ x, y, w, h, margin: 0, isTextBox: true, valign: "top", fontSize: 16, color: C.text2 }, o || {}));
}
function card(s, x, y, w, h, dark) {
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.1,
    fill: { color: dark ? C.text1 : C.background1 }, line: { color: dark ? HEX.ink : HEX.line, width: 0.75 } });
}
function arrow(s, x, y, w) {
  s.addShape(pres.ShapeType.line, { x, y, w, h: 0, line: { color: HEX.ink, width: 1.5, endArrowType: "triangle" } });
}
function cols(n, gap, x0, w0) {
  const x = x0 === undefined ? M : x0, total = w0 === undefined ? W : w0;
  const w = (total - gap * (n - 1)) / n;
  return { w, x: Array.from({ length: n }, (_, i) => x + i * (w + gap)) };
}
function source(s, text) {
  T(s, text, M + 5, FOOT, W - 5, 0.25, { fontSize: 10, color: C.accent5, align: "right" });
}
function closer(s, bold, rest, y) {
  T(s, [{ text: bold + " ", options: { bold: true, color: C.text1 } }, { text: rest }], M, y, W, 0.7, { fontSize: 16 });
}
function table(s, header, rows, colW, y, opts) {
  const o = opts || {};
  const head = header.map((t) => ({ text: t, options: { bold: true, color: HEX.paper, fill: { color: HEX.ink } } }));
  const body = rows.map((r) => r.map((cell, i) => {
    const c = typeof cell === "string" ? { text: cell } : cell;
    return { text: c.text, options: Object.assign({ color: i === 0 ? HEX.ink : HEX.muted, bold: i === 0,
      fill: { color: c.fill || HEX.white } }, c.color ? { color: c.color, bold: true } : {}) };
  }));
  s.addTable([head].concat(body), { x: M, y, w: W, colW, fontSize: o.fontSize || 15, valign: "middle",
    rowH: o.rowH || 0.52, margin: [0.06, 0.16, 0.06, 0.16], border: { type: "solid", pt: 0.75, color: HEX.line } });
}
// A titled card: small label, heading, body text.
function infoCard(s, x, y, w, h, label, heading, body, dark, o) {
  const opt = o || {};
  card(s, x, y, w, h, dark);
  let cy = y + 0.22;
  if (label) { T(s, label, x + 0.25, cy, w - 0.5, 0.25, { fontFace: MONO, fontSize: 12, color: dark ? C.accent2 : C.accent1 }); cy += 0.32; }
  T(s, heading, x + 0.25, cy, w - 0.5, opt.headH || 0.4, { fontSize: opt.headSize || 20, bold: true, color: dark ? C.background2 : C.text1 });
  cy += (opt.headH || 0.4) + 0.08;
  T(s, body, x + 0.25, cy, w - 0.5, y + h - cy - 0.15, { fontSize: opt.bodySize || 14, color: dark ? C.accent6 : C.text2 });
}

// ================================================================ slides
startSection("Opening");
{
  const s = slideOn("Statement dark", "cover");
  T(s, "AICTE ATAL FACULTY DEVELOPMENT PROGRAMME · 14–19 DECEMBER 2026", M, 0.9, W, 0.3, { fontFace: MONO, fontSize: 12, charSpacing: 1.5, color: C.accent2 });
  T(s, "AI-Driven DevSecOps", M, 2.3, W, 1.1, { fontSize: 60, bold: true, color: C.background2 });
  T(s, "Intelligent threat detection, automated security and continuous compliance", M, 3.6, 9.8, 0.9, { fontSize: 22, color: C.accent6 });
  T(s, "Himanshu Bhardwaj", M, 5.75, 5, 0.35, { fontSize: 16, bold: true, color: C.background2 });
  T(s, "Sr. DevOps Architect, Provar", M, 6.12, 5, 0.3, { fontSize: 14, color: C.accent6 });
  T(s, "Artificial Intelligence for Cyber Security:\nEmerging Threats and Future Trends\nSchool of Computer Science and Engineering, IILM University, Gurugram",
    M + 5.2, 5.65, W - 5.2, 0.8, { fontSize: 12, color: C.accent6, align: "right" });
}
{
  const s = slideOn("Statement dark", "why");
  T(s, "THE PROBLEM", M, 1.5, W, 0.3, { fontFace: MONO, fontSize: 12, charSpacing: 1.5, color: C.accent2 });
  T(s, [{ text: "Code ships every day.", options: { color: C.background2, breakLine: true } },
        { text: "Security reviews do not.", options: { color: C.accent2 } }], M, 2.1, W, 2.2, { fontSize: 54, bold: true });
  T(s, "Attackers already automate. A defence that waits for a human to read every alert loses on speed alone.", M, 4.7, 9.8, 0.9, { fontSize: 22, color: C.accent6 });
}
{
  const s = content("agenda", "Session plan · about 85 minutes", "Six parts, one running example");
  const items = [["10 min", "Foundations", "DevSecOps, its gaps, and where AI helps"],
    ["15 min", "Intelligent threat detection", "Learning normal behaviour from logs"],
    ["20 min", "Automated security", "Scanners, and an LLM that triages them"],
    ["10 min", "Continuous compliance", "Policy as code, evidence on every build"],
    ["20 min", "Live demo", "Blocked release, fix, green release"],
    ["10 min", "Classroom and Q&A", "Labs, research directions, questions"]];
  const g = cols(3, 0.25);
  items.forEach((it, i) => infoCard(s, g.x[i % 3], TOP + Math.floor(i / 3) * 2.2, g.w, 1.95, it[0], it[1], it[2], i === 4, { headSize: 17 }));
}

startSection("Foundations");
{
  const s = content("shift-left", "Foundations", "Security at every stage of delivery");
  const stages = [["Plan", "Threat modelling"], ["Code", "Secret scan, SAST"], ["Build", "Dependency audit, SBOM"], ["Test", "Dynamic testing"],
    ["Release", "Policy gate"], ["Deploy", "Config and image checks"], ["Operate", "Runtime protection"], ["Monitor", "Anomaly detection"]];
  const g = cols(8, 0.12);
  stages.forEach((st, i) => {
    card(s, g.x[i], TOP, g.w, 1.75, false);
    s.addShape(pres.ShapeType.roundRect, { x: g.x[i], y: TOP, w: g.w, h: 0.6, rectRadius: 0.1, fill: { color: C.text1 }, line: { color: HEX.ink, width: 0.75 } });
    T(s, st[0], g.x[i] + 0.12, TOP + 0.14, g.w - 0.24, 0.35, { fontSize: 15, bold: true, color: C.background2 });
    T(s, st[1], g.x[i] + 0.12, TOP + 0.78, g.w - 0.24, 0.9, { fontSize: 12 });
  });
  const h = cols(2, 0.5);
  T(s, [{ text: "Shift left. ", options: { bold: true, color: C.text1 } }, { text: "Find the flaw while the developer still has the file open." }], h.x[0], 4.5, h.w, 1.3, { fontSize: 22 });
  T(s, [{ text: "Shield right. ", options: { bold: true, color: C.text1 } }, { text: "Keep watching after release; some attacks only show in live traffic." }], h.x[1], 4.5, h.w, 1.3, { fontSize: 22 });
}
{
  const s = content("gaps", "Foundations", "Where automated pipelines still struggle");
  const items = [["Alert fatigue", "Scanners report everything they match. People stop reading long lists."],
    ["Severity without context", "A tool rates the weakness class, not whether it is reachable in your code."],
    ["Signatures miss the new", "A detection rule describes an attack someone has already seen."],
    ["Audits are snapshots", "Compliance is checked once a year. The system changes every day."]];
  const g = cols(2, 0.25);
  items.forEach((it, i) => infoCard(s, g.x[i % 2], TOP + Math.floor(i / 2) * 2.05, g.w, 1.8, "", it[0], it[1], false, { headSize: 22, headH: 0.45, bodySize: 16 }));
}
{
  const s = content("ai-roles", "Foundations", "Three jobs for AI in the pipeline");
  const items = [["Intelligent threat detection", "Detect", "Machine learning models what normal traffic looks like and flags what does not fit."],
    ["Automated security", "Decide", "A language model reads each finding in its code context, ranks it and drafts the fix."],
    ["Continuous compliance", "Prove", "Every build evaluates its controls and leaves the evidence behind."]];
  const g = cols(3, 0.25);
  items.forEach((it, i) => infoCard(s, g.x[i], TOP, g.w, 3.1, it[0], it[1], it[2], false, { headSize: 36, headH: 0.75, bodySize: 16 }));
  T(s, "AI advises. Policy decides. People stay accountable.", M, 5.75, W, 0.4, { fontSize: 18, bold: true, color: C.text1 });
}

startSection("Intelligent threat detection");
{
  const s = content("detect-compare", "Part 1 · Intelligent threat detection", "Two ways to spot an attack");
  table(s, ["", "Signature-based", "Behaviour-based"], [
    ["It knows", "Patterns of known attacks", "What normal looks like"],
    ["It catches", "Known attacks, precisely", "Unusual behaviour, including new attacks"],
    ["It misses", "Anything without a rule", "Attacks that look like normal use"],
    ["Main cost", "Writing and updating rules", "False alarms to investigate"]], [2.3, 4.62, 4.63], TOP, { fontSize: 17, rowH: 0.68 });
  T(s, "Use both: signatures for precision, behaviour for coverage.", M, 6.0, W, 0.4, { fontSize: 18, bold: true, color: C.text1 });
}
{
  const s = content("iforest", "Part 1 · Intelligent threat detection", "Isolation Forest: odd points are easy to cut off");
  const pts = ["Split the data with random cuts, many times over.", "A point unlike the rest ends up alone after very few cuts.",
    "Few cuts means a high anomaly score. No labels and no attack examples are needed."];
  pts.forEach((p, i) => {
    T(s, String(i + 1), M, TOP + 0.1 + i * 1.05, 0.4, 0.4, { fontFace: MONO, fontSize: 18, bold: true, color: C.accent1 });
    T(s, p, M + 0.5, TOP + 0.1 + i * 1.05, 5.4, 0.9, { fontSize: 16 });
  });
  const cx = 7.35, cy = TOP, cw = 5.09, ch = 3.45, k = 4.6 / 640, ox = cx + 0.25, oy = cy + 0.2;
  card(s, cx, cy, cw, ch, false);
  const ln = (x1, y1, x2, y2, color, width) => s.addShape(pres.ShapeType.line, { x: ox + x1 * k, y: oy + y1 * k, w: (x2 - x1) * k, h: (y2 - y1) * k, line: { color, width } });
  [[150, 130, 150, 340], [230, 130, 230, 340], [310, 130, 310, 340], [60, 200, 400, 200], [60, 270, 400, 270]].forEach((l) => ln(l[0], l[1], l[2], l[3], "B9C2CC", 1));
  ln(430, 10, 430, 350, HEX.amber, 2.5); ln(430, 130, 630, 130, HEX.amber, 2.5);
  [[95, 160], [125, 235], [110, 300], [175, 170], [190, 230], [170, 310], [205, 290], [255, 155], [270, 225], [250, 300], [290, 250], [335, 170],
   [350, 240], [330, 305], [375, 290], [215, 185], [140, 180], [295, 185], [365, 215], [235, 255]].forEach((p) =>
    s.addShape(pres.ShapeType.ellipse, { x: ox + (p[0] - 9) * k, y: oy + (p[1] - 9) * k, w: 18 * k, h: 18 * k, fill: { color: C.accent1 }, line: { color: "166B62", width: 0.25 } }));
  s.addShape(pres.ShapeType.ellipse, { x: ox + (540 - 16) * k, y: oy + (65 - 16) * k, w: 32 * k, h: 32 * k, fill: { color: C.accent2 }, line: { color: HEX.ink, width: 1.5 } });
  T(s, "Amber point: alone after 2 cuts. Green points: still together after 5.", cx + 0.25, cy + ch - 0.6, cw - 0.5, 0.5, { fontSize: 12 });
  T(s, "Features per client: requests · error rate · distinct paths · failed logins · response size · night-time share", M, 6.0, W, 0.5, { fontFace: MONO, fontSize: 12 });
}
{
  const s = content("detect-result", "Part 1 · Intelligent threat detection", "What the model flags in our logs");
  table(s, ["Client", "Score", "What it really was", "Why it stands out"], [
    ["203.0.113.7", "0.85", "Credential stuffing", "393 failed logins, all at night"],
    ["198.51.100.23", "0.82", "Injection probing", "180 distinct paths; typical is 6"],
    ["192.0.2.99", "0.81", "Data exfiltration", "9 MB per response; typical is 18 KB"],
    [{ text: "10.0.0.104", fill: "FBF1DD" }, { text: "0.59", fill: "FBF1DD" }, { text: "Normal client", fill: "FBF1DD" }, { text: "False alarm: few paths, one failed login", fill: "FBF1DD" }]],
    [2.55, 1.4, 3.0, 4.6], TOP, { fontSize: 17, rowH: 0.68 });
  closer(s, "3 of 3 injected attackers caught, 1 false alarm among 123 clients.", "The logs are synthetic, so the truth is known and the model can be scored.", 5.95);
  source(s, "Source: demo run, 3,264 generated log lines, seed 42");
}

startSection("Automated security");
{
  const s = content("aws-pipeline", "Part 2 · Automated security", "The release pipeline, running in AWS");
  const st = [["Amazon S3", "Source", "Release candidate uploaded"], ["CodeBuild", "Security gate", "Scan, AI triage, policy. Fails the release if blocked"],
    ["Amazon ECR", "Staging", "Image built and tagged staging"], ["A person", "Approval", "The pipeline stops and waits"], ["Amazon ECR", "Production", "Same image, tagged prod"]];
  const g = cols(5, 0.4);
  st.forEach((x, i) => { infoCard(s, g.x[i], TOP, g.w, 2.55, x[0], x[1], x[2], i === 3, { headSize: 17, headH: 0.62 }); if (i < 4) arrow(s, g.x[i] + g.w + 0.06, TOP + 1.27, 0.28); });
  const h = cols(2, 0.5);
  T(s, [{ text: "Vulnerable app: ", options: { bold: true, color: C.accent3 } }, { text: "blocked at the security gate. Nothing was built." }], h.x[0], 5.25, h.w, 0.9, { fontSize: 18 });
  T(s, [{ text: "Fixed app: ", options: { bold: true, color: C.accent4 } }, { text: "passed, built for staging, then waited for a person." }], h.x[1], 5.25, h.w, 0.9, { fontSize: 18 });
  source(s, "Source: AWS CodePipeline run, us-east-1, 17 November 2026");
}
{
  const s = content("pipeline", "Part 2 · Automated security", "Inside the security gate: six stages");
  const st = [["1", "Scan", "Secrets, code, packages, config"], ["2", "Triage", "AI ranks findings, drafts fixes"], ["3", "Detect", "ML flags odd clients in logs"],
    ["4", "Comply", "Controls checked from evidence"], ["5", "Gate", "Policy file says pass or block"], ["6", "Report", "One dashboard per build"]];
  const g = cols(6, 0.36);
  st.forEach((x, i) => { infoCard(s, g.x[i], TOP, g.w, 1.95, x[0], x[1], x[2], i === 4, { headSize: 18, bodySize: 13 }); if (i < 5) arrow(s, g.x[i] + g.w + 0.05, TOP + 0.97, 0.26); });
  card(s, M, 4.65, W, 1.35, true);
  T(s, "python -m pipeline.run --target app --ai bedrock --sca inspector", M + 0.3, 4.85, W - 0.6, 0.4, { fontFace: MONO, fontSize: 16, color: C.background2 });
  T(s, "Exit code 0 lets the release continue. Exit code 1 blocks it. The same command runs on a laptop and in AWS CodeBuild.", M + 0.3, 5.35, W - 0.6, 0.5, { fontSize: 13, color: C.accent6 });
}
{
  const s = content("scanners", "Part 2 · Automated security", "Four scanners, one common format");
  table(s, ["Scan type", "Tool in the demo", "What it finds"], [
    ["Secrets", "Regex rules", "Keys and passwords committed to the repository"],
    ["SAST", "Bandit", "Dangerous patterns in the Python source"],
    ["SCA", "Amazon Inspector", "Dependencies with published vulnerabilities"],
    ["IaC", "Policy checks", "Unsafe Dockerfile and Kubernetes settings"]], [2.75, 2.8, 6.0], TOP, { fontSize: 17, rowH: 0.68 });
  closer(s, "Every result becomes the same record:", "id, rule, severity, file, line and CWE. Later stages never need to know which tool spoke.", 5.95);
}
{
  const s = content("context", "Part 2 · Automated security", "One finding, read two ways");
  card(s, M, TOP, W, 1.25, true);
  T(s, [{ text: "# app/app.py, the /login route", options: { color: C.accent6, breakLine: true } },
        { text: "query = f\"SELECT id FROM users WHERE name = '", options: { color: C.background2 } }, { text: "{username}", options: { color: C.accent2 } },
        { text: "' AND pw = '{digest}'\"", options: { color: C.background2, breakLine: true } },
        { text: "row = get_db().execute(query).fetchone()", options: { color: C.background2 } }], M + 0.3, TOP + 0.18, W - 0.6, 0.95, { fontFace: MONO, fontSize: 13 });
  const g = cols(2, 0.25);
  [["Scanner severity (Bandit B608)", "Medium", HEX.warn, "It sees a query built from a string. It does not know where the string comes from."],
   ["Triage priority, in context", "P0: blocks release", HEX.bad, "The string is a login form field on a public route. No account is needed to exploit it."]].forEach((x, i) => {
    card(s, g.x[i], 3.75, g.w, 2.6, false);
    T(s, x[0], g.x[i] + 0.3, 3.95, g.w - 0.6, 0.3, { fontFace: MONO, fontSize: 12 });
    T(s, x[1], g.x[i] + 0.3, 4.3, g.w - 0.6, 0.7, { fontSize: 32, bold: true, color: x[2] });
    T(s, x[3], g.x[i] + 0.3, 5.15, g.w - 0.6, 1.0, { fontSize: 16 });
  });
}
{
  const s = content("triage-design", "Part 2 · Automated security", "How the AI triage stage is built");
  const st = [["In", "Each finding plus the lines of code around it"], ["Claude on Amazon Bedrock", "Asked for priority, exploitability and a concrete fix"],
    ["Out", "One typed record per finding, checked against a schema"]];
  const g = cols(3, 0.45);
  st.forEach((x, i) => {
    card(s, g.x[i], TOP, g.w, 1.5, i === 1);
    T(s, x[0], g.x[i] + 0.25, TOP + 0.2, g.w - 0.5, 0.3, { fontFace: MONO, fontSize: 12, color: i === 1 ? C.accent2 : C.accent1 });
    T(s, x[1], g.x[i] + 0.25, TOP + 0.55, g.w - 0.5, 0.85, { fontSize: 16, color: i === 1 ? C.background2 : C.text1 });
    if (i < 2) arrow(s, g.x[i] + g.w + 0.07, TOP + 0.75, 0.31);
  });
  const rails = [["Secrets are masked", "before anything leaves the machine."], ["Scanner text is data,", "never instructions to the model."],
    ["Output is validated.", "Unknown finding ids are dropped."], ["A rule table takes over", "if the model is unavailable, and says so."]];
  const h = cols(2, 0.5);
  rails.forEach((r, i) => {
    const x = h.x[i % 2], y = 4.25 + Math.floor(i / 2) * 1.0;
    s.addShape(pres.ShapeType.ellipse, { x, y: y + 0.02, w: 0.42, h: 0.42, fill: { color: C.accent1 }, line: { color: "166B62", width: 0.25 } });
    T(s, String(i + 1), x, y + 0.02, 0.42, 0.42, { fontSize: 14, bold: true, color: C.background1, align: "center", valign: "middle" });
    T(s, [{ text: r[0] + " ", options: { bold: true, color: C.text1 } }, { text: r[1] }], x + 0.6, y, h.w - 0.6, 0.8, { fontSize: 16 });
  });
}
{
  const s = content("ai-risks", "Part 2 · Automated security", "The model is also an attack surface");
  table(s, ["Risk", "What can go wrong", "What the pipeline does"], [
    ["Prompt injection", "Text in code or logs steers the model", "Treats inputs as data; validates output"],
    ["Wrong answers", "A confident fix that does not work", "Schema check; a person reviews the fix"],
    ["Data leakage", "Source and secrets go to a third party", "Masks secrets; model runs in our AWS account"],
    ["Over-reliance", "Nobody reads the findings any more", "Policy decides; AI output is labelled"]], [2.55, 4.4, 4.6], TOP, { fontSize: 17, rowH: 0.68 });
  closer(s, "Treat the model like any other untrusted component:", "check what goes in, check what comes out, and plan for it to fail.", 5.95);
}

startSection("Continuous compliance");
{
  const s = content("policy", "Part 3 · Continuous compliance", "The release rule is a file in the repository");
  card(s, M, TOP, 5.4, 3.6, true);
  T(s, [{ text: "# policy.yaml", options: { color: C.accent6, breakLine: true } }, { text: "max_allowed:", options: { breakLine: true } },
        { text: "  P0: " }, { text: "0", options: { color: C.accent2, breakLine: true } }, { text: "  P1: " }, { text: "0", options: { color: C.accent2, breakLine: true } },
        { text: "block_on_any_secret: " }, { text: "true", options: { color: C.accent2, breakLine: true } },
        { text: "max_failed_controls: " }, { text: "0", options: { color: C.accent2 } }], M + 0.35, TOP + 0.35, 4.7, 2.9,
    { fontFace: MONO, fontSize: 16, color: C.background2, paraSpaceAfter: 6 });
  [["Reviewed like code", "Changing the rule needs a pull request and an approver."], ["Enforced on every build", "No exceptions by email. The gate returns pass or block."],
   ["People own the threshold", "AI supplies priorities. It cannot change what is allowed."]].forEach((p, i) => {
    T(s, p[0], 6.95, TOP + 0.1 + i * 1.2, 5.5, 0.4, { fontSize: 20, bold: true, color: C.text1 });
    T(s, p[1], 6.95, TOP + 0.55 + i * 1.2, 5.5, 0.6, { fontSize: 16 });
  });
}
{
  const s = content("controls", "Part 3 · Continuous compliance", "From scanner output to control evidence");
  table(s, ["Framework", "Control", "Evidence from the pipeline"], [
    ["OWASP Top 10", "A03 Injection", "SAST findings for CWE-89, CWE-78"],
    ["OWASP Top 10", "A06 Vulnerable components", "Dependency audit result"],
    ["NIST SSDF", "PW.7 Code review and analysis", "SAST and secret scan results"],
    ["ISO/IEC 27001", "A.8.8 Technical vulnerabilities", "Dependency audit result"],
    ["ISO/IEC 27001", "A.8.16 Monitoring activities", "Anomaly detection ran on logs"]], [2.55, 4.4, 4.6], TOP, { fontSize: 15, rowH: 0.52 });
  closer(s, "17 controls, three frameworks, every run.", "A pass means no contradicting evidence in this build. It is not a certificate.", 5.7);
  source(s, "OWASP Top 10:2021 · NIST SP 800-218 v1.1 · ISO/IEC 27001:2022 Annex A");
}
{
  const s = slideOn("Statement amber", "evidence");
  T(s, "PART 3 · CONTINUOUS COMPLIANCE", M, 1.4, W, 0.3, { fontFace: MONO, fontSize: 12, charSpacing: 1.5, color: C.text1 });
  T(s, "Compliance becomes a by-product of shipping.", M, 2.0, W, 2.4, { fontSize: 54, bold: true, color: C.text1 });
  T(s, "Every build leaves a dated record: what was scanned, what was found, what was decided, and why.", M, 4.8, 9.8, 0.9, { fontSize: 22, color: C.text1 });
}

startSection("Live demo");
{
  const s = content("demo-plan", "Live demo · ShopLite", "Break it, read it, fix it, release it", true);
  const st = [["Step 1", "Break", "Release the vulnerable app in AWS. The gate blocks it."], ["Step 2", "Read", "Open the evidence. Follow one finding from scanner to fix."],
    ["Step 3", "Fix", "Compare the two versions of the code. Seven flaws, seven fixes."], ["Step 4", "Release", "Release the fixed app. It passes, then waits for approval."]];
  const g = cols(4, 0.25);
  st.forEach((x, i) => {
    s.addShape(pres.ShapeType.roundRect, { x: g.x[i], y: TOP, w: g.w, h: 2.7, rectRadius: 0.1, fill: { color: HEX.panel }, line: { color: HEX.panelLine, width: 0.75 } });
    T(s, x[0], g.x[i] + 0.25, TOP + 0.22, g.w - 0.5, 0.3, { fontFace: MONO, fontSize: 12, color: C.accent2 });
    T(s, x[1], g.x[i] + 0.25, TOP + 0.58, g.w - 0.5, 0.5, { fontSize: 22, bold: true, color: C.background2 });
    T(s, x[2], g.x[i] + 0.25, TOP + 1.2, g.w - 0.5, 1.35, { fontSize: 16, color: C.accent6 });
  });
  T(s, "python aws/package.py app  →  upload release.zip to S3  →  start the pipeline", M, 5.45, W, 0.4, { fontFace: MONO, fontSize: 13, color: C.accent6 });
}
{
  const s = content("demo-result", "Live demo · ShopLite", "What we just saw, in numbers");
  table(s, ["", "Vulnerable app", "Fixed app"], [
    ["Findings to review", "24", "0"],
    ["Release-blocking after AI triage", "16", "0"],
    ["Packages with known vulnerabilities", "5 of 5", "0 of 5"],
    ["Controls passing", "2 of 17", "17 of 17"],
    ["Release pipeline", { text: "Blocked at the gate", color: HEX.bad }, { text: "Passed, awaiting approval", color: HEX.good }]], [4.75, 3.4, 3.4], TOP, { fontSize: 16, rowH: 0.55 });
  closer(s, "Same pipeline, same policy, two outcomes.", "Nobody argued about whether to ship. The evidence decided.", 5.85);
  source(s, "Source: AWS run, us-east-1, 17 November 2026; counts change as new CVEs are published");
}

startSection("For the classroom");
{
  const s = content("classroom", "For your classroom", "Four labs from this one project");
  const items = [["Lab 1 · Secure coding", "Find and fix", "Fix one flaw at a time and re-run until the gate turns green."],
    ["Lab 2 · Software engineering", "Write a rule", "Add a new secret or Dockerfile check, with a unit test."],
    ["Lab 3 · Machine learning", "Tune the detector", "Change the features. Measure attackers caught and false alarms."],
    ["Lab 4 · AI security", "Attack the triage", "Plant a prompt injection in a comment. Do the guardrails hold?"]];
  const g = cols(2, 0.25);
  items.forEach((it, i) => infoCard(s, g.x[i % 2], TOP + Math.floor(i / 2) * 2.1, g.w, 1.9, it[0], it[1], it[2], false, { headSize: 22, headH: 0.45, bodySize: 16 }));
}
{
  const s = content("research", "For your research groups", "Open questions worth a project");
  [["Measuring triage", "How do we benchmark whether a model ranks vulnerabilities as well as an expert?"],
   ["Small local models", "Can a model that runs on campus hardware triage well enough to keep code private?"],
   ["Explaining alerts", "Which explanation of an anomaly score helps an analyst decide fastest?"],
   ["Attacking the defender", "How robust are security models to prompt injection and adversarial inputs?"]].forEach((r, i) => {
    const y = TOP + i * 1.05;
    card(s, M, y, W, 0.9, false);
    T(s, r[0], M + 0.3, y, 3.4, 0.9, { fontSize: 20, bold: true, color: C.text1, valign: "middle" });
    T(s, r[1], M + 3.9, y, W - 4.2, 0.9, { fontSize: 16, valign: "middle" });
  });
}
{
  const s = content("takeaways", "Takeaways", "Three things to remember", true);
  ["AI shortens the list. It does not make the release decision.", "Every model in a pipeline needs guardrails and a fallback.",
   "Compliance evidence should come out of every build, automatically."].forEach((t, i) => {
    const y = TOP + 0.2 + i * 1.3;
    s.addShape(pres.ShapeType.roundRect, { x: M, y, w: W, h: 1.05, rectRadius: 0.1, fill: { color: HEX.panel }, line: { color: HEX.panelLine, width: 0.75 } });
    T(s, String(i + 1), M + 0.3, y, 0.6, 1.05, { fontFace: MONO, fontSize: 24, bold: true, color: C.accent2, valign: "middle" });
    T(s, t, M + 1.0, y, W - 1.3, 1.05, { fontSize: 22, color: C.background2, valign: "middle" });
  });
}
{
  const s = slideOn("Statement dark", "thanks");
  T(s, "THANK YOU", M, 0.9, W, 0.3, { fontFace: MONO, fontSize: 12, charSpacing: 1.5, color: C.accent2 });
  T(s, "Questions?", M, 2.3, W, 1.1, { fontSize: 60, bold: true, color: C.background2 });
  T(s, "The demo project, slides and lab ideas are yours to reuse with your students.", M, 3.6, 9.8, 0.9, { fontSize: 22, color: C.accent6 });
  T(s, "Himanshu Bhardwaj", M, 5.75, 6, 0.35, { fontSize: 16, bold: true, color: C.background2 });
  T(s, "Sr. DevOps Architect, Provar · himanshu.bhardwaj@provartesting.com", M, 6.12, 7.5, 0.3, { fontSize: 14, color: C.accent6 });
  T(s, "github.com/himanshubhardwaj87/ai-devsecops-fdp", M + 5, 5.8, W - 5, 0.3, { fontFace: MONO, fontSize: 12, color: C.accent6, align: "right" });
}

(async () => {
  await pres.writeFile({ fileName: OUT });
  if (APPLY_THEME) {
    const { applyTheme } = require(APPLY_THEME);
    await applyTheme(OUT, THEME);
  }
  console.log("wrote " + OUT);
})().catch((err) => { console.error(err.message); process.exit(1); });
