// report_html_template.go
//
// The inline-everything HTML template for ProjectReportHTML. Kept in its own file
// because it is large; the rendering logic lives in report_html.go.
//
// Invariants this template MUST preserve (asserted by report_html_test.go):
//   - No external references: no <link>, no <script src=…>, no http(s):// asset URLs.
//   - No runtime network: no fetch(, no XMLHttpRequest, no WebSocket.
//   - The canonical Report JSON lives in <script type="application/json" id="report-data">.
//   - The inline JS reads that JSON from the DOM and renders charts + table.
package projection

import "html/template"

var reportHTMLTemplate = template.Must(template.New("report.html").Parse(reportHTMLSource))

const reportHTMLSource = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
  :root {
    --bg: #0e1116; --panel: #161b22; --panel-2: #1c2230; --border: #2a313c;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --ok: #3fb950; --info: #58a6ff; --candidate: #d29922; --candidate-strong: #e3b341;
    --notassessed: #a371f7;
    --shadow: 0 1px 3px rgba(0,0,0,.4), 0 8px 24px rgba(0,0,0,.25);
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    background: var(--bg); color: var(--text);
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 1040px; margin: 0 auto; padding: 40px 24px 80px; }
  header.page { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; margin-bottom: 4px; }
  header.page .brand { font-size: 22px; font-weight: 700; letter-spacing: -.01em; }
  header.page .brand .o { color: var(--accent); }
  header.page .tag {
    font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted);
    border: 1px solid var(--border); border-radius: 999px; padding: 2px 10px;
  }
  .sub { color: var(--muted); font-size: 13px; margin: 2px 0 28px; }
  .grid { display: grid; grid-template-columns: 320px 1fr; gap: 20px; align-items: start; }
  @media (max-width: 760px) { .grid { grid-template-columns: 1fr; } }
  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    padding: 22px; box-shadow: var(--shadow);
  }
  .card h2 { margin: 0 0 16px; font-size: 13px; text-transform: uppercase; letter-spacing: .07em; color: var(--muted); font-weight: 600; }
  .chart { display: flex; align-items: center; gap: 18px; }
  .chart svg { flex: 0 0 auto; }
  .legend { list-style: none; margin: 0; padding: 0; display: grid; gap: 9px; font-size: 13px; }
  .legend li { display: flex; align-items: center; gap: 9px; }
  .legend .dot { width: 11px; height: 11px; border-radius: 3px; flex: 0 0 auto; }
  .legend .n { margin-left: auto; font-variant-numeric: tabular-nums; color: var(--muted); font-weight: 600; }
  .dot.ok { background: var(--ok); } .dot.info { background: var(--info); } .dot.candidate { background: var(--candidate-strong); } .dot.notassessed { background: var(--notassessed); }
  .meta { display: grid; gap: 12px; }
  .meta .row { display: grid; grid-template-columns: 90px 1fr; gap: 10px; font-size: 13px; align-items: baseline; }
  .meta .k { color: var(--muted); }
  .meta .v { word-break: break-all; font-feature-settings: "tnum"; }
  code, .mono { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; }
  table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
  thead th {
    text-align: left; color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase;
    letter-spacing: .06em; padding: 0 12px 10px; border-bottom: 1px solid var(--border);
  }
  tbody td { padding: 13px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: var(--panel-2); }
  .vid { font-weight: 600; }
  .vid .src { display: block; color: var(--muted); font-size: 11px; font-weight: 400; margin-top: 2px; }
  .badge {
    display: inline-block; font-size: 11.5px; font-weight: 600; padding: 3px 10px; border-radius: 999px;
    border: 1px solid transparent; white-space: nowrap;
  }
  .badge.ok { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 45%, transparent); background: color-mix(in srgb, var(--ok) 12%, transparent); }
  .badge.info { color: var(--info); border-color: color-mix(in srgb, var(--info) 45%, transparent); background: color-mix(in srgb, var(--info) 12%, transparent); }
  .badge.candidate { color: var(--candidate-strong); border-color: color-mix(in srgb, var(--candidate) 55%, transparent); background: color-mix(in srgb, var(--candidate) 14%, transparent); }
  .detail { color: var(--muted); margin-top: 5px; }
  .path { margin-top: 6px; }
  .path .mono { background: var(--panel-2); border: 1px solid var(--border); border-radius: 6px; padding: 2px 7px; font-size: 12px; }
  .empty { color: var(--muted); padding: 28px 12px; text-align: center; }
  footer.page { margin-top: 32px; color: var(--muted); font-size: 12px; line-height: 1.7; }
  footer.page strong { color: var(--text); font-weight: 600; }
  .findings.card { margin-top: 20px; }
  .total { font-size: 34px; font-weight: 700; letter-spacing: -.02em; }
  .total small { display: block; font-size: 12px; font-weight: 500; color: var(--muted); text-transform: uppercase; letter-spacing: .07em; margin-top: 2px; }
  /* priority / intel badges */
  --kev: #f78166; --tainted: #d29922; --cfo: #8b949e;
  .intel { margin-top: 6px; display: flex; flex-wrap: wrap; gap: 5px; align-items: center; }
  .badge.kev { color: var(--kev); border-color: color-mix(in srgb, var(--kev) 45%, transparent); background: color-mix(in srgb, var(--kev) 10%, transparent); }
  .badge.tainted { color: var(--tainted); border-color: color-mix(in srgb, var(--tainted) 45%, transparent); background: color-mix(in srgb, var(--tainted) 12%, transparent); }
  .badge.cfo { color: var(--cfo); border-color: color-mix(in srgb, var(--cfo) 40%, transparent); background: color-mix(in srgb, var(--cfo) 10%, transparent); }
  .epss-label { font-size: 11.5px; color: var(--muted); font-variant-numeric: tabular-nums; }
  .entry-point { margin-top: 5px; font-size: 12px; color: var(--muted); }
  .entry-point .mono { background: var(--panel-2); border: 1px solid var(--border); border-radius: 4px; padding: 1px 5px; font-size: 11.5px; }
  /* coverage limits — the "not assessed" disclosure. Deliberately styled as a panel above the
     findings table, not as a footnote: an advisory withheld for honesty that renders quietly is
     indistinguishable from one that was never evaluated. */
  .limits.card { margin-top: 20px; border-color: color-mix(in srgb, var(--notassessed) 35%, var(--border)); }
  .badge.notassessed { color: var(--notassessed); border-color: color-mix(in srgb, var(--notassessed) 45%, transparent); background: color-mix(in srgb, var(--notassessed) 12%, transparent); }
  .limits-lede { color: var(--muted); font-size: 12.5px; line-height: 1.6; margin: 0 0 14px; }
  .limits-lede strong { color: var(--text); }
  .limit-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 14px; }
  .limit-list > li { padding: 12px; border: 1px solid var(--border); border-radius: 8px; background: var(--panel-2); }
  .limit-why { display: block; margin-top: 7px; font-size: 13px; line-height: 1.55; }
  .limit-code { margin-top: 6px; font-size: 11px; color: var(--muted); }
  .limit-advisories { list-style: none; padding: 0; margin: 9px 0 0; display: flex; flex-wrap: wrap; gap: 6px; }
  .limit-advisories li { font-size: 12px; padding: 2px 8px; border: 1px solid var(--border); border-radius: 6px; background: var(--panel); }
  .callpath { margin-top: 6px; padding-left: 0; list-style: none; font-size: 12px; color: var(--muted); }
  .callpath li { display: flex; gap: 6px; align-items: baseline; padding: 2px 0; }
  .callpath li .frame-idx { color: var(--border); font-size: 10px; min-width: 18px; text-align: right; }
  .callpath li .frame-sym { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; }
  .callpath li .frame-loc { color: var(--border); font-size: 11px; }
</style>
</head>
<body>
<div class="wrap">
  <header class="page">
    <span class="brand">{{.Brand}}</span>
    <span class="tag">scan report</span>
  </header>
  <p class="sub">Neutral, deterministic dependency advisory scan. Verdicts are reachability candidates and grounded refutations &mdash; never proofs of exploitability.</p>

  <div class="grid">
    <section class="card">
      <h2>Verdict breakdown</h2>
      <div class="chart">
        <svg id="donut" width="132" height="132" viewBox="0 0 132 132" role="img" aria-label="Verdict breakdown chart"></svg>
        <ul class="legend">
          <li><span class="dot ok"></span> Disqualified <span class="n" id="n-disqualified">0</span></li>
          <li><span class="dot info"></span> Not exploitable <span class="n" id="n-notexploitable">0</span></li>
          <li><span class="dot candidate"></span> Reachable candidate <span class="n" id="n-candidate">0</span></li>
          <li><span class="dot notassessed"></span> Not assessed <span class="n" id="n-undetermined">0</span></li>
        </ul>
      </div>
    </section>

    <section class="card">
      <h2>Subject &amp; provenance</h2>
      <div class="meta">
        <div class="row"><span class="k">Total</span><span class="v"><span class="total" id="m-total">0</span><small>advisories evaluated</small></span></div>
        <div class="row"><span class="k">Repository</span><span class="v mono" id="m-repo">&mdash;</span></div>
        <div class="row"><span class="k">Revision</span><span class="v mono" id="m-revision">&mdash;</span></div>
        <div class="row"><span class="k">Commit</span><span class="v mono" id="m-commit">&mdash;</span></div>
        <div class="row"><span class="k">Analyzer</span><span class="v mono" id="m-analyzer">&mdash;</span></div>
        <div class="row"><span class="k">Generated</span><span class="v mono" id="m-generated">&mdash;</span></div>
      </div>
    </section>
  </div>

  {{- if .Limits}}
  <section class="card limits">
    <h2>Coverage limits{{if .NotAssessedCount}} &mdash; {{.NotAssessedCount}} advisor{{if eq .NotAssessedCount 1}}y{{else}}ies{{end}} not assessed{{end}}</h2>
    <p class="limits-lede">These are the limits of what this scan established. An advisory these limits cover was evaluated and given <strong>no verdict</strong> &mdash; that is not a statement that this codebase is unaffected by it. Each such advisory appears in the table below marked <em>not assessed</em>.</p>
    <ul class="limit-list">
      {{- range .Limits}}
      <li>
        <span class="badge {{if .Withheld}}notassessed{{else}}info{{end}}">{{if .Withheld}}not assessed{{else}}partial coverage{{end}}</span>
        <span class="limit-why">{{.Label}}</span>
        {{- if .Ecosystem}}<span class="src">{{.Ecosystem}}</span>{{end}}
        <div class="limit-code mono">{{.Reason}}</div>
        {{- if .Advisories}}
        <ul class="limit-advisories">
          {{- range .Advisories}}
          <li class="vid">{{.}}</li>
          {{- end}}
        </ul>
        {{- end}}
      </li>
      {{- end}}
    </ul>
  </section>
  {{- end}}

  <section class="card findings">
    <h2>Advisory findings</h2>
    <table>
      <thead>
        <tr><th>Advisory</th><th>Package</th><th>Verdict</th><th>EPSS / KEV likelihood</th></tr>
      </thead>
      <tbody id="findings-body">
      {{- range .Findings}}
      <tr>
        <td>
          <span class="vid">{{.ID}}</span>
          <span class="src">{{.Source}}{{if .Aliases}} · {{.Aliases}}{{end}}</span>
        </td>
        <td class="mono">{{if .Package}}{{.Package}}{{else}}&mdash;{{end}}</td>
        <td>
          <span class="badge {{.Severity}}">{{.Label}}</span>
          {{- if .Detail}}<div class="detail">{{.Detail}}</div>{{end}}
          {{- if .UndeterminedReason}}<div class="limit-code mono">{{.UndeterminedReason}}</div>{{end}}
          {{- if .Path}}<div class="path"><span class="mono">{{.Path}}</span></div>{{end}}
          {{- if .HasGrade}}
            {{- if eq .Grade "attacker_tainted"}}
          <div class="intel"><span class="badge tainted" title="An attacker-controllable ingress reaches the vulnerable symbol along this path. Evidence-strength signal only — not an exploitability verdict.">attacker-tainted candidate</span></div>
            {{- else if eq .Grade "control_flow_only"}}
          <div class="intel"><span class="badge cfo" title="A control-flow path to the vulnerable symbol exists but no attacker-tainted data was found along it.">control-flow only</span></div>
            {{- end}}
          {{- end}}
          {{- if .HasEntryPoint}}
          <div class="entry-point">entry: <span class="mono">{{.EntrySymbol}}</span>{{if .EntryKind}} &mdash; {{.EntryKind}}{{end}}{{if .AttackerControllable}}, <strong>attacker-controllable</strong>{{end}}</div>
          {{- end}}
          {{- if .CallFrames}}
          <ol class="callpath">
            {{- range $i, $f := .CallFrames}}
            <li><span class="frame-idx">{{$i}}</span><span class="frame-sym">{{$f.Symbol}}</span>{{if $f.File}}<span class="frame-loc">{{$f.File}}{{if $f.Line}}:{{$f.Line}}{{end}}</span>{{end}}</li>
            {{- end}}
          </ol>
          {{- end}}
        </td>
        <td>
          {{- if .HasPriority}}
          <span class="epss-label" title="EPSS likelihood: probability this CVE is exploited in the wild (FIRST.org public feed). This is wild-exploitation likelihood context from public feeds — not an exploitability claim for this codebase.">EPSS {{printf "%.3f" .EPSSScore}} / p{{.EPSSPct}}</span>
          {{- if .KEVListed}}
          <div class="intel"><span class="badge kev" title="CISA Known Exploited Vulnerability — active exploitation of this CVE has been recorded in the wild (CISA KEV catalog). This is a wild-exploitation signal, not a claim that this codebase is exploitable.">CISA KEV{{if .KEVDateAdded}} ({{.KEVDateAdded}}){{end}}</span></div>
          {{- end}}
          {{- else}}<span class="epss-label">&mdash;</span>{{end}}
        </td>
      </tr>
      {{- end}}
      </tbody>
    </table>
    <div class="empty" id="findings-empty"{{if .Findings}} hidden{{end}}>No advisories were evaluated in this scan.</div>
  </section>

  <footer class="page">
    <strong>How to read this:</strong> a <em>reachable candidate</em> means a code path to the advisory symbol was found &mdash; it is a candidate for exploitability, not a proof.
    <em>Not exploitable</em> and <em>disqualified</em> are grounded deterministic refutations. {{.Brand}} never claims a finding is proven exploitable: proof requires observing the vulnerable path actually execute, which this scan does not do.
    <br>This report is self-contained: the data above is rendered from the JSON embedded in this file.
    <br><strong>EPSS / CISA KEV:</strong> EPSS scores and KEV flags come from the pinned intel snapshot indicated per finding. They are wild-exploitation likelihood signals from public feeds (FIRST.org EPSS, CISA KEV catalog) &mdash; not exploitability verdicts for this codebase.
  </footer>
</div>

<script type="application/json" id="report-data">{{.DataJSON}}</script>
<script>
(function () {
  "use strict";
  function text(id, v) { var el = document.getElementById(id); if (el) el.textContent = (v == null || v === "") ? "—" : v; }

  var raw = document.getElementById("report-data").textContent;
  var report;
  try { report = JSON.parse(raw); } catch (e) { report = { advisories: [], subject: {}, provenance: {} }; }

  var subject = report.subject || {};
  var prov = report.provenance || {};
  var findings = report.advisories || [];

  var counts = { disqualified: 0, not_exploitable: 0, reachable_candidate: 0, undetermined: 0 };
  findings.forEach(function (f) { if (counts[f.verdict] != null) counts[f.verdict]++; });

  text("m-total", String(findings.length));
  text("m-repo", subject.repo);
  text("m-revision", subject.revision);
  text("m-commit", subject.resolved_commit);
  text("m-analyzer", prov.analyzer_version);
  if (prov.timestamp) {
    var d = new Date(prov.timestamp);
    text("m-generated", isNaN(d.getTime()) ? prov.timestamp : d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z"));
  }
  text("n-disqualified", String(counts.disqualified));
  text("n-notexploitable", String(counts.not_exploitable));
  text("n-candidate", String(counts.reachable_candidate));
  text("n-undetermined", String(counts.undetermined));

  // The findings table is pre-rendered server-side via Go template.

  // --- SVG donut chart ---
  var SVGNS = "http://www.w3.org/2000/svg";
  var segs = [
    { v: counts.disqualified, color: getComputedStyle(document.documentElement).getPropertyValue("--ok").trim() || "#3fb950" },
    { v: counts.not_exploitable, color: getComputedStyle(document.documentElement).getPropertyValue("--info").trim() || "#58a6ff" },
    { v: counts.reachable_candidate, color: getComputedStyle(document.documentElement).getPropertyValue("--candidate-strong").trim() || "#e3b341" },
    { v: counts.undetermined, color: getComputedStyle(document.documentElement).getPropertyValue("--notassessed").trim() || "#a371f7" }
  ];
  var total = segs.reduce(function (a, s) { return a + s.v; }, 0);
  var svg = document.getElementById("donut");
  var cx = 66, cy = 66, r = 52, sw = 18;

  function ring(color) {
    var c = document.createElementNS(SVGNS, "circle");
    c.setAttribute("cx", cx); c.setAttribute("cy", cy); c.setAttribute("r", r);
    c.setAttribute("fill", "none"); c.setAttribute("stroke", color); c.setAttribute("stroke-width", sw);
    return c;
  }
  if (total === 0) {
    svg.appendChild(ring(getComputedStyle(document.documentElement).getPropertyValue("--border").trim() || "#2a313c"));
  } else {
    var circ = 2 * Math.PI * r;
    var offset = 0;
    segs.forEach(function (s) {
      if (s.v === 0) return;
      var frac = s.v / total;
      var arc = ring(s.color);
      arc.setAttribute("stroke-dasharray", (frac * circ) + " " + circ);
      arc.setAttribute("stroke-dashoffset", -offset * circ);
      arc.setAttribute("transform", "rotate(-90 " + cx + " " + cy + ")");
      svg.appendChild(arc);
      offset += frac;
    });
  }
  var label = document.createElementNS(SVGNS, "text");
  label.setAttribute("x", cx); label.setAttribute("y", cy);
  label.setAttribute("text-anchor", "middle"); label.setAttribute("dominant-baseline", "central");
  label.setAttribute("fill", getComputedStyle(document.documentElement).getPropertyValue("--text").trim() || "#e6edf3");
  label.setAttribute("font-size", "26"); label.setAttribute("font-weight", "700");
  label.textContent = String(total);
  svg.appendChild(label);
})();
</script>
</body>
</html>
`
