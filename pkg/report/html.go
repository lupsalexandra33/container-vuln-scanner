package report

import (
	"html/template"
	"io"
	"strings"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

const htmlTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Vulnerability Report - {{.Target}}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 24px; }
    .container { max-width: 1300px; margin: 0 auto; }
    h1 { color: #f0f6fc; margin-bottom: 4px; }
    .meta { color: #8b949e; font-size: 14px; margin-bottom: 24px; }
    .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; margin-bottom: 28px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px 10px; text-align: center; }
    .card .count { font-size: 22px; font-weight: bold; margin-bottom: 4px; }
    .badge-critical { color: #f85149; font-weight: bold; }
    .badge-high { color: #db6d28; font-weight: bold; }
    .badge-medium { color: #d29922; }
    .badge-low { color: #58a6ff; }
    .badge-kev { color: #ff7b72; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 6px; overflow: hidden; border: 1px solid #30363d; }
    th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #30363d; font-size: 13px; vertical-align: top; }
    th { background: #21262d; color: #f0f6fc; font-weight: 600; }
    tr:hover { background: #1f242c; }
    .tag { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 500; }
    .tag-kev { background: rgba(248, 81, 73, 0.15); border: 1px solid rgba(248, 81, 73, 0.4); color: #f85149; font-weight: bold; }
    .tag-fix { background: rgba(46, 160, 67, 0.15); border: 1px solid rgba(46, 160, 67, 0.4); color: #3fb950; }
    .tag-unfix { background: rgba(139, 148, 158, 0.15); border: 1px solid rgba(139, 148, 158, 0.4); color: #8b949e; }
    .tag-disputed { background: rgba(210, 153, 34, 0.15); border: 1px solid rgba(210, 153, 34, 0.4); color: #d29922; }
    .tag-none { color: #8b949e; }
    .scanner-entry { font-size: 11px; margin-bottom: 2px; }
    .participation-reported { color: #3fb950; }
    .participation-missed { color: #f85149; }
    .participation-silent { color: #8b949e; }
    .confidence { font-weight: 600; }
    .confidence-meta { font-size: 11px; color: #8b949e; }
    .conflict-box { font-size: 11px; color: #d29922; background: rgba(210, 153, 34, 0.1); padding: 4px 6px; border-radius: 4px; margin-top: 4px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Multi-Scanner Vulnerability Report</h1>
    <div class="meta">Target: <strong>{{.Target}}</strong> | Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}} | Tool: {{.ToolName}} {{.ToolVersion}}</div>

    <div class="summary-cards">
      <div class="card"><div class="count">{{.Summary.Total}}</div><div>Total</div></div>
      <div class="card"><div class="count badge-critical">{{.Summary.Critical}}</div><div>Critical</div></div>
      <div class="card"><div class="count badge-high">{{.Summary.High}}</div><div>High</div></div>
      <div class="card"><div class="count badge-medium">{{.Summary.Medium}}</div><div>Medium</div></div>
      <div class="card"><div class="count badge-low">{{.Summary.Low}}</div><div>Low</div></div>
      <div class="card"><div class="count badge-kev">{{.Summary.InKEV}}</div><div>CISA KEV</div></div>
      <div class="card"><div class="count">{{.Summary.FixAvailable}}</div><div>Fix Available</div></div>
      <div class="card"><div class="count tag-none">{{.Summary.Unfixable}}</div><div>Unfixable</div></div>
      <div class="card"><div class="count tag-disputed">{{.Summary.Disputed}}</div><div>Disputed</div></div>
    </div>

    <table>
      <thead>
        <tr>
          <th>Vulnerability</th>
          <th>Severity</th>
          <th>Package</th>
          <th>Fix State</th>
          <th>CISA KEV</th>
          <th>EPSS</th>
          <th>Scanner Participation</th>
          <th>Confidence Derivation</th>
        </tr>
      </thead>
      <tbody>
        {{range .Findings}}
        {{$ci := .ConfidenceInputs}}
        <tr>
          <td>
            <strong>{{vulnID .}}</strong>
            {{if .IsDisputed}}<span class="tag tag-disputed">Disputed</span>{{end}}
            {{if .IsSingleSource}}<span class="tag tag-none">Single Source</span>{{end}}
            {{if .Conflicts}}
              <div class="conflict-box">
                {{range .Conflicts}}
                  <div><strong>Conflict ({{.Kind}}):</strong> resolved to "{{.Resolved}}" ({{.Reason}})</div>
                {{end}}
              </div>
            {{end}}
          </td>
          <td>
            {{$sev := toLower (printf "%s" .Severity)}}
            {{if eq $sev "critical"}}<span class="badge-critical">{{.Severity}}</span>
            {{else if eq $sev "high"}}<span class="badge-high">{{.Severity}}</span>
            {{else if eq $sev "medium"}}<span class="badge-medium">{{.Severity}}</span>
            {{else}}<span class="badge-low">{{.Severity}}</span>{{end}}
          </td>
          <td>
            <div>{{packageName .}}</div>
            <div class="tag-none">{{.InstalledVersion}}</div>
          </td>
          <td>
            {{if .HasFix}}
              <span class="tag tag-fix">Fixed in {{join .FixedVersions ", "}}</span>
            {{else}}
              <span class="tag tag-unfix">{{.FixState}}</span>
            {{end}}
          </td>
          <td>
            {{if .IsActivelyExploited}}
              <span class="tag tag-kev">ACTIVE EXPLOIT</span>
              {{if .Enrichment.KEVDueDate}}<div class="tag-none">Due: {{.Enrichment.KEVDueDate}}</div>{{end}}
            {{else}}
              <span class="tag-none">-</span>
            {{end}}
          </td>
          <td>
            {{if and .Enrichment (gt .Enrichment.EPSSScore 0.0)}}
              {{printf "%.2f%%" (mulf .Enrichment.EPSSScore 100.0)}}
            {{else if .Enrichment}}
              <span class="tag-none">0.00%</span>
            {{else}}
              <span class="tag-none">Unenriched</span>
            {{end}}
          </td>
          <td>
            {{range .Verdicts}}
              <div class="scanner-entry">
                <strong>{{.Scanner}}:</strong>
                {{if eq (printf "%s" .Participation) "reported"}}
                  <span class="participation-reported">reported</span>
                {{else if eq (printf "%s" .Participation) "ran_and_missed"}}
                  <span class="participation-missed">missed</span>
                {{else}}
                  <span class="participation-silent">{{.Participation}}</span>
                {{end}}
                {{if .Reason}}<span class="tag-none">({{.Reason}})</span>{{end}}
              </div>
            {{else}}
              <span class="tag-none">-</span>
            {{end}}
          </td>
          <td>
            <div class="confidence">{{printf "%.2f" .Confidence}}</div>
            <div class="confidence-meta">
              {{$ci.AgreeingCount}}/{{$ci.ParticipatingCount}} agreed
              {{if gt $ci.ExcludedCount 0}}({{$ci.ExcludedCount}} excluded){{end}}
            </div>
          </td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
</body>
</html>`

func ExportHTML(w io.Writer, rep Report) error {
	funcMap := template.FuncMap{
		"mulf":    func(a, b float64) float64 { return a * b },
		"join":    strings.Join,
		"toLower": strings.ToLower,
		"vulnID": func(c model.ConsolidatedFinding) string {
			if id := c.Vulnerability.PreferredID().ID; id != "" {
				return id
			}
			return c.Vulnerability.Primary.ID
		},
		"packageName": func(c model.ConsolidatedFinding) string {
			if c.Package.Name != "" {
				return c.Package.Name
			}
			return c.Package.Canonical()
		},
	}
	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTmpl)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, rep)
}
