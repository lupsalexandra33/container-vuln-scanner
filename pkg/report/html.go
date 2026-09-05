package report

import (
	"html/template"
	"io"
)

const htmlTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Vulnerability Report - {{.Target}}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 24px; }
    .container { max-width: 1100px; margin: 0 auto; }
    h1 { color: #f0f6fc; margin-bottom: 4px; }
    .meta { color: #8b949e; font-size: 14px; margin-bottom: 24px; }
    .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin-bottom: 30px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px 16px; text-align: center; }
    .card .count { font-size: 24px; font-weight: bold; margin-bottom: 4px; }
    .badge-critical { color: #f85149; }
    .badge-high { color: #db6d28; }
    .badge-medium { color: #d29922; }
    .badge-low { color: #58a6ff; }
    .badge-kev { color: #ff7b72; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 6px; overflow: hidden; border: 1px solid #30363d; }
    th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid #30363d; font-size: 14px; }
    th { background: #21262d; color: #f0f6fc; font-weight: 600; }
    tr:hover { background: #1f242c; }
    .tag { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 12px; font-weight: 500; }
    .tag-kev { background: rgba(248, 81, 73, 0.15); border: 1px solid rgba(248, 81, 73, 0.4); color: #f85149; }
    .tag-none { color: #8b949e; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Container Vulnerability Scan Report</h1>
    <div class="meta">Target: <strong>{{.Target}}</strong> | Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}} | Tool: {{.ToolName}} {{.ToolVersion}}</div>

    <div class="summary-cards">
      <div class="card"><div class="count">{{.Summary.Total}}</div><div>Total</div></div>
      <div class="card"><div class="count badge-critical">{{.Summary.Critical}}</div><div>Critical</div></div>
      <div class="card"><div class="count badge-high">{{.Summary.High}}</div><div>High</div></div>
      <div class="card"><div class="count badge-medium">{{.Summary.Medium}}</div><div>Medium</div></div>
      <div class="card"><div class="count badge-low">{{.Summary.Low}}</div><div>Low</div></div>
      <div class="card"><div class="count badge-kev">{{.Summary.InKEV}}</div><div>CISA KEV</div></div>
    </div>

    <table>
      <thead>
        <tr>
          <th>CVE</th>
          <th>Severity</th>
          <th>Package</th>
          <th>Version</th>
          <th>CISA KEV</th>
          <th>EPSS Score</th>
          <th>Fixed In</th>
        </tr>
      </thead>
      <tbody>
        {{range .Findings}}
        <tr>
          <td><strong>{{.ID}}</strong></td>
          <td>
            {{if eq .Severity "CRITICAL"}}<span class="badge-critical">{{.Severity}}</span>
            {{else if eq .Severity "HIGH"}}<span class="badge-high">{{.Severity}}</span>
            {{else if eq .Severity "MEDIUM"}}<span class="badge-medium">{{.Severity}}</span>
            {{else}}<span class="badge-low">{{.Severity}}</span>{{end}}
          </td>
          <td>{{.Package}}</td>
          <td>{{.Version}}</td>
          <td>
            {{if .InKEV}}<span class="tag tag-kev">ACTIVE EXPLOIT</span>
            {{else}}<span class="tag-none">-</span>{{end}}
          </td>
          <td>{{if gt .EPSSScore 0.0}}{{printf "%.2f%%" (mulf .EPSSScore 100.0)}}{{else}}-{{end}}</td>
          <td>{{if .FixVersion}}{{.FixVersion}}{{else}}<span class="tag-none">None</span>{{end}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
</body>
</html>`

func ExportHTML(w io.Writer, rep Report) error {
	funcMap := template.FuncMap{
		"mulf": func(a, b float64) float64 { return a * b },
	}
	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTmpl)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, rep)
}
