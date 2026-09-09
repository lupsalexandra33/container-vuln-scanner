package report

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// FindingView is a flat, display-ready representation for the HTML template.
type FindingView struct {
	Severity      string
	SeverityClass string
	VulnID        string
	PackageName   string
	InstalledVer  string
	FixState      string
	FixedVersions string
	IsFixable     bool
}

type DashboardData struct {
	Scanner    string
	SourceFile string
	TotalCount int
	CritCount  int
	HighCount  int
	MedCount   int
	LowCount   int
	UnkCount   int
	Findings   []FindingView
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>vulnscan — Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0b0f19;
      --surface: #111827;
      --surface-hover: #172033;
      --border: #1f293d;
      --border-focus: #3b82f6;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --text-dim: #6b7280;
      
      --crit: #ef4444;
      --crit-bg: rgba(239, 68, 68, 0.12);
      --high: #f97316;
      --high-bg: rgba(249, 115, 22, 0.12);
      --med: #eab308;
      --med-bg: rgba(234, 179, 8, 0.12);
      --low: #38bdf8;
      --low-bg: rgba(56, 189, 248, 0.12);
      --unk: #94a3b8;
      --unk-bg: rgba(148, 163, 184, 0.12);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 32px 24px;
      -webkit-font-smoothing: antialiased;
    }
    .container {
      max-width: 1240px;
      margin: 0 auto;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      margin-bottom: 28px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .brand h1 {
      font-size: 20px;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .brand-badge {
      background: #1e293b;
      color: #38bdf8;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 9999px;
      font-weight: 500;
      border: 1px solid rgba(56, 189, 248, 0.2);
    }
    .metadata {
      font-size: 13px;
      color: var(--text-dim);
      font-family: 'JetBrains Mono', monospace;
      margin-top: 6px;
    }
    .metadata code {
      color: var(--text-muted);
      background: var(--surface);
      padding: 2px 6px;
      border-radius: 4px;
      border: 1px solid var(--border);
    }

    /* Stat Cards */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      cursor: pointer;
      transition: all 0.15s ease;
      user-select: none;
    }
    .stat-card:hover {
      background: var(--surface-hover);
      border-color: #334155;
      transform: translateY(-1px);
    }
    .stat-card.active {
      border-color: var(--text);
      background: #1e293b;
      box-shadow: 0 0 0 1px var(--text);
    }
    .stat-val {
      font-size: 26px;
      font-weight: 700;
      letter-spacing: -0.02em;
      font-variant-numeric: tabular-nums;
    }
    .stat-label {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-dim);
      margin-top: 2px;
    }
    .crit { color: var(--crit); }
    .high { color: var(--high); }
    .med  { color: var(--med); }
    .low  { color: var(--low); }
    .unk  { color: var(--unk); }

    /* Filter & Search Bar */
    .toolbar {
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }
    .search-box {
      flex: 1;
      min-width: 280px;
      position: relative;
    }
    .search-input {
      width: 100%;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 14px 10px 38px;
      color: var(--text);
      font-size: 14px;
      outline: none;
      transition: border-color 0.15s;
    }
    .search-input:focus {
      border-color: var(--border-focus);
      box-shadow: 0 0 0 1px var(--border-focus);
    }
    .search-icon {
      position: absolute;
      left: 12px;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-dim);
      pointer-events: none;
      font-size: 14px;
    }
    .toggle-fixable {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      color: var(--text-muted);
      cursor: pointer;
      user-select: none;
      background: var(--surface);
      padding: 9px 14px;
      border-radius: 8px;
      border: 1px solid var(--border);
    }
    .toggle-fixable input {
      accent-color: var(--border-focus);
      cursor: pointer;
    }
    .counter {
      font-size: 13px;
      color: var(--text-dim);
      margin-left: auto;
      font-variant-numeric: tabular-nums;
    }

    /* Findings Table */
    .table-wrapper {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      text-align: left;
    }
    th {
      background: #0f1523;
      padding: 12px 16px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-dim);
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 12px 16px;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }
    tbody tr:last-child td {
      border-bottom: none;
    }
    tbody tr:hover {
      background: var(--surface-hover);
    }
    .mono {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
    }
    .cve-link {
      color: #93c5fd;
      text-decoration: none;
    }
    .cve-link:hover {
      text-decoration: underline;
    }

    /* Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      line-height: 1;
    }
    .badge-critical { background: var(--crit-bg); color: var(--crit); border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-high     { background: var(--high-bg); color: var(--high); border: 1px solid rgba(249, 115, 22, 0.3); }
    .badge-medium   { background: var(--med-bg);  color: var(--med);  border: 1px solid rgba(234, 179, 8, 0.3); }
    .badge-low      { background: var(--low-bg);  color: var(--low);  border: 1px solid rgba(56, 189, 248, 0.3); }
    .badge-unknown  { background: var(--unk-bg);  color: var(--unk);  border: 1px solid rgba(148, 163, 184, 0.3); }

    .fix-state {
      display: inline-block;
      font-size: 12px;
      color: var(--text-muted);
    }
    .fix-state.fixed {
      color: #4ade80;
    }

    /* Empty state */
    .empty-state {
      padding: 48px 24px;
      text-align: center;
      color: var(--text-dim);
      display: none;
    }
    .empty-state h3 {
      font-size: 16px;
      color: var(--text-muted);
      margin-bottom: 6px;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <div class="brand">
          <h1>vulnscan report</h1>
          <span class="brand-badge">{{.Scanner}}</span>
        </div>
        <div class="metadata">Source: <code>{{.SourceFile}}</code></div>
      </div>
    </header>

    <section class="stats-grid">
      <div class="stat-card active" data-filter="all" onclick="selectSeverity('all')">
        <div class="stat-val">{{.TotalCount}}</div>
        <div class="stat-label">Total Findings</div>
      </div>
      <div class="stat-card" data-filter="critical" onclick="selectSeverity('critical')">
        <div class="stat-val crit">{{.CritCount}}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card" data-filter="high" onclick="selectSeverity('high')">
        <div class="stat-val high">{{.HighCount}}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card" data-filter="medium" onclick="selectSeverity('medium')">
        <div class="stat-val med">{{.MedCount}}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card" data-filter="low" onclick="selectSeverity('low')">
        <div class="stat-val low">{{.LowCount}}</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-card" data-filter="unknown" onclick="selectSeverity('unknown')">
        <div class="stat-val unk">{{.UnkCount}}</div>
        <div class="stat-label">Unknown</div>
      </div>
    </section>

    <div class="toolbar">
      <div class="search-box">
        <span class="search-icon">🔍</span>
        <input type="text" id="filter" class="search-input" placeholder="Search vulnerability, package, or version (Esc to clear)..." oninput="applyFilters()">
      </div>
      <label class="toggle-fixable">
        <input type="checkbox" id="fixableOnly" onchange="applyFilters()"> Fixable only
      </label>
      <div class="counter" id="matchCounter">Showing {{.TotalCount}} of {{.TotalCount}}</div>
    </div>

    <div class="table-wrapper">
      <table id="vulnTable">
        <thead>
          <tr>
            <th style="width: 120px;">Severity</th>
            <th style="width: 190px;">Vulnerability</th>
            <th>Package</th>
            <th style="width: 140px;">Installed</th>
            <th style="width: 110px;">Status</th>
            <th>Fixed Version</th>
          </tr>
        </thead>
        <tbody>
          {{range .Findings}}
          <tr data-severity="{{.SeverityClass}}" data-fixable="{{if .IsFixable}}true{{else}}false{{end}}">
            <td><span class="badge badge-{{.SeverityClass}}">{{.Severity}}</span></td>
            <td>
              <a class="mono cve-link" href="https://nvd.nist.gov/vuln/detail/{{.VulnID}}" target="_blank" rel="noopener">
                {{.VulnID}}
              </a>
            </td>
            <td><strong>{{.PackageName}}</strong></td>
            <td class="mono">{{.InstalledVer}}</td>
            <td><span class="fix-state {{if eq .FixState "fixed"}}fixed{{end}}">{{.FixState}}</span></td>
            <td class="mono">{{if .FixedVersions}}{{.FixedVersions}}{{else}}<span style="color:var(--text-dim)">—</span>{{end}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
      <div class="empty-state" id="emptyState">
        <h3>No matching vulnerabilities found</h3>
        <p>Try clearing your search query or selecting a different severity card above.</p>
      </div>
    </div>
  </div>

  <script>
    let activeSeverity = 'all';

    function selectSeverity(sev) {
      if (activeSeverity === sev && sev !== 'all') {
        activeSeverity = 'all';
      } else {
        activeSeverity = sev;
      }
      document.querySelectorAll('.stat-card').forEach(card => {
        card.classList.toggle('active', card.getAttribute('data-filter') === activeSeverity);
      });
      applyFilters();
    }

    function applyFilters() {
      const input = document.getElementById('filter');
      const q = input ? input.value.toLowerCase().trim() : '';
      const fixableCheckbox = document.getElementById('fixableOnly');
      const fixableOnly = fixableCheckbox ? fixableCheckbox.checked : false;
      const rows = document.querySelectorAll('#vulnTable tbody tr');
      let visible = 0;

      rows.forEach(r => {
        const rowSev = r.getAttribute('data-severity') || '';
        const rowFixable = r.getAttribute('data-fixable') === 'true';
        const textContent = r.innerText.toLowerCase();
        
        const matchesQuery = !q || textContent.includes(q);
        const matchesSev = (activeSeverity === 'all') || (rowSev === activeSeverity);
        const matchesFix = !fixableOnly || rowFixable;

        if (matchesQuery && matchesSev && matchesFix) {
          r.style.display = '';
          visible++;
        } else {
          r.style.display = 'none';
        }
      });

      const counter = document.getElementById('matchCounter');
      if (counter) {
        counter.textContent = "Showing " + visible + " of " + rows.length;
      }
      const emptyState = document.getElementById('emptyState');
      if (emptyState) {
        emptyState.style.display = visible === 0 ? 'block' : 'none';
      }
    }

    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        const f = document.getElementById('filter');
        if (f) f.value = '';
        const fix = document.getElementById('fixableOnly');
        if (fix) fix.checked = false;
        selectSeverity('all');
      }
    });
  </script>
</body>
</html>`

// ServeDashboard starts a local HTTP server and opens the browser.
func ServeDashboard(findings []model.Finding, scanner, sourcePath string) error {
	viewItems := make([]FindingView, 0, len(findings))

	var crit, high, med, low, unk int
	for _, f := range findings {
		sev := f.PrimarySeverity()
		sevStr := string(sev)
		sevClass := strings.ToLower(sevStr)

		switch sev {
		case model.SeverityCritical:
			crit++
		case model.SeverityHigh:
			high++
		case model.SeverityMedium:
			med++
		case model.SeverityLow:
			low++
		default:
			unk++
		}

		vulnID := f.Vulnerability.PreferredID().ID
		if vulnID == "" {
			vulnID = "UNKNOWN"
		}

		fixedVerStr := strings.Join(f.FixedVersions, ", ")

		viewItems = append(viewItems, FindingView{
			Severity:      sevStr,
			SeverityClass: sevClass,
			VulnID:        vulnID,
			PackageName:   f.PackageName,
			InstalledVer:  f.InstalledVersion,
			FixState:      string(f.FixState),
			FixedVersions: fixedVerStr,
			IsFixable:     len(f.FixedVersions) > 0,
		})
	}

	data := DashboardData{
		Scanner:    scanner,
		SourceFile: sourcePath,
		TotalCount: len(findings),
		CritCount:  crit,
		HighCount:  high,
		MedCount:   med,
		LowCount:   low,
		UnkCount:   unk,
		Findings:   viewItems,
	}

	tmpl, err := template.New("dashboard").Parse(dashboardHTML)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("binding port: %w", err)
	}

	url := fmt.Sprintf("http://%s", listener.Addr().String())
	fmt.Printf("\nServing interactive dashboard at %s\nPress Ctrl+C to stop.\n", url)

	openBrowser(url)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, data)
	})

	return http.Serve(listener, mux)
}

func openBrowser(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}

	_ = exec.Command(cmd, args...).Start()
}
