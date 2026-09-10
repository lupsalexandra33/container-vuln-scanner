package report

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

type tuiRow struct {
	severity    string
	vulnID      string
	pkg         string
	version     string
	fixState    string
	confidence  float64
	sources     string
	origin      string
	description string
	conflicts   []string
	verdicts    []model.ScannerVerdict
}

type tuiMeta struct {
	engine string
	source string

	total                                           int
	crit, high, med, low, unk                       int
	rawCount                                        int
	confirmed, disputed, singleSource, withConflict int
}

type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

func getTerminalDimensions() (int, int) {
	ws := winsize{}
	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(syscall.Stdout),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(&ws)),
	)
	cols := int(ws.Col)
	rows := int(ws.Row)
	if err != 0 || cols <= 0 || rows <= 0 {
		return 80, 24
	}
	return cols, rows
}

func RenderTUI(rep Report) error {
	fmt.Print("\033[?1049h\033[?25l\033[2J\033[H")
	defer fmt.Print("\033[?1049l\033[?25h\033[0m\r\n")

	findings := rep.Findings

	var meta tuiMeta
	meta.source = rep.Target
	meta.rawCount = rep.RawFindingCount

	rows := make([]tuiRow, 0, len(findings))
	scannerSet := map[string]bool{}

	for _, f := range findings {
		switch f.Severity {
		case model.SeverityCritical:
			meta.crit++
		case model.SeverityHigh:
			meta.high++
		case model.SeverityMedium:
			meta.med++
		case model.SeverityLow:
			meta.low++
		default:
			meta.unk++
		}

		for _, v := range f.Verdicts {
			scannerSet[v.Scanner] = true
		}

		if len(f.ReportedBy()) > 1 {
			meta.confirmed++
		}
		if f.IsDisputed() {
			meta.disputed++
		}
		if f.IsSingleSource() {
			meta.singleSource++
		}
		if len(f.Conflicts) > 0 {
			meta.withConflict++
		}

		id := f.Vulnerability.PreferredID().ID
		if id == "" {
			id = "UNKNOWN"
		}

		pkgName := f.Package.Name
		if pkgName == "" {
			pkgName = "-"
		}

		in := f.ConfidenceInputs()
		src := fmt.Sprintf("%d/%d %s", in.AgreeingCount, in.ParticipatingCount, strings.Join(f.ReportedBy(), ","))
		if missed := f.RanAndMissedBy(); len(missed) > 0 {
			src += " missed:" + strings.Join(missed, ",")
		}
		if nodata := f.HadNoDataFor(); len(nodata) > 0 {
			src += " nodata:" + strings.Join(nodata, ",")
		}

		originStr := "n/a"
		if f.Origin != nil {
			if f.Origin.LayerIndex >= 0 {
				originStr = fmt.Sprintf("layer #%d", f.Origin.LayerIndex)
				if f.Origin.Instruction != "" {
					originStr += " (" + f.Origin.Instruction + ")"
				}
			} else if f.Origin.LayerDigest != "" {
				originStr = "layer " + f.Origin.LayerDigest
			}
		}

		var conflictLines []string
		for _, c := range f.Conflicts {
			conflictLines = append(conflictLines, formatConflict(c))
		}

		rows = append(rows, tuiRow{
			severity:    string(f.Severity),
			vulnID:      id,
			pkg:         pkgName,
			version:     f.InstalledVersion,
			fixState:    string(f.FixState),
			confidence:  f.Confidence,
			sources:     src,
			origin:      originStr,
			description: f.Description,
			conflicts:   conflictLines,
			verdicts:    f.Verdicts,
		})
	}
	meta.total = len(rows)

	scanners := make([]string, 0, len(scannerSet))
	for s := range scannerSet {
		scanners = append(scanners, s)
	}
	sort.Strings(scanners)
	meta.engine = strings.Join(scanners, "+")
	if meta.engine == "" {
		meta.engine = "unknown"
	}

	// Spinner
	spinnerFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	for i := 0; i < 16; i++ {
		frame := spinnerFrames[i%len(spinnerFrames)]
		fmt.Printf("\r\033[1;36m%s\033[0m  Loading findings from \033[1;35m%s\033[0m...", frame, meta.engine)
		time.Sleep(40 * time.Millisecond)
	}
	fmt.Print("\r\033[2K")

	// Slot machine animation
	steps := 35
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	loadingLabel := "Loading findings"
	if len(scanners) > 1 {
		loadingLabel = fmt.Sprintf("Correlating records from %d scanners", len(scanners))
	}

	for step := 1; step <= steps; step++ {
		progress := float64(step) / float64(steps)
		ease := 1.0 - (1.0-progress)*(1.0-progress)*(1.0-progress)

		curTotal := int(float64(meta.total) * ease)
		curCrit := int(float64(meta.crit) * ease)
		curHigh := int(float64(meta.high) * ease)
		curMed := int(float64(meta.med) * ease)
		curLow := int(float64(meta.low) * ease)
		curUnk := int(float64(meta.unk) * ease)

		if step < steps-3 {
			if curTotal > 5 {
				curTotal += r.Intn(4) - 2
			}
			if curHigh > 3 {
				curHigh += r.Intn(3) - 1
			}
			if curMed > 5 {
				curMed += r.Intn(4) - 2
			}
		} else {
			curTotal = meta.total
			curCrit = meta.crit
			curHigh = meta.high
			curMed = meta.med
			curLow = meta.low
			curUnk = meta.unk
		}

		fmt.Print("\033[H")
		renderHeader(meta.engine, meta.source)
		renderStats(curTotal, curCrit, curHigh, curMed, curLow, curUnk, "ALL")

		barWidth := 28
		filled := int(float64(barWidth) * ease)
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
		fmt.Printf("\r\n  \033[90m%s: \033[1;36m[%s]\033[0m \033[90m%3d%%\033[0m\r\n", loadingLabel, bar, int(progress*100))

		time.Sleep(30 * time.Millisecond)
	}

	time.Sleep(100 * time.Millisecond)

	return runInteractiveLoop(rows, meta)
}

func renderHeader(engine, source string) {
	if len(source) > 34 {
		source = "..." + source[len(source)-31:]
	}
	fmt.Printf(" \033[1;97;45m vulnscan \033[0m \033[1;30;47m TUI \033[0m  \033[90mEngine:\033[0m \033[1;36m%-8s\033[0m \033[90mSource:\033[0m \033[33m%s\033[0m\r\n\r\n", engine, source)
}

func renderStats(total, crit, high, med, low, unk int, activeTab string) {
	fmt.Print("  \033[90m┌──────────────────────┬──────────────────────┬──────────────────────┐\033[0m\r\n")

	fmt.Printf("  \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m\r\n",
		formatCardHeader("1. ALL", activeTab == "ALL"),
		formatCardHeader("2. CRITICAL", activeTab == "CRITICAL"),
		formatCardHeader("3. HIGH", activeTab == "HIGH"),
	)
	fmt.Printf("  \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m\r\n",
		formatCardNumber(total, "\033[1;37m", activeTab == "ALL"),
		formatCardNumber(crit, "\033[1;31m", activeTab == "CRITICAL"),
		formatCardNumber(high, "\033[1;33m", activeTab == "HIGH"),
	)

	fmt.Print("  \033[90m├──────────────────────┼──────────────────────┼──────────────────────┤\033[0m\r\n")

	fmt.Printf("  \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m\r\n",
		formatCardHeader("4. MEDIUM", activeTab == "MEDIUM"),
		formatCardHeader("5. LOW", activeTab == "LOW"),
		formatCardHeader("6. UNKNOWN", activeTab == "UNKNOWN"),
	)
	fmt.Printf("  \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m\r\n",
		formatCardNumber(med, "\033[1;32m", activeTab == "MEDIUM"),
		formatCardNumber(low, "\033[1;34m", activeTab == "LOW"),
		formatCardNumber(unk, "\033[1;90m", activeTab == "UNKNOWN"),
	)

	fmt.Print("  \033[90m└──────────────────────┴──────────────────────┴──────────────────────┘\033[0m\r\n")
}

func formatCardHeader(title string, active bool) string {
	padded := fmt.Sprintf("%-20s", title)
	if active {
		return fmt.Sprintf("\033[1;30;47m%s\033[0m", padded)
	}
	return fmt.Sprintf("\033[1;90m%s\033[0m", padded)
}

func formatCardNumber(count int, colorCode string, active bool) string {
	numStr := fmt.Sprintf("%-20d", count)
	if active {
		return fmt.Sprintf("\033[48;5;18;1;97m%s\033[0m", numStr)
	}
	return fmt.Sprintf("%s%s\033[0m", colorCode, numStr)
}

func formatConfidenceMeter(conf float64) string {
	filled := int(conf*5.0 + 0.5)
	if filled > 5 {
		filled = 5
	}
	if filled < 0 {
		filled = 0
	}
	bar := strings.Repeat("▰", filled) + strings.Repeat("▱", 5-filled)

	var color string
	switch {
	case conf >= 0.80:
		color = "\033[1;32m" // Green
	case conf >= 0.50:
		color = "\033[1;33m" // Yellow
	default:
		color = "\033[1;31m" // Red
	}
	return fmt.Sprintf("%s%s %.2f\033[0m", color, bar, conf)
}

func formatConflict(c model.Conflict) string {
	vals := make([]string, 0, len(c.Values))
	for scanner, v := range c.Values {
		vals = append(vals, fmt.Sprintf("%s=%s", scanner, v))
	}
	sort.Strings(vals)

	reason := c.Reason
	if reason == "" {
		reason = "no reason recorded"
	}
	return fmt.Sprintf("%s → %q (%s) [reported: %s]", c.Kind, c.Resolved, reason, strings.Join(vals, ", "))
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func runInteractiveLoop(allRows []tuiRow, meta tuiMeta) error {
	_ = exec.Command("sh", "-c", "stty raw -echo < /dev/tty").Run()
	defer func() {
		_ = exec.Command("sh", "-c", "stty sane < /dev/tty").Run()
	}()

	activeTab := "ALL"
	searchQuery := ""
	cursor := 0
	scrollOffset := 0
	isDrawerOpen := false

	reader := bufio.NewReader(os.Stdin)

	for {
		cols, termRows := getTerminalDimensions()

		// Filter rows
		filtered := make([]tuiRow, 0, len(allRows))
		for _, r := range allRows {
			matchesTab := activeTab == "ALL" || strings.ToUpper(r.severity) == activeTab
			matchesSearch := searchQuery == "" ||
				strings.Contains(strings.ToLower(r.vulnID), searchQuery) ||
				strings.Contains(strings.ToLower(r.pkg), searchQuery)

			if matchesTab && matchesSearch {
				filtered = append(filtered, r)
			}
		}

		if cursor >= len(filtered) {
			cursor = len(filtered) - 1
		}
		if cursor < 0 {
			cursor = 0
		}
		if cursor < scrollOffset {
			scrollOffset = cursor
		}

		// Fixed vertical overhead:
		// Header (3) + Stats box (8) + Summary (2) + Filter (3) + Col Header & line (2) + Footer (2) = 20 lines
		fixedOverhead := 18
		if meta.rawCount > 0 && meta.rawCount != meta.total {
			fixedOverhead += 2
		}
		if isDrawerOpen {
			fixedOverhead += 9 // Space reserved for the inspector box
		}

		maxTableLines := termRows - fixedOverhead
		if maxTableLines < 4 {
			maxTableLines = 4
		}

		// Calculate visible items based on REAL rendered lines (including ↳ conflict rows)
		visibleCount := 0
		linesUsed := 0
		for i := scrollOffset; i < len(filtered); i++ {
			rowLines := 1
			if !isDrawerOpen {
				// Each conflict takes 1 additional line
				rowLines += len(filtered[i].conflicts)
			}
			if linesUsed+rowLines > maxTableLines && visibleCount > 0 {
				break
			}
			linesUsed += rowLines
			visibleCount++
		}

		if cursor >= scrollOffset+visibleCount {
			scrollOffset = cursor - visibleCount + 1
			if scrollOffset < 0 {
				scrollOffset = 0
			}
		}

		var b strings.Builder
		// Clear screen and reset cursor to (1,1)
		b.WriteString("\033[H\033[2J")

		// 1. Header
		source := meta.source
		if len(source) > 30 {
			source = "..." + source[len(source)-27:]
		}
		b.WriteString(fmt.Sprintf(" \033[1;97;45m vulnscan \033[0m \033[1;30;47m TUI \033[0m  \033[90mEngine:\033[0m \033[1;36m%-8s\033[0m \033[90mSource:\033[0m \033[33m%s\033[0m\r\n\r\n", meta.engine, source))

		// 2. Stats box
		b.WriteString("  \033[90m┌──────────────────────┬──────────────────────┬──────────────────────┐\033[0m\r\n")
		b.WriteString(fmt.Sprintf("  \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m\r\n",
			formatCardHeader("1. ALL", activeTab == "ALL"),
			formatCardHeader("2. CRITICAL", activeTab == "CRITICAL"),
			formatCardHeader("3. HIGH", activeTab == "HIGH"),
		))
		b.WriteString(fmt.Sprintf("  \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m\r\n",
			formatCardNumber(meta.total, "\033[1;37m", activeTab == "ALL"),
			formatCardNumber(meta.crit, "\033[1;31m", activeTab == "CRITICAL"),
			formatCardNumber(meta.high, "\033[1;33m", activeTab == "HIGH"),
		))
		b.WriteString("  \033[90m├──────────────────────┼──────────────────────┼──────────────────────┤\033[0m\r\n")
		b.WriteString(fmt.Sprintf("  \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m\r\n",
			formatCardHeader("4. MEDIUM", activeTab == "MEDIUM"),
			formatCardHeader("5. LOW", activeTab == "LOW"),
			formatCardHeader("6. UNKNOWN", activeTab == "UNKNOWN"),
		))
		b.WriteString(fmt.Sprintf("  \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m\r\n",
			formatCardNumber(meta.med, "\033[1;32m", activeTab == "MEDIUM"),
			formatCardNumber(meta.low, "\033[1;34m", activeTab == "LOW"),
			formatCardNumber(meta.unk, "\033[1;90m", activeTab == "UNKNOWN"),
		))
		b.WriteString("  \033[90m└──────────────────────┴──────────────────────┴──────────────────────┘\033[0m\r\n")

		// 3. Summary line
		if meta.rawCount > 0 && meta.rawCount != meta.total {
			b.WriteString(fmt.Sprintf("\r\n \033[90mraw: %d → consolidated: %d | confirmed: %d | disputed: %d | conflicts: %d\033[0m\r\n",
				meta.rawCount, meta.total, meta.confirmed, meta.disputed, meta.withConflict))
		}

		filterDisplay := activeTab
		if searchQuery != "" {
			filterDisplay += fmt.Sprintf(" | Search: \033[1;33m%s\033[0m", searchQuery)
		}

		b.WriteString(fmt.Sprintf("\r\n \033[1;37;44m FINDINGS \033[0m \033[90m(%d/%d) | Filter: \033[1;36m%s\033[0m\r\n\r\n",
			len(filtered), meta.total, filterDisplay))

		// 4. Column headers
		b.WriteString(fmt.Sprintf("   \033[1;90m%-5s %-16s %-13s %-9s %-9s %-11s %s\033[0m\r\n",
			"SEV", "VULNERABILITY", "PACKAGE", "INSTALLED", "STATUS", "CONF", "SOURCES"))
		b.WriteString("  \033[90m─────────────────────────────────────────────────────────────────────────────\033[0m\r\n")

		// 5. Table rows
		if len(filtered) == 0 {
			b.WriteString("\r\n              \033[90mNo vulnerabilities match the current filter.\033[0m\r\n\r\n")
		} else {
			currentLines := 0
			for i := scrollOffset; i < len(filtered); i++ {
				r := filtered[i]
				rowLines := 1
				if !isDrawerOpen {
					rowLines += len(r.conflicts)
				}

				if currentLines+rowLines > maxTableLines && i > scrollOffset {
					break
				}
				currentLines += rowLines

				isSelected := (i == cursor)
				pkg := truncateStr(r.pkg, 13)
				ver := truncateStr(r.version, 9)
				sources := truncateStr(r.sources, 18)
				sevTag := colorSeverityPill(r.severity)
				confBar := formatConfidenceMeter(r.confidence)

				if isSelected {
					b.WriteString(fmt.Sprintf(" \033[1;36m❯\033[0m \033[48;5;18;1;97m%-5s %-16s %-13s %-9s %-9s %s %-18s\033[0m\r\n",
						truncateStr(r.severity, 5), r.vulnID, pkg, ver, r.fixState, confBar, sources))
				} else {
					b.WriteString(fmt.Sprintf("   %-5s \033[37m%-16s\033[0m \033[90m%-13s\033[0m \033[90m%-9s\033[0m \033[90m%-9s\033[0m %s \033[90m%s\033[0m\r\n",
						sevTag, r.vulnID, pkg, ver, r.fixState, confBar, sources))
				}

				if !isDrawerOpen {
					for _, cl := range r.conflicts {
						b.WriteString(fmt.Sprintf("       \033[2;33m↳ %s\033[0m\r\n", truncateStr(cl, cols-10)))
					}
				}
			}
		}

		// 6. Inspector Drawer
		if isDrawerOpen && len(filtered) > 0 && cursor < len(filtered) {
			curFinding := filtered[cursor]
			headerDashes := cols - len(curFinding.vulnID) - 22
			if headerDashes < 4 {
				headerDashes = 4
			}
			b.WriteString("\r\n  \033[1;36m┌── [INSPECTOR: " + curFinding.vulnID + "] " + strings.Repeat("─", headerDashes) + "┐\033[0m\r\n")

			pkgInfo := truncateStr(curFinding.pkg+"@"+curFinding.version, 24)
			originInfo := truncateStr(curFinding.origin, cols-38)
			b.WriteString(fmt.Sprintf("  \033[1;36m│\033[0m \033[1;37mPackage:\033[0m %-24s \033[1;37mOrigin:\033[0m \033[33m%s\033[0m\r\n",
				pkgInfo, originInfo))

			desc := curFinding.description
			if desc == "" {
				desc = "No description available."
			}
			b.WriteString(fmt.Sprintf("  \033[1;36m│\033[0m \033[90mDesc:\033[0m %s\r\n", truncateStr(desc, cols-12)))

			if len(curFinding.conflicts) > 0 {
				b.WriteString("  \033[1;36m│\033[0m \033[1;33mResolved Conflicts:\033[0m\r\n")
				for idx, cf := range curFinding.conflicts {
					if idx >= 2 {
						b.WriteString(fmt.Sprintf("  \033[1;36m│\033[0m   \033[90m... and %d more conflicts\033[0m\r\n", len(curFinding.conflicts)-2))
						break
					}
					b.WriteString(fmt.Sprintf("  \033[1;36m│\033[0m   \033[33m•\033[0m %s\r\n", truncateStr(cf, cols-12)))
				}
			} else {
				b.WriteString("  \033[1;36m│\033[0m \033[90mConsensus:\033[0m \033[32mNo scanner conflicts recorded for this finding.\033[0m\r\n")
			}

			footerDashes := cols - 5
			if footerDashes < 4 {
				footerDashes = 4
			}
			b.WriteString("  \033[1;36m└" + strings.Repeat("─", footerDashes) + "┘\033[0m\r\n")
		}

		drawerHint := "[Enter] Inspect"
		if isDrawerOpen {
			drawerHint = "[Enter] Close"
		}
		b.WriteString(fmt.Sprintf("\r\n \033[90m[↑/↓] Move  [1-6] Filter  %s  [/] Search  [c] Reset  [q] Quit\033[0m\r\n", drawerHint))

		// Atomic flush to screen
		os.Stdout.WriteString(b.String())

		byteIn, err := reader.ReadByte()
		if err != nil {
			break
		}

		switch byteIn {
		case 'q', 3:
			return nil
		case 13, 10, ' ':
			isDrawerOpen = !isDrawerOpen
		case 'j':
			cursor++
		case 'k':
			cursor--
		case '1':
			activeTab = "ALL"
			cursor = 0
			scrollOffset = 0
		case '2':
			activeTab = "CRITICAL"
			cursor = 0
			scrollOffset = 0
		case '3':
			activeTab = "HIGH"
			cursor = 0
			scrollOffset = 0
		case '4':
			activeTab = "MEDIUM"
			cursor = 0
			scrollOffset = 0
		case '5':
			activeTab = "LOW"
			cursor = 0
			scrollOffset = 0
		case '6':
			activeTab = "UNKNOWN"
			cursor = 0
			scrollOffset = 0
		case 'c':
			searchQuery = ""
			activeTab = "ALL"
			cursor = 0
			scrollOffset = 0
		case '/':
			fmt.Print("\033[?25h\r\n\r\n  \033[1;36mSearch:\033[0m ")
			_ = exec.Command("sh", "-c", "stty sane < /dev/tty").Run()
			scannerInput := bufio.NewScanner(os.Stdin)
			if scannerInput.Scan() {
				searchQuery = strings.ToLower(strings.TrimSpace(scannerInput.Text()))
			}
			_ = exec.Command("sh", "-c", "stty raw -echo < /dev/tty").Run()
			fmt.Print("\033[?25l")
			cursor = 0
			scrollOffset = 0
		case 27:
			if reader.Buffered() > 0 {
				b1, _ := reader.ReadByte()
				if reader.Buffered() > 0 {
					b2, _ := reader.ReadByte()
					if b1 == '[' || b1 == 'O' {
						switch b2 {
						case 'A':
							cursor--
						case 'B':
							cursor++
						}
					}
				}
			}
		}
	}

	return nil
}

func colorSeverityPill(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "\033[1;31mcrit\033[0m"
	case "HIGH":
		return "\033[1;33mhigh\033[0m"
	case "MEDIUM":
		return "\033[1;32mmed \033[0m"
	case "LOW":
		return "\033[1;34mlow \033[0m"
	default:
		return "\033[90munk \033[0m"
	}
}

