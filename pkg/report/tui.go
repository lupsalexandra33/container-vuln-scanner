package report

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

type tuiRow struct {
	severity string
	vulnID   string
	pkg      string
	version  string
	fixState string
}

// RenderTUI executes the startup animation sequence and enters the interactive browser.
func RenderTUI(findings []model.Finding, scanner, sourcePath string) error {
	// Hide cursor and clear screen
	fmt.Print("\033[?25l\033[2J\033[H")
	defer fmt.Print("\033[?25h\033[0m\r\n")

	// Pre-calculate counts and prepare rows
	var crit, high, med, low, unk int
	rows := make([]tuiRow, 0, len(findings))
	for _, f := range findings {
		sev := f.PrimarySeverity()
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

		id := f.Vulnerability.PreferredID().ID
		if id == "" {
			id = "UNKNOWN"
		}

		rows = append(rows, tuiRow{
			severity: string(sev),
			vulnID:   id,
			pkg:      f.PackageName,
			version:  f.InstalledVersion,
			fixState: string(f.FixState),
		})
	}
	total := len(rows)

	// 1. Sleek Braille Spinner
	spinnerFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	for i := 0; i < 20; i++ {
		frame := spinnerFrames[i%len(spinnerFrames)]
		fmt.Printf("\r\033[1;36m%s\033[0m  Ingesting scanner AST from \033[1;35m%s\033[0m...", frame, scanner)
		time.Sleep(45 * time.Millisecond)
	}
	fmt.Print("\r\033[2K")

	// 2. Smooth "Slot Machine" Rolling Counter Animation
	// 45 steps * 35ms = ~1.6s smooth reveal
	steps := 45
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for step := 1; step <= steps; step++ {
		progress := float64(step) / float64(steps)
		// Ease-out cubic curve for natural decelerating momentum
		ease := 1.0 - (1.0-progress)*(1.0-progress)*(1.0-progress)

		curTotal := int(float64(total) * ease)
		curCrit := int(float64(crit) * ease)
		curHigh := int(float64(high) * ease)
		curMed := int(float64(med) * ease)
		curLow := int(float64(low) * ease)
		curUnk := int(float64(unk) * ease)

		// Introduce subtle mechanical digit jitter before snapping in place
		if step < steps-4 {
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
			curTotal = total
			curCrit = crit
			curHigh = high
			curMed = med
			curLow = low
			curUnk = unk
		}

		fmt.Print("\033[H")
		renderHeader(scanner, sourcePath)
		renderStats(curTotal, curCrit, curHigh, curMed, curLow, curUnk, "ALL")

		// Render animated progress bar underneath
		barWidth := 28
		filled := int(float64(barWidth) * ease)
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
		fmt.Printf("\r\n  \033[90mCorrelating records: \033[1;36m[%s]\033[0m \033[90m%3d%%\033[0m\r\n", bar, int(progress*100))

		time.Sleep(35 * time.Millisecond)
	}

	// 3. Brief settling pause
	time.Sleep(150 * time.Millisecond)

	// 4. Launch Interactive Terminal UI Loop
	return runInteractiveLoop(rows, scanner, sourcePath, total, crit, high, med, low, unk)
}

func renderHeader(scanner, source string) {
	if len(source) > 34 {
		source = "..." + source[len(source)-31:]
	}
	fmt.Printf(" \033[1;97;45m vulnscan \033[0m \033[1;30;47m TUI \033[0m  \033[90mEngine:\033[0m \033[1;36m%-8s\033[0m \033[90mSource:\033[0m \033[33m%s\033[0m\r\n\r\n", scanner, source)
}

func renderStats(total, crit, high, med, low, unk int, activeTab string) {
	// Total width: 68 characters, strictly aligned with \r\n
	fmt.Print("  \033[90m┌──────────────────────┬──────────────────────┬──────────────────────┐\033[0m\r\n")

	// Top Headers
	fmt.Printf("  \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m\r\n",
		formatCardHeader("1. ALL", activeTab == "ALL"),
		formatCardHeader("2. CRITICAL", activeTab == "CRITICAL"),
		formatCardHeader("3. HIGH", activeTab == "HIGH"),
	)
	// Top Numbers
	fmt.Printf("  \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m\r\n",
		formatCardNumber(total, "\033[1;37m", activeTab == "ALL"),
		formatCardNumber(crit, "\033[1;31m", activeTab == "CRITICAL"),
		formatCardNumber(high, "\033[1;33m", activeTab == "HIGH"),
	)

	fmt.Print("  \033[90m├──────────────────────┼──────────────────────┼──────────────────────┤\033[0m\r\n")

	// Bottom Headers
	fmt.Printf("  \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m %s \033[90m│\033[0m\r\n",
		formatCardHeader("4. MEDIUM", activeTab == "MEDIUM"),
		formatCardHeader("5. LOW", activeTab == "LOW"),
		formatCardHeader("6. UNKNOWN", activeTab == "UNKNOWN"),
	)
	// Bottom Numbers
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

func runInteractiveLoop(allRows []tuiRow, scanner, source string, total, crit, high, med, low, unk int) error {
	_ = exec.Command("sh", "-c", "stty raw -echo < /dev/tty").Run()
	defer func() {
		_ = exec.Command("sh", "-c", "stty sane < /dev/tty").Run()
	}()

	activeTab := "ALL"
	searchQuery := ""
	cursor := 0
	scrollOffset := 0
	pageSize := 10

	reader := bufio.NewReader(os.Stdin)

	for {
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
		if cursor >= scrollOffset+pageSize {
			scrollOffset = cursor - pageSize + 1
		}

		fmt.Print("\033[H\033[2J")
		renderHeader(scanner, source)
		renderStats(total, crit, high, med, low, unk, activeTab)

		filterDisplay := activeTab
		if searchQuery != "" {
			filterDisplay += fmt.Sprintf(" | Search: \033[1;33m%s\033[0m", searchQuery)
		}

		fmt.Printf("\r\n \033[1;37;44m FINDINGS \033[0m \033[90m(%d/%d) | Filter: \033[1;36m%s\033[0m\r\n\r\n",
			len(filtered), total, filterDisplay)

		// Column headers - strictly 3 leading spaces
		fmt.Printf("   \033[1;90m%-8s %-17s %-16s %-11s %-10s\033[0m\r\n", "SEV", "VULNERABILITY", "PACKAGE", "INSTALLED", "STATUS")
		fmt.Print("  \033[90m──────────────────────────────────────────────────────────────────\033[0m\r\n")

		if len(filtered) == 0 {
			fmt.Print("\r\n              \033[90mNo vulnerabilities match the current filter.\033[0m\r\n\r\n")
		} else {
			for i := scrollOffset; i < scrollOffset+pageSize && i < len(filtered); i++ {
				r := filtered[i]
				isSelected := (i == cursor)

				pkg := r.pkg
				if len(pkg) > 16 {
					pkg = pkg[:13] + "..."
				}
				ver := r.version
				if len(ver) > 11 {
					ver = ver[:9] + ".."
				}

				sevTag := colorSeverityPill(r.severity)

				if isSelected {
					// 1 space + marker '❯' (1 col) + 1 space = exactly 3 chars, matching "   "
					fmt.Printf(" \033[1;36m❯\033[0m \033[48;5;18;1;97m%-8s %-17s %-16s %-11s %-10s\033[0m\r\n",
						r.severity, r.vulnID, pkg, ver, r.fixState)
				} else {
					// Exactly 3 spaces so columns align with the cursor row above and below
					fmt.Printf("   %-8s \033[37m%-17s\033[0m \033[90m%-16s\033[0m \033[90m%-11s\033[0m \033[90m%-10s\033[0m\r\n",
						sevTag, r.vulnID, pkg, ver, r.fixState)
				}
			}
		}

		fmt.Print("\r\n \033[90m[↑/↓] Move  [1-6] Filter  [/] Search  [c] Reset  [q] Quit\033[0m\r\n")

		b, err := reader.ReadByte()
		if err != nil {
			break
		}

		switch b {
		case 'q', 3: // 'q' or Ctrl+C
			return nil
		case 'j':
			cursor++
		case 'k':
			cursor--
		case '1':
			activeTab = "ALL"
			cursor = 0
		case '2':
			activeTab = "CRITICAL"
			cursor = 0
		case '3':
			activeTab = "HIGH"
			cursor = 0
		case '4':
			activeTab = "MEDIUM"
			cursor = 0
		case '5':
			activeTab = "LOW"
			cursor = 0
		case '6':
			activeTab = "UNKNOWN"
			cursor = 0
		case 'c':
			searchQuery = ""
			activeTab = "ALL"
			cursor = 0
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
		case 27: // Arrow keys
			if reader.Buffered() >= 2 {
				b1, _ := reader.ReadByte()
				b2, _ := reader.ReadByte()
				if b1 == '[' || b1 == 'O' {
					switch b2 {
					case 'A': // UP
						cursor--
					case 'B': // DOWN
						cursor++
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

