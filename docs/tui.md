# Terminal User Interface (TUI) Reference

`vulnscan` features an interactive, low-level terminal UI designed to explore, filter, and inspect correlated vulnerability findings without third-party runtime dependencies.

---

## 1. Quick Invocation

Launch the TUI from recorded scan fixtures:

```bash
./bin/vulnscan scan --from testdata/fixtures/debian_11 --out tui
```

Launch the TUI on a single normalized scanner file:

```bash
./bin/vulnscan normalize -file testdata/fixtures/debian_11/grype.json -out tui
```

---

## 2. Keyboard Navigation

The interface uses standard modal terminal navigation bindings:

| Key Binding | Action | Description |
| :--- | :--- | :--- |
| `↑` / `k` | **Cursor Up** | Select previous vulnerability in the table |
| `↓` / `j` | **Cursor Down** | Select next vulnerability in the table |
| `Enter` / `Space` | **Toggle Inspector** | Open / collapse the detail drawer for the active row |
| `1` | **Tab: ALL** | Show all consolidated vulnerabilities |
| `2` | **Tab: CRITICAL** | Filter to vulnerabilities resolved as `CRITICAL` |
| `3` | **Tab: HIGH** | Filter to vulnerabilities resolved as `HIGH` |
| `4` | **Tab: MEDIUM** | Filter to vulnerabilities resolved as `MEDIUM` |
| `5` | **Tab: LOW** | Filter to vulnerabilities resolved as `LOW` |
| `6` | **Tab: UNKNOWN** | Filter to vulnerabilities resolved as `UNKNOWN` |
| `/` | **Interactive Search** | Filter rows by CVE ID or package name in real-time |
| `c` | **Reset Filters** | Clear the active search string and reset filter tab to `ALL` |
| `q` / `Ctrl+C` | **Exit** | Restore terminal settings and exit cleanly |

---

## 3. UI Components & Layout Anatomy

```text
 ┌────────────────────────────────────────────────────────────────────────────┐
 │  vulnscan  TUI   Engine: grype+trivy+osv  Source: testdata/fixtures/deb_11 │
 ├────────────────────────────────────────────────────────────────────────────┤
 │ ┌──────────────────┬──────────────────┬──────────────────┐                │
 │ │ 1. ALL           │ 2. CRITICAL      │ 3. HIGH          │                │
 │ │ 243              │ 10               │ 37               │                │
 │ ├──────────────────┼──────────────────┼──────────────────┤                │
 │ │ 4. MEDIUM        │ 5. LOW           │ 6. UNKNOWN       │                │
 │ │ 78               │ 98               │ 20               │                │
 │ └──────────────────┴──────────────────┴──────────────────┘                │
 │ raw: 433 → consolidated: 243 | confirmed: 190 | disputed: 53 | conflicts: 168│
 ├────────────────────────────────────────────────────────────────────────────┤
 │ SEV   VULNERABILITY    PACKAGE      STATUS    CONF        SOURCES          │
 │ ────────────────────────────────────────────────────────────────────────── │
 │❯crit  CVE-2019-8457    libdb5.3     wont_fix  ▰▰▰▰▰ 1.00  2/2 grype,trivy  │
 │ med   CVE-2023-4813    libc6        wont_fix  ▰▰▰▰▰ 1.00  2/2 grype,trivy  │
 ├────────────────────────────────────────────────────────────────────────────┤
 │ ┌── [INSPECTOR: CVE-2019-8457] ──────────────────────────────────────────┐ │
 │ │ Package: libdb5.3@5.3.28    Origin: layer #2 (RUN apt-get update...)   │ │
 │ │ Desc: Memory corruption in Berkeley DB...                              │ │
 │ │ Resolved Conflicts:                                                    │ │
 │ │   • severity → "critical" (debian is authoritative for deb packages)   │ │
 │ └────────────────────────────────────────────────────────────────────────┘ │
 │ [↑/↓] Move  [1-6] Filter  [Enter] Close  [/] Search  [c] Reset  [q] Quit    │
 └────────────────────────────────────────────────────────────────────────────┘
```

### Visual Confidence Meters (`CONF`)
Confidence is rendered as a 5-segment indicator representing consensus reliability:
* `▰▰▰▰▰ 1.00` (Green): Multi-scanner corroboration or authoritative vendor alignment.
* `▰▰▰▱▱ 0.60` (Yellow): Partial consensus or scanner disagreements.
* `▰▱▱▱▱ 0.20` (Red): Single-source or disputed finding.

### Expandable Inspector Drawer
Pressing `Enter` or `Space` opens a dedicated pane directly beneath the table displaying:
* **Package Coordinates**: Canonical package name and installed version.
* **Layer Provenance**: Specific OCI container layer index or instruction digest (`pkg/layers`).
* **Conflict Resolution Rationale**: Exact justification for why a specific rating was chosen over dissenting scanner outputs (e.g., authoritative distribution tracker vs. generic NVD).

---

## 4. Systems-Level Engineering

The TUI implementation (`pkg/report/tui.go`) adheres to strict systems-level constraints:
* **Zero External Dependencies**: Built entirely using standard library packages (`syscall`, `unsafe`, `os`, `fmt`).
* **Alternate Screen Buffer**: Enters `\033[?1049h` on launch and restores `\033[?1049l` on exit, preventing any pollution of the user's terminal scrollback history.
* **Dynamic Sizing via `ioctl`**: Issues `syscall.SYS_IOCTL` with `TIOCGWINSZ` on stdout to dynamically read terminal column and row bounds.
* **Vertical Line-Budgeting**: Accounts for multi-line conflict rows (`↳`) within the table height calculations, ensuring top summary stat cards remain anchored without being pushed off-screen.
* **Atomic Frame Buffering**: Builds each frame entirely in an in-memory `strings.Builder` and flushes it in a single write operation, preventing screen tearing and flicker.