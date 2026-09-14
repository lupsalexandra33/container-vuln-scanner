# Policy Engine & CI/CD Gating (`pkg/policy`)

The `vulnscan` policy engine evaluates consolidated vulnerability findings against admission rules. Rather than applying a naive pass/fail filter on raw scanner counts, it evaluates actionable, corroborated, and exploit-enriched findings to provide deterministic go/no-go gates for CI/CD pipelines.

---

## 1. Core Principles & Motivation

Traditional scanner gates often fail on base image debt that cannot be fixed (for example, on `debian:11` all 243 consolidated findings have no available fix—162 with no fix published, 60 marked `wont_fix`). A gate that trips on unfixable debt blocks teams on work they cannot do, leading to alert fatigue and bypassed security checks.

The `vulnscan` policy engine operates on three foundational principles:
1. **Actionability over theoretical debt:** Fixable vulnerabilities with patches (`HasFix: true`) are prioritized over dead ends (`wont_fix`, `unavailable`).
2. **Tri-state outcomes (`pass`, `warn`, `fail`):** Findings are not forced into a binary pass/fail; unfixable severe findings and disputed criticals are categorized as `warn`, surfacing visibility without breaking the pipeline.
3. **No negative inference on missing data:** When running offline without telemetry (`Enrichment == nil`), conditions like `InKEV: false` do not match. Absence of telemetry is treated as unknown, preventing un-enriched scans from silently bypassing gates.

---

## 2. CLI Usage

To evaluate a policy during a scan, pass `--policy <name>` **before** positional arguments:

```bash
# Evaluate against recorded fixtures (default: balanced)
./bin/vulnscan scan --policy balanced --from testdata/fixtures/debian_11

# Evaluate in strict mode
./bin/vulnscan scan --policy strict --from testdata/fixtures/debian_11

# Evaluate in advisory mode (never breaks CI)
./bin/vulnscan scan --policy advisory --from testdata/fixtures/debian_11

# Live container scan
./bin/vulnscan scan --policy balanced debian:11-slim
```

### Exit Codes

`Outcome.ExitCode()` maps decisions to standard process exit statuses:
* **`0` (`PASS` or `WARN`):** All findings satisfied policy constraints or were non-blocking warnings. The pipeline proceeds.
* **`1` (`FAIL`):** One or more findings triggered a `Fail` rule. The pipeline gate is tripped.
* **`2` (`ERROR`):** Execution error (invalid CLI flags, unrecognized policy name, or unreadable inputs).

---

## 3. Built-In Policies

`vulnscan` ships with three built-in policies: `advisory`, `balanced`, and `strict`.

### `balanced` (Default)
Blocks only on severe findings a team can act upon, and warns on the rest.

| Rule Name | Outcome | Conditions | Intent / Rationale |
| :--- | :---: | :--- | :--- |
| `actively exploited with a fix` | **FAIL** | `InKEV: true`, `HasFix: true` | Confirmed actively exploited in real attacks with an available patch. |
| `critical, fixable, and corroborated` | **FAIL** | `MinSeverity: CRITICAL`, `HasFix: true`, `MinConfidence: >= 0.6` | Actionable, critical severity confirmed across capable scanners. |
| `high likelihood of exploitation with a fix` | **FAIL** | `MinEPSS: >= 0.50`, `HasFix: true` | Better than 50% probability of near-term exploit with an available patch. |
| `actively exploited, no fix available` | **WARN** | `InKEV: true`, `HasFix: false` | Confirmed exploited but unfixable; alerts for mitigation without blocking builds. |
| `critical or high with a fix` | **WARN** | `MinSeverity: HIGH`, `HasFix: true` | Serious and actionable, but without telemetry proving active exploitation. |
| `severe with no fix` | **WARN** | `MinSeverity: HIGH`, `HasFix: false` | Severe unfixable debt (e.g., EOL base distro); addressed by base image rebasing. |
| `disputed critical finding` | **WARN** | `MinSeverity: CRITICAL`, `MinConfidence: 0` | Surfaced regardless of scanner consensus or fix state. |

---

### `strict`
Intended for production builds where base images and dependencies are actively maintained by the team.

| Rule Name | Outcome | Conditions | Intent / Rationale |
| :--- | :---: | :--- | :--- |
| `actively exploited` | **FAIL** | `InKEV: true` | Blocks on any vulnerability weaponized in the wild, regardless of fix availability. |
| `critical or high with a fix` | **FAIL** | `MinSeverity: HIGH`, `HasFix: true` | Blocks on any actionable severe vulnerability. |
| `any exploitation probability above 10%` | **FAIL** | `MinEPSS: >= 0.10`, `HasFix: true` | Blocks on any fixable CVE with measurable exploitation likelihood. |
| `severe with no fix` | **WARN** | `MinSeverity: HIGH`, `HasFix: false` | Warns on unfixable severe vulnerabilities rather than halting work. |
| `medium severity` | **WARN** | `MinSeverity: MEDIUM` | Tracked for triage visibility. |

---

### `advisory`
Never blocks a pipeline (`Outcome.ExitCode() == 0` for all findings). Used for auditing environments or introducing vulnerability tracking into legacy repositories.

| Rule Name | Outcome | Conditions | Intent / Rationale |
| :--- | :---: | :--- | :--- |
| `actively exploited` | **WARN** | `InKEV: true` | Confirmed exploited in the wild. |
| `severe` | **WARN** | `MinSeverity: HIGH` | High and Critical findings surfaced for visibility only. |

---

## 4. Evaluation Semantics

* **Non-Short-Circuit Evaluation:** Findings are evaluated against every rule in the policy. If a finding satisfies multiple rules, all matching rules are recorded in `Decision.Matches`, and the finding assumes the most severe outcome (`Fail` > `Warn` > `Pass`).
* **Overall Decision:** The scan decision reflects the worst outcome across all evaluated findings: if any finding produces a `Fail`, the overall scan outcome is `Fail`.
* **Exceptions & Risk Acceptance:** Findings matching an `Exception` (by CVE ID or package name) are silenced from failing/warning and recorded in `Decision.Suppressed` along with the stated business reason and expiry date.
* **Alias Resolution Support:** Exceptions written against a CVE ID automatically suppress findings even if scanners reported them under an alternate alias (e.g., GHSA).