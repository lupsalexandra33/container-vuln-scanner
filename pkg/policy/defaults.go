package policy

import "github.com/lupsalexandra33/container-vuln-scanner/pkg/model"

// Balanced is the default policy.
//
// It blocks only on findings a team can act on, and warns on everything else.
// The distinction matters more than it sounds: on debian:11 all 243
// consolidated findings are unfixable — 162 with no fix published, 60 the
// maintainer will not fix — and 10 of them are critical. A policy that failed
// on any critical finding would block every build of that image on work nobody
// can do, and would be switched off within a week.
//
// What survives that filter is small. That is the point: a gate that fires on
// five things people fix is worth more than one that fires on two hundred they
// ignore.
func Balanced() Policy {
	return Policy{
		Name: "balanced",
		Rules: []Rule{
			{
				Name: "actively exploited with a fix",
				Condition: Condition{
					InKEV:  boolPtr(true),
					HasFix: boolPtr(true),
				},
				Outcome: Fail,
				Reason: "CISA has confirmed this is being exploited in real attacks and a " +
					"fixed version exists — this is the shortest path from a report to an incident",
			},
			{
				Name: "critical, fixable, and corroborated",
				Condition: Condition{
					MinSeverity:   model.SeverityCritical,
					HasFix:        boolPtr(true),
					MinConfidence: 0.6,
				},
				Outcome: Fail,
				Reason: "severe, actionable, and reported by enough of the scanners that could " +
					"have seen it that it is unlikely to be an artefact of one tool's matching",
			},
			{
				Name: "high likelihood of exploitation with a fix",
				Condition: Condition{
					MinEPSS: 0.5,
					HasFix:  boolPtr(true),
				},
				Outcome: Fail,
				Reason: "EPSS estimates a better-than-even chance of exploitation in the near " +
					"term, and there is something to upgrade to",
			},

			{
				Name: "actively exploited, no fix available",
				Condition: Condition{
					InKEV:  boolPtr(true),
					HasFix: boolPtr(false),
				},
				Outcome: Warn,
				Reason: "confirmed exploited but unfixable — worth knowing about and worth " +
					"mitigating around, but not something a build can be blocked on",
			},
			{
				Name: "critical or high with a fix",
				Condition: Condition{
					MinSeverity: model.SeverityHigh,
					HasFix:      boolPtr(true),
				},
				Outcome: Warn,
				Reason:  "actionable and serious, but with no evidence of exploitation",
			},
			{
				Name: "severe with no fix",
				Condition: Condition{
					MinSeverity: model.SeverityHigh,
					HasFix:      boolPtr(false),
				},
				Outcome: Warn,
				Reason: "severe but unfixable — the dominant case on an end-of-life " +
					"distribution, where none of the 243 consolidated findings on debian:11 " +
					"has a fix available. The answer is to change base image rather than to " +
					"patch, and a build cannot be blocked on that",
			},
			{
				Name: "disputed critical finding",
				Condition: Condition{
					MinSeverity:   model.SeverityCritical,
					MinConfidence: 0,
				},
				Outcome: Warn,
				Reason:  "critical severity, surfaced regardless of fix state or agreement",
			},
		},
	}
}

// Strict blocks on anything severe and actionable, and warns on severe findings
// that are not.
//
// Appropriate where the base image is under the team's control and moving off
// an end-of-life distribution is a thing they can actually do. On an image they
// cannot change, this fails every build and teaches people to bypass it.
func Strict() Policy {
	return Policy{
		Name: "strict",
		Rules: []Rule{
			{
				Name:      "actively exploited",
				Condition: Condition{InKEV: boolPtr(true)},
				Outcome:   Fail,
				Reason:    "confirmed exploited in real attacks",
			},
			{
				Name: "critical or high with a fix",
				Condition: Condition{
					MinSeverity: model.SeverityHigh,
					HasFix:      boolPtr(true),
				},
				Outcome: Fail,
				Reason:  "severe and something can be done about it",
			},
			{
				Name: "any exploitation probability above 10%",
				Condition: Condition{
					MinEPSS: 0.1,
					HasFix:  boolPtr(true),
				},
				Outcome: Fail,
				Reason:  "measurably likely to be exploited, and fixable",
			},
			{
				Name: "severe with no fix",
				Condition: Condition{
					MinSeverity: model.SeverityHigh,
					HasFix:      boolPtr(false),
				},
				Outcome: Warn,
				Reason: "severe but unfixable — blocking here would stop work nobody can " +
					"do, which is how a gate gets disabled",
			},
			{
				Name:      "medium severity",
				Condition: Condition{MinSeverity: model.SeverityMedium},
				Outcome:   Warn,
				Reason:    "worth tracking",
			},
		},
	}
}

// Advisory never fails a build. Useful for introducing scanning to a codebase
// that has never had it, where an immediately failing gate gets removed before
// anyone reads what it found.
func Advisory() Policy {
	return Policy{
		Name: "advisory",
		Rules: []Rule{
			{
				Name:      "actively exploited",
				Condition: Condition{InKEV: boolPtr(true)},
				Outcome:   Warn,
				Reason:    "confirmed exploited in real attacks",
			},
			{
				Name:      "severe",
				Condition: Condition{MinSeverity: model.SeverityHigh},
				Outcome:   Warn,
				Reason:    "reported for visibility only; this policy never fails a build",
			},
		},
	}
}

// ByName returns a built-in policy.
func ByName(name string) (Policy, bool) {
	switch name {
	case "balanced", "":
		return Balanced(), true
	case "strict":
		return Strict(), true
	case "advisory":
		return Advisory(), true
	default:
		return Policy{}, false
	}
}

// Names returns the built-in policy names, for help text and validation.
func Names() []string { return []string{"advisory", "balanced", "strict"} }
