package main

import "testing"

// TestHoistFlags covers the argument reordering that lets flags follow a
// positional argument.
//
// Go's flag package stops parsing at the first argument that does not begin
// with a dash, so `scan alpine:3.14 --policy balanced` silently drops the
// policy. hoistFlags rearranges before parsing — and the rearrangement has its
// own failure mode, which is what most of these cases are about.
func TestHoistFlags(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "flag after positional is hoisted",
			in:   []string{"alpine:3.14", "--policy", "balanced"},
			want: []string{"--policy", "balanced", "alpine:3.14"},
		},
		{
			name: "already in order is unchanged",
			in:   []string{"--policy", "balanced", "alpine:3.14"},
			want: []string{"--policy", "balanced", "alpine:3.14"},
		},
		{
			name: "inline value keeps its flag intact",
			in:   []string{"alpine:3.14", "--policy=balanced"},
			want: []string{"--policy=balanced", "alpine:3.14"},
		},
		{
			// A boolean flag takes no value, so the argument after it must not
			// be swallowed. This is the case isBoolFlag exists for, and the one
			// that breaks silently when a new boolean flag is added without
			// updating that list.
			name: "boolean flag does not consume the argument after it",
			in:   []string{"--all", "run.session"},
			want: []string{"--all", "run.session"},
		},
		{
			name: "boolean flag after positional",
			in:   []string{"run.session", "--all"},
			want: []string{"--all", "run.session"},
		},
		{
			// A bare "-" means stdin. Treating it as a flag would lose it, and
			// `normalize -file -` is a documented way to pipe scanner output in.
			name: "bare dash is a value, not a flag",
			in:   []string{"-file", "-", "--scanner", "trivy"},
			want: []string{"-file", "-", "--scanner", "trivy"},
		},
		{
			name: "two flags with values, positional in the middle",
			in:   []string{"--out", "json", "run.session", "--verify", "out.json"},
			want: []string{"--out", "json", "--verify", "out.json", "run.session"},
		},
		{
			name: "a flag whose value is missing is left alone",
			in:   []string{"alpine:3.14", "--policy"},
			want: []string{"--policy", "alpine:3.14"},
		},
		{
			name: "single-dash flags behave the same",
			in:   []string{"testdata/x.json", "-scanner", "trivy"},
			want: []string{"-scanner", "trivy", "testdata/x.json"},
		},
		{
			name: "only positionals",
			in:   []string{"a.session", "b.session"},
			want: []string{"a.session", "b.session"},
		},
		{
			name: "no arguments",
			in:   nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hoistFlags(tt.in)

			if len(got) != len(tt.want) {
				t.Fatalf("hoistFlags(%v) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("position %d: got %q, want %q\n  full: %v", i, got[i], tt.want[i], got)
				}
			}
		})
	}
}

// TestHoistFlagsPreservesOrderWithinGroups checks that flags keep their relative
// order and positionals keep theirs. `diff a.session b.session` depends on it:
// swapping the two would silently reverse the comparison.
func TestHoistFlagsPreservesOrderWithinGroups(t *testing.T) {
	got := hoistFlags([]string{"a.session", "--out", "json", "b.session", "--all"})
	want := []string{"--out", "json", "--all", "a.session", "b.session"}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("position %d: got %q, want %q\n  full: %v", i, got[i], want[i], got)
		}
	}
}

// TestIsBoolFlagCoversEveryBooleanFlag is the guard on the list that makes
// hoistFlags fragile.
//
// It does not check the code — a boolean flag missing from isBoolFlag compiles
// fine and only breaks the argument after it at runtime. This pins the ones that
// exist today, so removing one is a deliberate act rather than an accident.
func TestIsBoolFlagCoversEveryBooleanFlag(t *testing.T) {
	// Every boolean flag declared across the commands. Add to this when a new
	// one is added, and the test will point at isBoolFlag if it was forgotten.
	declared := []string{"all", "explain-weights", "no-provenance", "per-image"}

	for _, name := range declared {
		for _, form := range []string{"-" + name, "--" + name} {
			if !isBoolFlag(form) {
				t.Errorf("%q is a boolean flag but isBoolFlag does not know it; "+
					"the argument following it will be swallowed as its value", form)
			}
		}
	}

	// And a flag that does take a value must not be listed, or its value gets
	// left behind as a positional.
	for _, name := range []string{"-policy", "--policy", "-out", "--from", "-file"} {
		if isBoolFlag(name) {
			t.Errorf("%q takes a value but isBoolFlag claims otherwise; "+
				"its value will be parsed as a positional argument", name)
		}
	}
}
