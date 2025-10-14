package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestActiveDestructiveFlags(t *testing.T) {
	tests := []struct {
		name       string
		aggressive bool
		recursive  bool
		want       []string
	}{
		{name: "none", want: nil},
		{name: "aggressive", aggressive: true, want: []string{"--aggressive"}},
		{name: "recursive", recursive: true, want: []string{"--recursive"}},
		{name: "both", aggressive: true, recursive: true, want: []string{"--aggressive", "--recursive"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := activeDestructiveFlags(tt.aggressive, tt.recursive)
			if len(got) != len(tt.want) {
				t.Fatalf("expected %d flags, got %d (%v)", len(tt.want), len(got), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("expected flag %q at index %d, got %q", tt.want[i], i, got[i])
				}
			}
		})
	}
}

func TestMaybeWarnDestructive_NoFlags(t *testing.T) {
	var buf bytes.Buffer
	if err := maybeWarnDestructive(&buf, false, nil); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected no output, got %q", buf.String())
	}
}

func TestMaybeWarnDestructive_RequiresConfirmation(t *testing.T) {
	var buf bytes.Buffer
	err := maybeWarnDestructive(&buf, false, []string{"--aggressive", "--recursive"})
	if err == nil {
		t.Fatal("expected error when confirmation missing")
	}
	if !strings.Contains(err.Error(), "--aggressive and --recursive") {
		t.Fatalf("unexpected error message: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "LEGAL NOTICE") || !strings.Contains(out, "Destructive options enabled") {
		t.Fatalf("banner not printed, output: %q", out)
	}
}

func TestMaybeWarnDestructive_WithConfirmation(t *testing.T) {
	var buf bytes.Buffer
	err := maybeWarnDestructive(&buf, true, []string{"--aggressive"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "LEGAL NOTICE") {
		t.Fatalf("expected legal notice banner, got %q", out)
	}
}

func TestJoinDestructiveFlags(t *testing.T) {
	tests := []struct {
		flags []string
		want  string
	}{
		{nil, ""},
		{[]string{"--aggressive"}, "--aggressive"},
		{[]string{"--aggressive", "--recursive"}, "--aggressive and --recursive"},
		{[]string{"one", "two", "three"}, "one, two and three"},
	}

	for _, tt := range tests {
		if got := joinDestructiveFlags(tt.flags); got != tt.want {
			t.Errorf("joinDestructiveFlags(%v) = %q, want %q", tt.flags, got, tt.want)
		}
	}
}
