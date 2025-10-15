package env

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestLookupPrefersNewKey(t *testing.T) {
	ResetWarningsForTesting()
	restore := SetWarnLoggerForTesting(func(string, ...any) {})
	defer restore()

	t.Setenv("0XGEN_HOME", "/modern")
	t.Setenv("GLYPH_HOME", "/legacy")

	val, ok := Lookup("0XGEN_HOME", "GLYPH_HOME")
	if !ok {
		t.Fatalf("expected lookup to succeed")
	}
	if val != "/modern" {
		t.Fatalf("expected new key to win, got %s", val)
	}
}

func TestLookupWarnsOnLegacyKeyOnce(t *testing.T) {
	ResetWarningsForTesting()

	var buf bytes.Buffer
	restore := SetWarnLoggerForTesting(func(format string, args ...any) {
		buf.WriteString(strings.TrimSpace(fmt.Sprintf(format, args...)))
	})
	defer restore()

	t.Setenv("GLYPH_HOME", "/legacy")

	if _, ok := Lookup("0XGEN_HOME", "GLYPH_HOME"); !ok {
		t.Fatalf("expected lookup to succeed")
	}
	if _, ok := Lookup("0XGEN_HOME", "GLYPH_HOME"); !ok {
		t.Fatalf("expected second lookup to succeed")
	}

	output := buf.String()
	if output != "GLYPH_HOME is deprecated; use 0XGEN_HOME" {
		t.Fatalf("unexpected warning format: %q", output)
	}
}

func TestLookupReturnsLegacyValue(t *testing.T) {
	ResetWarningsForTesting()
	restore := SetWarnLoggerForTesting(func(string, ...any) {})
	defer restore()

	want := "/legacy"
	t.Setenv("GLYPH_OUT", want)

	got, ok := Lookup("0XGEN_OUT", "GLYPH_OUT")
	if !ok {
		t.Fatalf("expected lookup to succeed")
	}
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}
