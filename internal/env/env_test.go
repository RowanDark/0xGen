package env

import "testing"

func TestLookup(t *testing.T) {
	want := "/tmp/root"
	t.Setenv("0XGEN_HOME", want)

	got, ok := Lookup("0XGEN_HOME")
	if !ok {
		t.Fatalf("expected lookup to succeed")
	}
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
