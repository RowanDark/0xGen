package raider

import "testing"

func TestParseTemplatePositions(t *testing.T) {
	markers, err := ParseMarkers("{{}}")
	if err != nil {
		t.Fatalf("parse markers: %v", err)
	}

	raw := "POST /test HTTP/1.1\nHost: example.com\n\nfield={{ value }}&other={{second}}"
	tpl, err := ParseTemplate(raw, markers)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}

	positions := tpl.Positions()
	if len(positions) != 2 {
		t.Fatalf("expected 2 positions, got %d", len(positions))
	}
	if positions[0].Name != "value" {
		t.Errorf("unexpected first position name %q", positions[0].Name)
	}
	if positions[0].Default != " value " {
		t.Errorf("unexpected first default %q", positions[0].Default)
	}
	if positions[1].Name != "second" {
		t.Errorf("unexpected second position name %q", positions[1].Name)
	}

	rendered := tpl.RenderWith(0, "FUZZ")
	want := "POST /test HTTP/1.1\nHost: example.com\n\nfield=FUZZ&other=second"
	if rendered != want {
		t.Fatalf("rendered mismatch:\nwant: %q\n got: %q", want, rendered)
	}
}
