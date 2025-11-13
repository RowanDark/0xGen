package blitz

import (
	"testing"
)

func TestParseMarkers(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    Markers
		wantErr bool
	}{
		{
			name: "default",
			spec: "",
			want: Markers{Open: "{{", Close: "}}"},
		},
		{
			name: "burp-style",
			spec: "§§",
			want: Markers{Open: "§", Close: "§"},
		},
		{
			name: "space-separated",
			spec: "{{ }}",
			want: Markers{Open: "{{", Close: "}}"},
		},
		{
			name:    "odd-length",
			spec:    "abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMarkers(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMarkers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseMarkers() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRequest(t *testing.T) {
	markers := Markers{Open: "{{", Close: "}}"}

	req := `GET /api/user/{{id}}/profile?role={{role}} HTTP/1.1
Host: example.com

`

	parsed, err := ParseRequest(req, markers)
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}

	if len(parsed.Positions) != 2 {
		t.Errorf("Expected 2 positions, got %d", len(parsed.Positions))
	}

	if parsed.Positions[0].Name != "id" {
		t.Errorf("Position 0 name = %v, want 'id'", parsed.Positions[0].Name)
	}

	if parsed.Positions[1].Name != "role" {
		t.Errorf("Position 1 name = %v, want 'role'", parsed.Positions[1].Name)
	}
}

func TestRequestRender(t *testing.T) {
	markers := Markers{Open: "{{", Close: "}}"}
	req := `GET /user/{{id}} HTTP/1.1
Host: example.com

`

	parsed, _ := ParseRequest(req, markers)

	rendered := parsed.RenderSingle(0, "123")
	expected := `GET /user/123 HTTP/1.1
Host: example.com

`

	if rendered != expected {
		t.Errorf("RenderSingle() = %q, want %q", rendered, expected)
	}
}

func TestRequestRenderAll(t *testing.T) {
	markers := Markers{Open: "{{", Close: "}}"}
	req := `GET /{{path}}/{{resource}} HTTP/1.1
Host: {{host}}

`

	parsed, _ := ParseRequest(req, markers)

	rendered := parsed.RenderAll("test")
	expected := `GET /test/test HTTP/1.1
Host: test

`

	if rendered != expected {
		t.Errorf("RenderAll() = %q, want %q", rendered, expected)
	}
}
