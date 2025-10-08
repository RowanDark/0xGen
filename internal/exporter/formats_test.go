package exporter

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestRegisterFormatRejectsDuplicate(t *testing.T) {
	if err := RegisterFormat(FormatSpec{Format: FormatJSONL, Encode: func(Request) ([]byte, error) { return nil, nil }}); err == nil {
		t.Fatalf("expected duplicate registration to fail")
	}
}

func TestEncodeUsesRegisteredFormat(t *testing.T) {
	formatName := Format("unit-test-format")
	spec := FormatSpec{
		Format:          formatName,
		DefaultFilename: "unit-test.txt",
		Encode: func(req Request) ([]byte, error) {
			buf := bytes.NewBufferString("cases:")
			buf.WriteString(fmt.Sprintf("%d", req.Telemetry.CaseCount))
			return buf.Bytes(), nil
		},
	}
	if err := RegisterFormat(spec); err != nil {
		t.Fatalf("register format: %v", err)
	}

	req := Request{Telemetry: Telemetry{CaseCount: 2}}
	data, err := Encode(formatName, req)
	if err != nil {
		t.Fatalf("encode custom format: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("expected data from custom exporter")
	}

	path, err := DefaultPath(formatName)
	if err != nil {
		t.Fatalf("default path: %v", err)
	}
	if !strings.HasSuffix(path, spec.DefaultFilename) {
		t.Fatalf("unexpected default path %q", path)
	}
}
