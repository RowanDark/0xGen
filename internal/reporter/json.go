package reporter

import (
	"encoding/json"

	"github.com/RowanDark/0xgen/internal/findings"
)

// RenderJSON converts a slice of findings into a signed bundle payload.
func RenderJSON(list []findings.Finding, opts ReportOptions) ([]byte, error) {
	bundle, err := BuildBundle(opts.Context, list, opts)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	return data, nil
}
