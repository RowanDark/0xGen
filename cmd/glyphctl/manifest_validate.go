package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/RowanDark/Glyph/internal/plugins"
)

var manifestValidate = flag.String("manifest-validate", "", "Validate a plugin manifest JSON file and exit")

// runManifestValidate integrates into main() without breaking other commands.
// main() should call flag.Parse() and then exit(runManifestValidate()) if the
// flag is set.
func runManifestValidate() int {
	if *manifestValidate == "" {
		return 0
	}

	data, err := os.ReadFile(*manifestValidate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read error: %v\n", err)
		return 2
	}

	var strict plugins.Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&strict); err != nil {
		fmt.Fprintf(os.Stderr, "json decode error (unknown field or type): %v\n", err)
		return 1
	}
	if err := strict.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid manifest: %v\n", err)
		return 1
	}

	if _, err := fmt.Fprintln(os.Stdout, "ok"); err != nil {
		fmt.Fprintf(os.Stderr, "write stdout: %v\n", err)
		return 2
	}
	return 0
}
