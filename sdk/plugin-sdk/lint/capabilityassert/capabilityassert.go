package capabilityassert

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// Diagnostic captures a lint finding.
type Diagnostic struct {
	File    string
	Line    int
	Column  int
	Message string
}

var forbidden = map[string]map[string]string{
	"net": {
		"Dial":        "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND",
		"DialContext": "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND",
		"DialTimeout": "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND",
	},
	"net/http": {
		"Get":  "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND",
		"Post": "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND",
		"Head": "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND",
	},
	"os": {
		"Open":      "use pluginsdk.UseFilesystem with workspace capabilities",
		"OpenFile":  "use pluginsdk.UseFilesystem with workspace capabilities",
		"ReadFile":  "use pluginsdk.UseFilesystem with workspace capabilities",
		"WriteFile": "use pluginsdk.UseFilesystem with workspace capabilities",
	},
	"io/ioutil": {
		"ReadFile":  "use pluginsdk.UseFilesystem with workspace capabilities",
		"WriteFile": "use pluginsdk.UseFilesystem with workspace capabilities",
	},
}

// Run lints the provided package patterns.
func Run(patterns []string) ([]Diagnostic, error) {
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	args := append([]string{"list", "-json"}, patterns...)
	cmd := exec.Command("go", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("go list: %w\n%s", err, output)
	}

	dec := json.NewDecoder(strings.NewReader(string(output)))
	diagnostics := []Diagnostic{}
	for dec.More() {
		var pkg struct {
			Dir     string
			GoFiles []string
		}
		if err := dec.Decode(&pkg); err != nil {
			return nil, fmt.Errorf("decode package: %w", err)
		}
		fset := token.NewFileSet()
		for _, rel := range pkg.GoFiles {
			filename := filepath.Join(pkg.Dir, rel)
			file, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", filename, err)
			}
			imports := map[string]string{}
			for _, imp := range file.Imports {
				name := importName(imp)
				pathVal := strings.Trim(imp.Path.Value, "\"")
				imports[name] = pathVal
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				pkgPath := imports[ident.Name]
				if pkgPath == "" {
					return true
				}
				if msgs, ok := forbidden[pkgPath]; ok {
					if msg, ok := msgs[sel.Sel.Name]; ok {
						pos := fset.Position(sel.Sel.Pos())
						diagnostics = append(diagnostics, Diagnostic{
							File:    pos.Filename,
							Line:    pos.Line,
							Column:  pos.Column,
							Message: msg,
						})
					}
				}
				return true
			})
		}
	}
	return diagnostics, nil
}

func importName(spec *ast.ImportSpec) string {
	if spec.Name != nil {
		return spec.Name.Name
	}
	trimmed := strings.Trim(spec.Path.Value, "\"")
	return path.Base(trimmed)
}
