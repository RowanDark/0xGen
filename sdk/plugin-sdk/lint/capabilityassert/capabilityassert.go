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
		"Dial":        "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND (enable via plugin.CapabilityMacros)",
		"DialContext": "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND (enable via plugin.CapabilityMacros)",
		"DialTimeout": "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND (enable via plugin.CapabilityMacros)",
	},
	"net/http": {
		"Get":  "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND (enable via plugin.CapabilityMacros)",
		"Post": "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND (enable via plugin.CapabilityMacros)",
		"Head": "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND (enable via plugin.CapabilityMacros)",
	},
	"os": {
		"Open":      "use pluginsdk.UseFilesystem with workspace capabilities (enable via plugin.CapabilityMacros)",
		"OpenFile":  "use pluginsdk.UseFilesystem with workspace capabilities (enable via plugin.CapabilityMacros)",
		"ReadFile":  "use pluginsdk.UseFilesystem with workspace capabilities (enable via plugin.CapabilityMacros)",
		"WriteFile": "use pluginsdk.UseFilesystem with workspace capabilities (enable via plugin.CapabilityMacros)",
	},
	"io/ioutil": {
		"ReadFile":  "use pluginsdk.UseFilesystem with workspace capabilities (enable via plugin.CapabilityMacros)",
		"WriteFile": "use pluginsdk.UseFilesystem with workspace capabilities (enable via plugin.CapabilityMacros)",
	},
}

type capabilityRequirement struct {
	name      string
	fields    []string
	constants []string
}

var sdkCapabilities = map[string]capabilityRequirement{
	"UseFilesystem": {
		name:      "workspace",
		fields:    []string{"WorkspaceRead", "WorkspaceWrite"},
		constants: []string{"CapabilityWorkspaceRead", "CapabilityWorkspaceWrite"},
	},
	"UseNetwork": {
		name:      "network",
		fields:    []string{"NetOutbound"},
		constants: []string{"CapabilityNetOutbound"},
	},
	"UseSecrets": {
		name:      "secrets",
		fields:    []string{"SecretsRead"},
		constants: []string{"CapabilitySecretsRead"},
	},
}

type macroSet struct {
	values map[string]bool
	known  bool
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
		parsed := make([]*ast.File, 0, len(pkg.GoFiles))
		macroValues := macroSet{values: map[string]bool{}}
		for _, rel := range pkg.GoFiles {
			filename := filepath.Join(pkg.Dir, rel)
			file, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", filename, err)
			}
			extractMacros(file, &macroValues)
			parsed = append(parsed, file)
		}
		for _, file := range parsed {
			imports := map[string]string{}
			for _, imp := range file.Imports {
				name := importName(imp)
				pathVal := strings.Trim(imp.Path.Value, "\"")
				imports[name] = pathVal
			}
			inspector := &fileInspector{
				fset:        fset,
				imports:     imports,
				macros:      macroValues,
				diagnostics: &diagnostics,
			}
			inspector.walk(file)
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

type fileInspector struct {
	fset        *token.FileSet
	imports     map[string]string
	macros      macroSet
	diagnostics *[]Diagnostic
	stack       []ast.Node
}

func (fi *fileInspector) walk(node ast.Node) {
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			if len(fi.stack) > 0 {
				fi.stack = fi.stack[:len(fi.stack)-1]
			}
			return false
		}
		fi.stack = append(fi.stack, n)

		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		switch x := sel.X.(type) {
		case *ast.Ident:
			fi.handleCall(call, sel, fi.imports[x.Name])
		case *ast.SelectorExpr:
			if ident, ok := x.X.(*ast.Ident); ok {
				pkgPath := fi.imports[ident.Name]
				fi.handleCall(call, sel, pkgPath)
			}
		}

		return true
	})
}

func (fi *fileInspector) handleCall(call *ast.CallExpr, sel *ast.SelectorExpr, pkgPath string) {
	if pkgPath == "" {
		return
	}
	if msgs, ok := forbidden[pkgPath]; ok {
		if msg, ok := msgs[sel.Sel.Name]; ok {
			pos := fi.fset.Position(sel.Sel.Pos())
			*fi.diagnostics = append(*fi.diagnostics, Diagnostic{
				File:    pos.Filename,
				Line:    pos.Line,
				Column:  pos.Column,
				Message: msg,
			})
			return
		}
	}

	if pkgPath != "github.com/RowanDark/Glyph/sdk/plugin-sdk" {
		return
	}
	req, ok := sdkCapabilities[sel.Sel.Name]
	if !ok {
		return
	}
	if fi.capabilityDeclared(call, req) {
		return
	}
	pos := fi.fset.Position(sel.Sel.Pos())
	message := fmt.Sprintf("%s access requires enabling plugin.CapabilityMacros.%s", req.name, req.fields[0])
	if len(req.fields) > 1 {
		message = fmt.Sprintf("%s access requires enabling one of plugin.CapabilityMacros.%s", req.name, strings.Join(req.fields, ", "))
	}
	*fi.diagnostics = append(*fi.diagnostics, Diagnostic{
		File:    pos.Filename,
		Line:    pos.Line,
		Column:  pos.Column,
		Message: message,
	})
}

func (fi *fileInspector) capabilityDeclared(call *ast.CallExpr, req capabilityRequirement) bool {
	for _, field := range req.fields {
		if fi.macros.values[field] {
			return true
		}
	}
	if fi.callGuarded(call, req) {
		return true
	}
	return false
}

func (fi *fileInspector) callGuarded(call *ast.CallExpr, req capabilityRequirement) bool {
	for i := len(fi.stack) - 1; i >= 0; i-- {
		ifStmt, ok := fi.stack[i].(*ast.IfStmt)
		if !ok {
			continue
		}
		if !within(call, ifStmt.Body) {
			continue
		}
		if usesCapability(ifStmt.Cond, req) {
			return true
		}
	}
	return false
}

func within(node ast.Node, block *ast.BlockStmt) bool {
	if block == nil {
		return false
	}
	return node.Pos() >= block.Lbrace && node.End() <= block.Rbrace
}

func usesCapability(expr ast.Expr, req capabilityRequirement) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if isCapabilityMacrosExpr(v.X) {
				for _, field := range req.fields {
					if v.Sel.Name == field {
						found = true
						return false
					}
				}
			}
		case *ast.CallExpr:
			sel, ok := v.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Enabled" || !isCapabilityMacrosExpr(sel.X) {
				return true
			}
			for _, arg := range v.Args {
				if matchesCapabilityConst(arg, req.constants) {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

func isCapabilityMacrosExpr(expr ast.Expr) bool {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name == "CapabilityMacros"
	case *ast.SelectorExpr:
		if v.Sel.Name != "CapabilityMacros" {
			return false
		}
		switch base := v.X.(type) {
		case *ast.Ident:
			return base.Name != ""
		case *ast.SelectorExpr:
			return isCapabilityMacrosExpr(base)
		default:
			return false
		}
	default:
		return false
	}
}

func matchesCapabilityConst(expr ast.Expr, constants []string) bool {
	switch v := expr.(type) {
	case *ast.Ident:
		for _, name := range constants {
			if v.Name == name {
				return true
			}
		}
	case *ast.SelectorExpr:
		for _, name := range constants {
			if v.Sel.Name == name {
				return true
			}
		}
	}
	return false
}

func extractMacros(file *ast.File, macros *macroSet) {
	ast.Inspect(file, func(n ast.Node) bool {
		decl, ok := n.(*ast.GenDecl)
		if !ok || decl.Tok != token.VAR {
			return true
		}
		for _, spec := range decl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if name.Name != "CapabilityMacros" || len(vs.Values) <= i {
					continue
				}
				lit, ok := vs.Values[i].(*ast.CompositeLit)
				if !ok {
					continue
				}
				sel, ok := lit.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "CapabilitySet" {
					continue
				}
                                macros.known = true
				for _, elt := range lit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok {
						continue
					}
					switch val := kv.Value.(type) {
					case *ast.Ident:
						if val.Name == "true" {
							macros.values[key.Name] = true
						} else if val.Name == "false" {
							macros.values[key.Name] = false
						}
					case *ast.BasicLit:
						if val.Kind == token.STRING {
							trimmed := strings.Trim(val.Value, "\"")
							if trimmed == "true" {
								macros.values[key.Name] = true
							} else if trimmed == "false" {
								macros.values[key.Name] = false
							}
						}
					}
				}
			}
		}
		return false
	})
}
