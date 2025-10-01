package main

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

//go:embed templates/**
var templateFS embed.FS

type scaffoldData struct {
	Module     string
	PluginName string
	BinaryName string
	SDKReplace string
}

func scaffoldGo(name, module string) error {
	absProject, err := filepath.Abs(name)
	if err != nil {
		return err
	}
	sdkPath, err := findSDKRoot()
	if err != nil {
		return err
	}
	rootPath := filepath.Dir(filepath.Dir(sdkPath))
	rel, err := filepath.Rel(absProject, rootPath)
	if err != nil {
		return err
	}

	base := filepath.Base(name)
	data := scaffoldData{
		Module:     module,
		PluginName: strings.ReplaceAll(base, "_", "-"),
		BinaryName: base,
		SDKReplace: rel,
	}
	return renderTemplates(name, "templates/go", data)
}

func scaffoldNode(name string) error {
	base := filepath.Base(name)
	data := scaffoldData{PluginName: strings.ReplaceAll(base, "_", "-")}
	return renderTemplates(name, "templates/node", data)
}

func renderTemplates(dir, base string, data scaffoldData) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	return fs.WalkDir(templateFS, base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == base {
			return nil
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		rel = strings.TrimSuffix(rel, ".tmpl")
		rel = strings.ReplaceAll(rel, "__BINARY__", data.BinaryName)
		target := filepath.Join(dir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		contents, err := fs.ReadFile(templateFS, path)
		if err != nil {
			return err
		}
		tmpl, err := template.New(rel).Parse(string(contents))
		if err != nil {
			return fmt.Errorf("parse template %s: %w", rel, err)
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		if err := tmpl.Execute(f, data); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if strings.HasPrefix(rel, "scripts/") {
			return os.Chmod(target, 0o755)
		}
		return nil
	})
}

func findSDKRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, "sdk", "plugin-sdk")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("unable to locate sdk/plugin-sdk")
		}
		dir = parent
	}
}
