package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	stdfs "io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/RowanDark/Glyph/internal/cases"
	"github.com/RowanDark/Glyph/internal/exporter"
	"github.com/RowanDark/Glyph/internal/reporter"
)

// uiAssets contains the static files that power the Glyph UI server.
var (
	//go:embed ui_assets/*
	uiAssets embed.FS
)

type uiDataset struct {
	Cases         []cases.Case       `json:"cases"`
	Telemetry     exporter.Telemetry `json:"telemetry"`
	FindingsCount int                `json:"findings_count"`
	RefreshedAt   string             `json:"refreshed_at"`
}

type uiServerState struct {
	dataset   uiDataset
	casesJSON []byte
	sarif     []byte
	caseIndex map[string]cases.Case
}

func runServeUI(args []string) int {
	fs := flag.NewFlagSet("serve ui", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", "127.0.0.1:5150", "address to bind the UI server")
	input := fs.String("input", reporter.DefaultFindingsPath, "path to findings JSONL input")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument: %s\n", fs.Arg(0))
		return 2
	}

	dataset, err := loadUIDataset(strings.TrimSpace(*input))
	if err != nil {
		fmt.Fprintf(os.Stderr, "load dataset: %v\n", err)
		return 1
	}

	state, err := newUIServerState(dataset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prepare UI server: %v\n", err)
		return 1
	}

	listener, err := net.Listen("tcp", strings.TrimSpace(*addr))
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		return 1
	}
	defer func() { _ = listener.Close() }()

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/api/data", state.handleAPIDataset)
	mux.HandleFunc("/download/cases.json", state.handleDownloadCasesJSON)
	mux.HandleFunc("/download/cases.sarif", state.handleDownloadSARIF)
	mux.HandleFunc("/download/case/", state.handleDownloadCaseAsset)
	assetFS, err := stdfs.Sub(uiAssets, "ui_assets")
	if err != nil {
		fmt.Fprintf(os.Stderr, "load assets: %v\n", err)
		return 1
	}
	fileServer := http.FileServer(http.FS(assetFS))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))

	server := &http.Server{Handler: mux}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(os.Stdout, "Glyph UI available at http://%s\n", listener.Addr())
	err = server.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "serve UI: %v\n", err)
		return 1
	}
	return 0
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := uiAssets.ReadFile("ui_assets/index.html")
	if err != nil {
		http.Error(w, "missing UI assets", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func loadUIDataset(inputPath string) (uiDataset, error) {
	if inputPath == "" {
		inputPath = reporter.DefaultFindingsPath
	}
	findingsList, err := reporter.ReadJSONL(inputPath)
	if err != nil {
		return uiDataset{}, err
	}

	builder := cases.NewBuilder()
	casesList, err := builder.Build(context.Background(), findingsList)
	if err != nil {
		return uiDataset{}, err
	}
	if casesList == nil {
		casesList = []cases.Case{}
	}

	telemetry := exporter.BuildTelemetry(casesList, len(findingsList))
	dataset := uiDataset{
		Cases:         casesList,
		Telemetry:     telemetry,
		FindingsCount: len(findingsList),
		RefreshedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	return dataset, nil
}

func newUIServerState(dataset uiDataset) (uiServerState, error) {
	state := uiServerState{dataset: dataset, caseIndex: make(map[string]cases.Case, len(dataset.Cases))}
	for _, c := range dataset.Cases {
		state.caseIndex[c.ID] = c
	}

	envelope := struct {
		GeneratedAt string             `json:"generated_at"`
		Telemetry   exporter.Telemetry `json:"telemetry"`
		Cases       []cases.Case       `json:"cases"`
	}{
		GeneratedAt: dataset.RefreshedAt,
		Telemetry:   dataset.Telemetry,
		Cases:       dataset.Cases,
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return uiServerState{}, fmt.Errorf("encode cases json: %w", err)
	}
	data = append(data, '\n')
	state.casesJSON = data

	sarif, err := exporter.EncodeSARIF(dataset.Cases)
	if err != nil {
		return uiServerState{}, fmt.Errorf("encode sarif: %w", err)
	}
	state.sarif = sarif

	return state, nil
}

func (s uiServerState) handleAPIDataset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s.dataset)
}

func (s uiServerState) handleDownloadCasesJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=cases.json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.casesJSON)
}

func (s uiServerState) handleDownloadSARIF(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/sarif+json")
	w.Header().Set("Content-Disposition", "attachment; filename=cases.sarif")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.sarif)
}

func (s uiServerState) handleDownloadCaseAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/download/case/")
	if trimmed == "" {
		http.NotFound(w, r)
		return
	}

	switch {
	case strings.HasSuffix(trimmed, ".json"):
		id, err := url.PathUnescape(strings.TrimSuffix(trimmed, ".json"))
		if err != nil {
			http.Error(w, "invalid case id", http.StatusBadRequest)
			return
		}
		s.serveCaseJSON(w, r, id)
	case strings.HasSuffix(trimmed, ".md"):
		id, err := url.PathUnescape(strings.TrimSuffix(trimmed, ".md"))
		if err != nil {
			http.Error(w, "invalid case id", http.StatusBadRequest)
			return
		}
		s.serveCaseMarkdown(w, r, id)
	case strings.HasSuffix(trimmed, "/poc.txt"):
		id, err := url.PathUnescape(strings.TrimSuffix(trimmed, "/poc.txt"))
		if err != nil {
			http.Error(w, "invalid case id", http.StatusBadRequest)
			return
		}
		s.serveCasePOC(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (s uiServerState) serveCaseJSON(w http.ResponseWriter, r *http.Request, id string) {
	c, ok := s.caseIndex[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, err := cases.ExportJSON(c)
	if err != nil {
		http.Error(w, "encode case", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.json", sanitizeFilename(c.ID)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s uiServerState) serveCaseMarkdown(w http.ResponseWriter, r *http.Request, id string) {
	c, ok := s.caseIndex[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	payload := cases.ExportMarkdown(c)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.md", sanitizeFilename(c.ID)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(payload))
}

func (s uiServerState) serveCasePOC(w http.ResponseWriter, r *http.Request, id string) {
	c, ok := s.caseIndex[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	payload := formatPOC(c)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-poc.txt", sanitizeFilename(c.ID)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(payload))
}

func formatPOC(c cases.Case) string {
	var b strings.Builder
	summary := strings.TrimSpace(c.Proof.Summary)
	if summary != "" {
		b.WriteString(summary)
		b.WriteString("\n\n")
	}
	if len(c.Proof.Steps) == 0 {
		b.WriteString("No proof of concept steps were provided.\n")
		return b.String()
	}
	stepIndex := 1
	for _, step := range c.Proof.Steps {
		trimmed := strings.TrimSpace(step)
		if trimmed == "" {
			continue
		}
		fmt.Fprintf(&b, "%d. %s\n", stepIndex, trimmed)
		stepIndex++
	}
	if stepIndex == 1 {
		b.WriteString("No proof of concept steps were provided.\n")
	}
	return b.String()
}

func sanitizeFilename(name string) string {
	sanitized := make([]rune, 0, len(name))
	lastHyphen := false
	trimmed := strings.TrimSpace(name)
	for _, r := range trimmed {
		replace := r
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', '.':
			replace = '-'
		}
		if replace == '-' {
			if lastHyphen {
				continue
			}
			sanitized = append(sanitized, replace)
			lastHyphen = true
			continue
		}
		sanitized = append(sanitized, replace)
		lastHyphen = false
	}
	cleaned := strings.Trim(string(sanitized), "-")
	if cleaned == "" {
		return "case"
	}
	return cleaned
}
