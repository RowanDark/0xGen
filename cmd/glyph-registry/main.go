package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/RowanDark/Glyph/internal/registry"
)

func main() {
	listen := flag.String("listen", ":8088", "address to listen on")
	dataPath := flag.String("data", "docs/en/data/plugin-registry.json", "path to the registry dataset")
	enableCORS := flag.Bool("cors", false, "allow cross-origin requests")
	flag.Parse()

	srv := &server{dataPath: *dataPath, allowCORS: *enableCORS}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", srv.handleHealth)
	mux.HandleFunc("/registry.json", srv.handleRegistry)
	mux.HandleFunc("/plugins", srv.handlePlugins)
	mux.HandleFunc("/plugins/", srv.handlePluginByID)
	mux.HandleFunc("/compatibility", srv.handleCompatibility)

	httpSrv := &http.Server{
		Addr:    *listen,
		Handler: srv.withMiddleware(mux),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("registry server: %v", err)
			stop()
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("registry shutdown: %v", err)
	}
}

type server struct {
	dataPath  string
	allowCORS bool
}

func (s *server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.allowCORS {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleRegistry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w)
		return
	}
	dataset, err := s.load()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, dataset)
}

func (s *server) handlePlugins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w)
		return
	}
	dataset, err := s.load()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	query := r.URL.Query()
	filter := registry.Filter{
		Query:      coalesce(query.Get("q"), query.Get("query")),
		Language:   query.Get("language"),
		Category:   query.Get("category"),
		Capability: query.Get("capability"),
		Glyph:      query.Get("glyph"),
		Status:     query.Get("status"),
	}
	plugins := dataset.FilterPlugins(filter)
	response := struct {
		Count         int               `json:"count"`
		Total         int               `json:"total"`
		GlyphVersions []string          `json:"glyph_versions"`
		Plugins       []registry.Plugin `json:"plugins"`
	}{
		Count:         len(plugins),
		Total:         len(dataset.Plugins),
		GlyphVersions: dataset.GlyphVersions,
		Plugins:       plugins,
	}
	s.writeJSON(w, http.StatusOK, response)
}

func (s *server) handlePluginByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w)
		return
	}
	dataset, err := s.load()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/plugins/")
	id = strings.TrimSpace(id)
	if id == "" {
		http.NotFound(w, r)
		return
	}
	plugin, ok := dataset.Plugin(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.writeJSON(w, http.StatusOK, plugin)
}

func (s *server) handleCompatibility(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w)
		return
	}
	dataset, err := s.load()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	type compatibilityEntry struct {
		ID            string                            `json:"id"`
		Name          string                            `json:"name"`
		Version       string                            `json:"version"`
		Compatibility map[string]registry.Compatibility `json:"compatibility"`
	}
	entries := make([]compatibilityEntry, 0, len(dataset.Plugins))
	for _, plugin := range dataset.Plugins {
		entries = append(entries, compatibilityEntry{
			ID:            plugin.ID,
			Name:          plugin.Name,
			Version:       plugin.Version,
			Compatibility: plugin.Compatibility,
		})
	}
	payload := struct {
		GlyphVersions []string             `json:"glyph_versions"`
		Plugins       []compatibilityEntry `json:"plugins"`
	}{
		GlyphVersions: dataset.GlyphVersions,
		Plugins:       entries,
	}
	s.writeJSON(w, http.StatusOK, payload)
}

func (s *server) methodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Allow", http.MethodGet)
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}

func (s *server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write response: %v", err)
	}
}

func (s *server) writeError(w http.ResponseWriter, status int, err error) {
	message := ""
	if err != nil {
		message = err.Error()
	}
	type errorPayload struct {
		Error string `json:"error"`
	}
	s.writeJSON(w, status, errorPayload{Error: message})
}

func (s *server) load() (registry.Dataset, error) {
	dataset, err := registry.Load(s.dataPath)
	if err != nil {
		return registry.Dataset{}, fmt.Errorf("load registry: %w", err)
	}
	return dataset, nil
}

func coalesce(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
