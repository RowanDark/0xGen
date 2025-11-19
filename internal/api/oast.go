package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/RowanDark/0xgen/internal/oast"
	"github.com/RowanDark/0xgen/internal/oast/local"
	"github.com/RowanDark/0xgen/internal/team"
)

// OASTAPI handles OAST-related API endpoints.
type OASTAPI struct {
	client *oast.Client
}

// NewOASTAPI creates a new OAST API handler.
func NewOASTAPI(client *oast.Client) *OASTAPI {
	return &OASTAPI{client: client}
}

// RegisterRoutes registers OAST routes on the provided mux.
func (a *OASTAPI) RegisterRoutes(mux *http.ServeMux, requireRole func(role team.Role, next http.Handler) http.Handler) {
	mux.Handle("/api/v1/oast/status", requireRole(team.RoleViewer, http.HandlerFunc(a.handleStatus)))
	mux.Handle("/api/v1/oast/interactions", requireRole(team.RoleViewer, http.HandlerFunc(a.handleInteractions)))
	mux.Handle("/api/v1/oast/interactions/", requireRole(team.RoleViewer, http.HandlerFunc(a.handleInteractionsByID)))
}

// handleStatus returns the current OAST status.
func (a *OASTAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"enabled": a.client != nil && a.client.IsEnabled(),
	}

	if a.client != nil && a.client.IsEnabled() {
		response["status"] = map[string]interface{}{
			"running": true,
			"port":    a.client.GetPort(),
			"mode":    string(a.client.GetMode()),
		}

		// Get stats
		stats, err := a.client.GetStats()
		if err == nil {
			response["stats"] = map[string]interface{}{
				"total":     stats.TotalInteractions,
				"uniqueIDs": stats.UniqueIDs,
				"byType":    stats.ByType,
			}
		}

		// Get interactions
		ctx := r.Context()
		interactions, err := a.getInteractionsList(ctx, 100)
		if err == nil {
			response["interactions"] = interactions
		}
	}

	respondJSON(w, response)
}

// handleInteractions returns a list of OAST interactions.
func (a *OASTAPI) handleInteractions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.client == nil || !a.client.IsEnabled() {
		http.Error(w, "OAST is disabled", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	ctx := r.Context()
	interactions, err := a.getInteractionsList(ctx, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get stats
	stats, err := a.client.GetStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respondJSON(w, map[string]interface{}{
		"interactions": interactions,
		"stats": map[string]interface{}{
			"total":     stats.TotalInteractions,
			"uniqueIDs": stats.UniqueIDs,
			"byType":    stats.ByType,
		},
	})
}

// handleInteractionsByID returns interactions for a specific callback ID.
func (a *OASTAPI) handleInteractionsByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.client == nil || !a.client.IsEnabled() {
		http.Error(w, "OAST is disabled", http.StatusServiceUnavailable)
		return
	}

	// Extract ID from path: /api/v1/oast/interactions/{id}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/oast/interactions/")
	if id == "" {
		http.Error(w, "missing interaction ID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	interactions, err := a.client.CheckInteractions(ctx, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert to response format
	responseInteractions := make([]map[string]interface{}, len(interactions))
	for i, interaction := range interactions {
		responseInteractions[i] = interactionToMap(interaction)
	}

	respondJSON(w, map[string]interface{}{
		"id":           id,
		"count":        len(interactions),
		"interactions": responseInteractions,
	})
}

// getInteractionsList retrieves a list of interactions with the specified limit.
func (a *OASTAPI) getInteractionsList(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	storage := a.client.GetStorage()
	if storage == nil {
		return []map[string]interface{}{}, nil
	}

	filter := local.InteractionFilter{
		Limit: limit,
	}

	interactions := storage.List(filter)

	result := make([]map[string]interface{}, len(interactions))
	for i, interaction := range interactions {
		result[i] = interactionToMap(interaction)
	}

	return result, nil
}

// interactionToMap converts an Interaction to a map for JSON serialization.
func interactionToMap(interaction *local.Interaction) map[string]interface{} {
	m := map[string]interface{}{
		"id":        interaction.ID,
		"timestamp": interaction.Timestamp.Format("2006-01-02T15:04:05.000Z07:00"),
		"type":      "http",
		"method":    interaction.Method,
		"path":      interaction.Path,
		"clientIP":  interaction.ClientIP,
	}

	if interaction.Query != "" {
		m["query"] = interaction.Query
	}

	if len(interaction.Headers) > 0 {
		m["headers"] = interaction.Headers
	}

	if interaction.Body != "" {
		m["body"] = interaction.Body
	}

	if interaction.UserAgent != "" {
		m["userAgent"] = interaction.UserAgent
	}

	if interaction.TestID != "" {
		m["testID"] = interaction.TestID
	}

	if interaction.RequestID != "" {
		m["requestID"] = interaction.RequestID
	}

	return m
}

// respondJSON writes a JSON response.
func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
