package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/RowanDark/0xgen/internal/cipher"
)

// CipherOperationRequest represents a request to execute a cipher operation
type CipherOperationRequest struct {
	Operation string                 `json:"operation"`
	Input     string                 `json:"input"`
	Config    map[string]interface{} `json:"config,omitempty"`
}

// CipherOperationResponse represents the result of a cipher operation
type CipherOperationResponse struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

// CipherPipelineRequest represents a request to execute a pipeline of operations
type CipherPipelineRequest struct {
	Input      string                     `json:"input"`
	Operations []cipher.OperationConfig   `json:"operations"`
}

// CipherPipelineResponse represents the result of a pipeline execution
type CipherPipelineResponse struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

// CipherDetectRequest represents a request to auto-detect encoding
type CipherDetectRequest struct {
	Input string `json:"input"`
}

// CipherDetectResponse represents the detection result
type CipherDetectResponse struct {
	Detections []cipher.DetectionResult `json:"detections"`
}

// CipherSmartDecodeRequest represents a request for smart auto-decode
type CipherSmartDecodeRequest struct {
	Input string `json:"input"`
}

// CipherSmartDecodeResponse represents the smart decode result
type CipherSmartDecodeResponse struct {
	Output         string             `json:"output"`
	Pipeline       []string           `json:"pipeline"`
	Confidence     float64            `json:"confidence"`
	Error          string             `json:"error,omitempty"`
}

// RecipeSaveRequest represents a request to save a recipe
type RecipeSaveRequest struct {
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Tags        []string                 `json:"tags,omitempty"`
	Operations  []cipher.OperationConfig `json:"operations"`
}

// RecipeListResponse represents the list of recipes
type RecipeListResponse struct {
	Recipes []cipher.Recipe `json:"recipes"`
}

// RecipeExportResponse represents an exported recipe
type RecipeExportResponse struct {
	Recipe cipher.Recipe `json:"recipe"`
}

// handleCipherExecute handles execution of a single cipher operation
func (s *Server) handleCipherExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CipherOperationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Operation == "" {
		http.Error(w, "operation field is required", http.StatusBadRequest)
		return
	}

	// Get the operation from the registry
	op, exists := cipher.GetOperation(req.Operation)
	if !exists {
		s.writeJSON(w, http.StatusBadRequest, CipherOperationResponse{
			Error: "unknown operation: " + req.Operation,
		})
		return
	}

	// Execute the operation using request context for proper cancellation and tracing
	ctx := r.Context()
	params := req.Config
	if params == nil {
		params = make(map[string]interface{})
	}

	result, err := op.Execute(ctx, []byte(req.Input), params)
	if err != nil {
		// Check for context cancellation
		if ctx.Err() != nil {
			if ctx.Err() == context.Canceled {
				http.Error(w, "request canceled", http.StatusRequestTimeout)
			} else {
				http.Error(w, "request timeout", http.StatusGatewayTimeout)
			}
			return
		}
		s.writeJSON(w, http.StatusUnprocessableEntity, CipherOperationResponse{
			Error: err.Error(),
		})
		return
	}

	s.writeJSON(w, http.StatusOK, CipherOperationResponse{
		Output: string(result),
	})
}

// handleCipherPipeline handles execution of a pipeline of operations
func (s *Server) handleCipherPipeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CipherPipelineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if len(req.Operations) == 0 {
		http.Error(w, "operations field is required and must not be empty", http.StatusBadRequest)
		return
	}

	// Create the pipeline
	pipeline := &cipher.Pipeline{
		Operations: req.Operations,
	}

	// Execute the pipeline using request context for proper cancellation and tracing
	ctx := r.Context()
	result, err := pipeline.Execute(ctx, []byte(req.Input))
	if err != nil {
		// Check for context cancellation
		if ctx.Err() != nil {
			if ctx.Err() == context.Canceled {
				http.Error(w, "request canceled", http.StatusRequestTimeout)
			} else {
				http.Error(w, "request timeout", http.StatusGatewayTimeout)
			}
			return
		}
		s.writeJSON(w, http.StatusUnprocessableEntity, CipherPipelineResponse{
			Error: err.Error(),
		})
		return
	}

	s.writeJSON(w, http.StatusOK, CipherPipelineResponse{
		Output: string(result),
	})
}

// handleCipherDetect handles auto-detection of encoding
func (s *Server) handleCipherDetect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CipherDetectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Input == "" {
		http.Error(w, "input field is required", http.StatusBadRequest)
		return
	}

	// Use the smart detector with request context for proper cancellation and tracing
	detector := cipher.NewSmartDetector()
	ctx := r.Context()
	detections, err := detector.Detect(ctx, []byte(req.Input))
	if err != nil {
		// Check for context cancellation
		if ctx.Err() != nil {
			if ctx.Err() == context.Canceled {
				http.Error(w, "request canceled", http.StatusRequestTimeout)
			} else {
				http.Error(w, "request timeout", http.StatusGatewayTimeout)
			}
			return
		}
		s.writeJSON(w, http.StatusUnprocessableEntity, map[string]interface{}{
			"error":      err.Error(),
			"detections": []cipher.DetectionResult{},
		})
		return
	}

	s.writeJSON(w, http.StatusOK, CipherDetectResponse{
		Detections: detections,
	})
}

// handleCipherSmartDecode handles smart auto-decode
func (s *Server) handleCipherSmartDecode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CipherSmartDecodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Input == "" {
		http.Error(w, "input field is required", http.StatusBadRequest)
		return
	}

	// Use the smart detector to detect encoding with request context for proper cancellation and tracing
	detector := cipher.NewSmartDetector()
	ctx := r.Context()

	detections, err := detector.Detect(ctx, []byte(req.Input))
	if err != nil {
		// Check for context cancellation
		if ctx.Err() != nil {
			if ctx.Err() == context.Canceled {
				http.Error(w, "request canceled", http.StatusRequestTimeout)
			} else {
				http.Error(w, "request timeout", http.StatusGatewayTimeout)
			}
			return
		}
	}
	if err != nil || len(detections) == 0 {
		s.writeJSON(w, http.StatusUnprocessableEntity, CipherSmartDecodeResponse{
			Error: "could not detect encoding",
		})
		return
	}

	// Use the top detection result
	topDetection := detections[0]

	// Apply the suggested operation
	op, exists := cipher.GetOperation(topDetection.Operation)
	if !exists {
		s.writeJSON(w, http.StatusInternalServerError, CipherSmartDecodeResponse{
			Error: "operation not found: " + topDetection.Operation,
		})
		return
	}

	result, err := op.Execute(ctx, []byte(req.Input), nil)
	if err != nil {
		// Check for context cancellation
		if ctx.Err() != nil {
			if ctx.Err() == context.Canceled {
				http.Error(w, "request canceled", http.StatusRequestTimeout)
			} else {
				http.Error(w, "request timeout", http.StatusGatewayTimeout)
			}
			return
		}
		s.writeJSON(w, http.StatusUnprocessableEntity, CipherSmartDecodeResponse{
			Error: err.Error(),
		})
		return
	}

	// Build pipeline
	pipelineNames := []string{topDetection.Operation}

	s.writeJSON(w, http.StatusOK, CipherSmartDecodeResponse{
		Output:     string(result),
		Pipeline:   pipelineNames,
		Confidence: topDetection.Confidence,
	})
}

// handleCipherListOperations handles listing all available operations
func (s *Server) handleCipherListOperations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	operations := cipher.ListOperations()

	// Convert to a simple list of operation info
	type OperationInfo struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		Description string `json:"description"`
		Reversible  bool   `json:"reversible"`
	}

	var opList []OperationInfo
	for _, op := range operations {
		opName := op.Name()
		opTypeStr := string(op.Type())

		_, reversible := op.Reverse()

		opList = append(opList, OperationInfo{
			Name:        opName,
			Type:        opTypeStr,
			Description: op.Description(),
			Reversible:  reversible,
		})
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"operations": opList,
	})
}

// handleRecipeSave handles saving a new recipe
func (s *Server) handleRecipeSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RecipeSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	recipe := &cipher.Recipe{
		Name:        req.Name,
		Description: req.Description,
		Tags:        req.Tags,
		Pipeline: cipher.Pipeline{
			Operations: req.Operations,
		},
	}

	if err := s.recipeManager.SaveRecipe(recipe); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"status": "saved",
	})
}

// handleRecipeList handles listing all recipes
func (s *Server) handleRecipeList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	recipes := s.recipeManager.ListRecipes()

	// Convert from []*Recipe to []Recipe for JSON marshaling
	recipeList := make([]cipher.Recipe, len(recipes))
	for i, r := range recipes {
		recipeList[i] = *r
	}

	s.writeJSON(w, http.StatusOK, RecipeListResponse{
		Recipes: recipeList,
	})
}

// handleRecipeLoad handles loading a specific recipe
func (s *Server) handleRecipeLoad(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "recipe name required", http.StatusBadRequest)
		return
	}

	recipe, exists := s.recipeManager.GetRecipe(name)
	if !exists {
		http.Error(w, "recipe not found", http.StatusNotFound)
		return
	}

	s.writeJSON(w, http.StatusOK, RecipeExportResponse{
		Recipe: *recipe,
	})
}

// handleRecipeDelete handles deleting a recipe
func (s *Server) handleRecipeDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "recipe name required", http.StatusBadRequest)
		return
	}

	if err := s.recipeManager.DeleteRecipe(name); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"status": "deleted",
	})
}
