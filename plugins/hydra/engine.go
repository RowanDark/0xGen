package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

type hydraEngine struct {
	analyzers []analyzer
	evaluator aiEvaluator
	now       func() time.Time
}

type analyzer interface {
	ID() string
	Analyse(responseContext) *analysisCandidate
}

type aiEvaluator interface {
	Decide(*analysisCandidate) (analysisDecision, bool)
}

type analysisDecision struct {
	Message   string
	Severity  pluginsdk.Severity
	Rationale string
	Policy    string
}

type responseContext struct {
	URL        string
	Host       string
	StatusCode int
	Headers    http.Header
	Body       []byte
	BodyText   string
	BodyLower  string
}

type analysisCandidate struct {
	AnalyzerID string
	Category   string
	Type       string
	Summary    string
	Evidence   string
	Confidence float64
	Severity   pluginsdk.Severity
	TargetURL  string
	Host       string
	Vector     string
	StatusCode int
	Metadata   map[string]string
}

func newHydraEngine(now func() time.Time) *hydraEngine {
	if now == nil {
		now = time.Now
	}
	return &hydraEngine{
		analyzers: []analyzer{
			newXSSAnalyzer(),
			newSQLiAnalyzer(),
			newSSRFAnalyzer(),
			newCommandInjectionAnalyzer(),
			newOpenRedirectAnalyzer(),
		},
		evaluator: newLLMConsensus(),
		now:       now,
	}
}

func (e *hydraEngine) process(ctx *pluginsdk.Context, event pluginsdk.HTTPPassiveEvent) error {
	if event.Response == nil {
		return nil
	}
	respCtx := buildResponseContext(event.Response)
	for _, analyzer := range e.analyzers {
		candidate := analyzer.Analyse(respCtx)
		if candidate == nil {
			continue
		}
		decision, ok := e.evaluator.Decide(candidate)
		if !ok {
			ctx.Logger().Debug("candidate rejected by AI consensus", "analyzer", analyzer.ID(), "confidence", fmt.Sprintf("%.2f", candidate.Confidence))
			continue
		}
		finding := pluginsdk.Finding{
			Type:       candidate.Type,
			Message:    decision.Message,
			Target:     candidate.TargetURL,
			Evidence:   candidate.Evidence,
			Severity:   decision.Severity,
			DetectedAt: e.now().UTC(),
			Metadata:   buildMetadata(candidate, decision),
		}
		if strings.TrimSpace(finding.Target) == "" {
			finding.Target = candidate.Host
		}
		if strings.TrimSpace(finding.Target) == "" {
			finding.Target = "hydra://unknown-target"
		}
		if err := ctx.EmitFinding(finding); err != nil {
			return fmt.Errorf("emit finding: %w", err)
		}
		ctx.Logger().Info("finding emitted", "type", finding.Type, "policy", decision.Policy, "confidence", finding.Metadata["analysis_confidence"])
	}
	return nil
}

func buildResponseContext(resp *pluginsdk.HTTPResponse) responseContext {
	if resp == nil {
		return responseContext{}
	}
	clonedHeaders := http.Header{}
	for k, values := range resp.Headers {
		copied := make([]string, len(values))
		copy(copied, values)
		clonedHeaders[k] = copied
	}
	url, host := deriveTarget(clonedHeaders)
	bodyText := string(resp.Body)
	return responseContext{
		URL:        url,
		Host:       host,
		StatusCode: parseStatusCode(resp.StatusLine),
		Headers:    clonedHeaders,
		Body:       append([]byte(nil), resp.Body...),
		BodyText:   bodyText,
		BodyLower:  strings.ToLower(bodyText),
	}
}

func buildMetadata(candidate *analysisCandidate, decision analysisDecision) map[string]string {
	metadata := make(map[string]string, len(candidate.Metadata)+10)
	for k, v := range candidate.Metadata {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			continue
		}
		metadata[k] = v
	}
	metadata["analysis_mode"] = "ai_hybrid"
	metadata["analysis_engine"] = "hydra"
	metadata["analysis_confidence"] = fmt.Sprintf("%.2f", candidate.Confidence)
	metadata["analysis_policy"] = decision.Policy
	metadata["analysis_rationale"] = decision.Rationale
	metadata["signal_source"] = candidate.AnalyzerID
	metadata["vector"] = candidate.Vector
	if candidate.StatusCode > 0 {
		metadata["status_code"] = strconv.Itoa(candidate.StatusCode)
	}
	metadata["asset_kind"] = "web"
	assetID := candidate.Host
	if strings.TrimSpace(assetID) == "" {
		assetID = candidate.TargetURL
	}
	if strings.TrimSpace(assetID) == "" {
		assetID = "unknown"
	}
	metadata["asset_id"] = assetID
	if strings.TrimSpace(candidate.TargetURL) != "" {
		metadata["asset_detail"] = candidate.TargetURL
	}
	return metadata
}
