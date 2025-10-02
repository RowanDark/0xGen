package exporter

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/RowanDark/Glyph/internal/cases"
	"github.com/RowanDark/Glyph/internal/findings"
)

const (
	sarifSchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion   = "2.1.0"
)

// EncodeSARIF converts cases into a SARIF 2.1.0 log for interoperability with security tooling.
func EncodeSARIF(casesList []cases.Case) ([]byte, error) {
	run := sarifRun{
		Tool: sarifTool{
			Driver: sarifDriver{
				Name:           "Glyph",
				Version:        "dev",
				InformationURI: "https://github.com/RowanDark/Glyph",
				Rules:          make([]sarifReportingDescriptor, 0, len(casesList)),
			},
		},
		Results: make([]sarifResult, 0, len(casesList)),
	}

	for idx, c := range casesList {
		rule := buildSarifRule(c)
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)

		result := buildSarifResult(c, idx)
		run.Results = append(run.Results, result)
	}

	log := sarifLog{
		Schema:  sarifSchemaURI,
		Version: sarifVersion,
		Runs:    []sarifRun{run},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode SARIF: %w", err)
	}
	data = append(data, '\n')
	return data, nil
}

func buildSarifRule(c cases.Case) sarifReportingDescriptor {
	short := firstLine(c.Summary)
	helpText := buildHelpText(c)

	props := map[string]any{
		"glyph": map[string]any{
			"asset":      c.Asset,
			"vector":     c.Vector,
			"risk":       map[string]any{"severity": string(c.Risk.Severity), "score": c.Risk.Score, "rationale": c.Risk.Rationale},
			"confidence": map[string]any{"score": c.Confidence, "log": c.ConfidenceLog},
		},
	}
	if len(c.Labels) > 0 {
		props["glyph"].(map[string]any)["labels"] = c.Labels
	}

	return sarifReportingDescriptor{
		ID:   c.ID,
		Name: ruleName(c),
		ShortDescription: &sarifMultiformatMessageString{
			Text: short,
		},
		FullDescription: &sarifMultiformatMessageString{
			Text: strings.TrimSpace(c.Summary),
		},
		Help:                 &sarifMultiformatMessageString{Text: helpText},
		DefaultConfiguration: &sarifDefaultConfiguration{Level: severityToSARIFLevel(c.Risk.Severity)},
		Properties:           props,
	}
}

func buildSarifResult(c cases.Case, ruleIndex int) sarifResult {
	level := severityToSARIFLevel(c.Risk.Severity)

	glyphProps := map[string]any{
		"case_id":    c.ID,
		"asset":      c.Asset,
		"vector":     c.Vector,
		"risk":       map[string]any{"severity": string(c.Risk.Severity), "score": c.Risk.Score, "rationale": c.Risk.Rationale},
		"confidence": map[string]any{"score": c.Confidence, "log": c.ConfidenceLog},
		"sources":    c.Sources,
		"evidence":   c.Evidence,
	}
	if len(c.Labels) > 0 {
		glyphProps["labels"] = c.Labels
	}

	props := map[string]any{"glyph": glyphProps}

	result := sarifResult{
		RuleID:    c.ID,
		RuleIndex: ruleIndex,
		Level:     level,
		Message:   sarifMessage{Text: strings.TrimSpace(c.Summary)},
		Locations: []sarifLocation{buildSarifLocation(c)},
		PartialFingerprints: map[string]string{
			"glyph.case":  c.ID,
			"glyph.asset": fingerprintForAsset(c.Asset),
		},
		Properties: props,
	}

	if fix := buildFix(c.Proof); fix != nil {
		result.Fixes = []sarifFix{*fix}
	}

	return result
}

func buildSarifLocation(c cases.Case) sarifLocation {
	var uri string
	if u := strings.TrimSpace(c.Asset.Details); u != "" {
		uri = u
	} else if id := strings.TrimSpace(c.Asset.Identifier); id != "" {
		uri = id
	}

	location := sarifLocation{}
	if uri != "" {
		location.PhysicalLocation = &sarifPhysicalLocation{ArtifactLocation: &sarifArtifactLocation{URI: uri}}
	}

	logical := make([]sarifLogicalLocation, 0, 2)
	if id := strings.TrimSpace(c.Asset.Identifier); id != "" {
		logical = append(logical, sarifLogicalLocation{Kind: "asset", Name: id, FullyQualifiedName: strings.TrimSpace(c.Asset.Kind)})
	}
	if vec := strings.TrimSpace(c.Vector.Kind); vec != "" {
		name := vec
		if value := strings.TrimSpace(c.Vector.Value); value != "" {
			name = fmt.Sprintf("%s:%s", vec, value)
		}
		logical = append(logical, sarifLogicalLocation{Kind: "attack-vector", Name: name})
	}
	if len(logical) > 0 {
		location.LogicalLocations = logical
	}
	return location
}

func buildHelpText(c cases.Case) string {
	var b strings.Builder
	if summary := strings.TrimSpace(c.Proof.Summary); summary != "" {
		b.WriteString(summary)
	}
	if len(c.Proof.Steps) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString("Recommended remediation steps:\n")
		for _, step := range c.Proof.Steps {
			cleaned := strings.TrimSpace(step)
			if cleaned == "" {
				continue
			}
			b.WriteString("- ")
			b.WriteString(cleaned)
			b.WriteString("\n")
		}
	}
	return strings.TrimSpace(b.String())
}

func buildFix(proof cases.ProofOfConcept) *sarifFix {
	if len(proof.Steps) == 0 {
		return nil
	}
	var b strings.Builder
	if summary := strings.TrimSpace(proof.Summary); summary != "" {
		b.WriteString(summary)
		b.WriteString("\n\n")
	}
	for i, step := range proof.Steps {
		cleaned := strings.TrimSpace(step)
		if cleaned == "" {
			continue
		}
		b.WriteString(fmt.Sprintf("%d. %s\n", i+1, cleaned))
	}
	text := strings.TrimSpace(b.String())
	if text == "" {
		return nil
	}
	return &sarifFix{Description: &sarifMessage{Text: text}}
}

func fingerprintForAsset(asset cases.Asset) string {
	kind := strings.ToLower(strings.TrimSpace(asset.Kind))
	if kind == "" {
		kind = "generic"
	}
	identifier := strings.TrimSpace(asset.Identifier)
	if identifier == "" {
		identifier = "(unspecified)"
	}
	return fmt.Sprintf("%s:%s", kind, identifier)
}

func ruleName(c cases.Case) string {
	asset := strings.TrimSpace(c.Asset.Identifier)
	if asset == "" {
		asset = "unknown-asset"
	}
	vector := strings.TrimSpace(c.Vector.Kind)
	if vector == "" {
		vector = "unknown-vector"
	}
	return fmt.Sprintf("%s:%s", vector, asset)
}

func firstLine(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	if idx := strings.IndexByte(input, '\n'); idx >= 0 {
		return strings.TrimSpace(input[:idx])
	}
	return input
}

func severityToSARIFLevel(sev findings.Severity) string {
	switch sev {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium:
		return "warning"
	case findings.SeverityLow, findings.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// SARIF domain models kept minimal for schema compliance.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string                     `json:"name"`
	Version        string                     `json:"version,omitempty"`
	InformationURI string                     `json:"informationUri,omitempty"`
	Rules          []sarifReportingDescriptor `json:"rules,omitempty"`
}

type sarifReportingDescriptor struct {
	ID                   string                         `json:"id"`
	Name                 string                         `json:"name,omitempty"`
	ShortDescription     *sarifMultiformatMessageString `json:"shortDescription,omitempty"`
	FullDescription      *sarifMultiformatMessageString `json:"fullDescription,omitempty"`
	Help                 *sarifMultiformatMessageString `json:"help,omitempty"`
	DefaultConfiguration *sarifDefaultConfiguration     `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any                 `json:"properties,omitempty"`
}

type sarifDefaultConfiguration struct {
	Level string `json:"level,omitempty"`
}

type sarifMultiformatMessageString struct {
	Text string `json:"text,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId,omitempty"`
	RuleIndex           int               `json:"ruleIndex,omitempty"`
	Level               string            `json:"level,omitempty"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
	Fixes               []sarifFix        `json:"fixes,omitempty"`
}

type sarifMessage struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation *sarifArtifactLocation `json:"artifactLocation,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri,omitempty"`
}

type sarifLogicalLocation struct {
	Kind               string `json:"kind,omitempty"`
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
}

type sarifFix struct {
	Description *sarifMessage `json:"description,omitempty"`
}
