package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

// IntegrationType specifies the type of integration.
type IntegrationType string

const (
	IntegrationSlack   IntegrationType = "slack"
	IntegrationWebhook IntegrationType = "webhook"
)

// IntegrationConfig holds configuration for sending reports to external systems.
type IntegrationConfig struct {
	Type         IntegrationType
	URL          string
	Headers      map[string]string
	Timeout      time.Duration
	CustomFormat bool // If true, send raw report data; else use integration-specific format
}

// SlackPayload represents a Slack message payload.
type SlackPayload struct {
	Text        string             `json:"text,omitempty"`
	Blocks      []SlackBlock       `json:"blocks,omitempty"`
	Attachments []SlackAttachment  `json:"attachments,omitempty"`
}

// SlackBlock represents a Slack block element.
type SlackBlock struct {
	Type string                 `json:"type"`
	Text *SlackTextObject       `json:"text,omitempty"`
	Fields []SlackTextObject    `json:"fields,omitempty"`
}

// SlackTextObject represents text in a Slack message.
type SlackTextObject struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// SlackAttachment represents a Slack message attachment.
type SlackAttachment struct {
	Color  string       `json:"color,omitempty"`
	Title  string       `json:"title,omitempty"`
	Text   string       `json:"text,omitempty"`
	Fields []SlackField `json:"fields,omitempty"`
}

// SlackField represents a field in a Slack attachment.
type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// WebhookPayload represents a generic webhook payload.
type WebhookPayload struct {
	Event     string      `json:"event"`
	Timestamp string      `json:"timestamp"`
	Summary   interface{} `json:"summary"`
	Findings  interface{} `json:"findings"`
}

// SendToSlack sends a report summary to Slack.
func SendToSlack(webhookURL string, list []findings.Finding, opts ReportOptions) error {
	summary, filteredList, _, _ := buildSummary(list, opts)

	// Build Slack message
	payload := buildSlackPayload(summary, filteredList)

	return sendSlackMessage(webhookURL, payload, 30*time.Second)
}

// SendToWebhook sends a report to a generic webhook.
func SendToWebhook(webhookURL string, list []findings.Finding, opts ReportOptions, customHeaders map[string]string) error {
	summary, filteredList, _, _ := buildSummary(list, opts)

	// Build webhook payload
	payload := WebhookPayload{
		Event:     "scan_complete",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Summary:   summary,
		Findings:  filteredList,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	return sendHTTPPost(webhookURL, "application/json", data, customHeaders, 30*time.Second)
}

// SendReportViaIntegration sends a report using the specified integration.
func SendReportViaIntegration(config IntegrationConfig, list []findings.Finding, opts ReportOptions) error {
	switch config.Type {
	case IntegrationSlack:
		return SendToSlack(config.URL, list, opts)
	case IntegrationWebhook:
		return SendToWebhook(config.URL, list, opts, config.Headers)
	default:
		return fmt.Errorf("unsupported integration type: %s", config.Type)
	}
}

// buildSlackPayload creates a formatted Slack message from findings.
func buildSlackPayload(summary Summary, findingsList []findings.Finding) SlackPayload {
	// Determine color based on severity distribution
	color := determineOverallColor(summary.SeverityCount)

	// Build summary text
	summaryText := fmt.Sprintf("*Security Scan Complete*\n\n")
	summaryText += fmt.Sprintf("Total Findings: *%d*\n", summary.Total)
	summaryText += fmt.Sprintf("• Critical: %d\n", summary.SeverityCount[findings.SeverityCritical])
	summaryText += fmt.Sprintf("• High: %d\n", summary.SeverityCount[findings.SeverityHigh])
	summaryText += fmt.Sprintf("• Medium: %d\n", summary.SeverityCount[findings.SeverityMedium])
	summaryText += fmt.Sprintf("• Low: %d\n", summary.SeverityCount[findings.SeverityLow])
	summaryText += fmt.Sprintf("• Info: %d\n", summary.SeverityCount[findings.SeverityInfo])

	payload := SlackPayload{
		Attachments: []SlackAttachment{
			{
				Color: color,
				Title: "Scan Summary",
				Text:  summaryText,
			},
		},
	}

	// Add top targets if available
	if len(summary.Targets) > 0 {
		var targetsText string
		for i, tc := range summary.Targets {
			if i >= 5 {
				break // Limit to top 5
			}
			targetsText += fmt.Sprintf("• %s (%d)\n", tc.Target, tc.Count)
		}

		if targetsText != "" {
			payload.Attachments = append(payload.Attachments, SlackAttachment{
				Color: "#36a64f",
				Title: "Top Targets",
				Text:  targetsText,
			})
		}
	}

	// Add recent critical/high findings
	criticalHighFindings := filterBySeverity(findingsList, []findings.Severity{
		findings.SeverityCritical,
		findings.SeverityHigh,
	})

	if len(criticalHighFindings) > 0 {
		var findingsText string
		count := 0
		for _, f := range criticalHighFindings {
			if count >= 3 {
				break // Limit to 3
			}
			findingsText += fmt.Sprintf("*%s* - %s\n", f.Type, f.Target)
			findingsText += fmt.Sprintf("_%s_\n\n", truncateForSlack(f.Message, 100))
			count++
		}

		if findingsText != "" {
			payload.Attachments = append(payload.Attachments, SlackAttachment{
				Color: determineColor(findings.SeverityCritical),
				Title: "Critical/High Findings",
				Text:  findingsText,
			})
		}
	}

	return payload
}

// sendSlackMessage sends a message to Slack webhook.
func sendSlackMessage(webhookURL string, payload SlackPayload, timeout time.Duration) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal Slack payload: %w", err)
	}

	return sendHTTPPost(webhookURL, "application/json", data, nil, timeout)
}

// sendHTTPPost sends an HTTP POST request.
func sendHTTPPost(url, contentType string, body []byte, headers map[string]string, timeout time.Duration) error {
	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "0xGen-Reporter/1.0")

	// Add custom headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Helper functions

func determineOverallColor(severityCount map[findings.Severity]int) string {
	if severityCount[findings.SeverityCritical] > 0 {
		return "#b91c1c" // Red
	}
	if severityCount[findings.SeverityHigh] > 0 {
		return "#c2410c" // Orange
	}
	if severityCount[findings.SeverityMedium] > 0 {
		return "#eab308" // Yellow
	}
	if severityCount[findings.SeverityLow] > 0 {
		return "#2563eb" // Blue
	}
	return "#94a3b8" // Gray
}

func determineColor(severity findings.Severity) string {
	switch severity {
	case findings.SeverityCritical:
		return "#b91c1c"
	case findings.SeverityHigh:
		return "#c2410c"
	case findings.SeverityMedium:
		return "#eab308"
	case findings.SeverityLow:
		return "#2563eb"
	default:
		return "#94a3b8"
	}
}

func filterBySeverity(list []findings.Finding, severities []findings.Severity) []findings.Finding {
	severitySet := make(map[findings.Severity]bool)
	for _, s := range severities {
		severitySet[s] = true
	}

	var filtered []findings.Finding
	for _, f := range list {
		if severitySet[f.Severity] {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func truncateForSlack(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
