package scheduler

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"gopkg.in/yaml.v3"
)

// WorkflowEngine executes workflows.
type WorkflowEngine struct {
	storage *Storage
}

// NewWorkflowEngine creates a new workflow engine.
func NewWorkflowEngine(storage *Storage) *WorkflowEngine {
	return &WorkflowEngine{
		storage: storage,
	}
}

// LoadWorkflowFromFile loads a workflow definition from a YAML file.
func LoadWorkflowFromFile(path string) (*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read workflow file: %w", err)
	}

	return ParseWorkflowYAML(data)
}

// ParseWorkflowYAML parses a workflow from YAML data.
func ParseWorkflowYAML(data []byte) (*Workflow, error) {
	var workflow Workflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		return nil, fmt.Errorf("parse workflow YAML: %w", err)
	}

	// Validate workflow
	if err := validateWorkflow(&workflow); err != nil {
		return nil, err
	}

	return &workflow, nil
}

// validateWorkflow validates a workflow definition.
func validateWorkflow(workflow *Workflow) error {
	if workflow.Name == "" {
		return fmt.Errorf("workflow name is required")
	}

	if len(workflow.Steps) == 0 {
		return fmt.Errorf("workflow must have at least one step")
	}

	// Check if at least one trigger is enabled
	if !workflow.Trigger.Manual && workflow.Trigger.Schedule == "" && !workflow.Trigger.Webhook {
		return fmt.Errorf("workflow must have at least one trigger enabled")
	}

	// Validate steps
	for i, step := range workflow.Steps {
		if step.Name == "" {
			return fmt.Errorf("step %d: name is required", i)
		}
		if step.Action == "" {
			return fmt.Errorf("step %d (%s): action is required", i, step.Name)
		}

		// Validate action type
		validActions := map[string]bool{
			"scan":     true,
			"compare":  true,
			"notify":   true,
			"report":   true,
			"baseline": true,
			"webhook":  true,
		}
		if !validActions[step.Action] {
			return fmt.Errorf("step %d (%s): invalid action %q", i, step.Name, step.Action)
		}
	}

	return nil
}

// Execute executes a workflow.
func (e *WorkflowEngine) Execute(ctx context.Context, workflow *Workflow) (*WorkflowExecution, error) {
	execution := &WorkflowExecution{
		ID:         ulid.Make().String(),
		WorkflowID: workflow.ID,
		Status:     ExecutionStatusRunning,
		StartedAt:  time.Now().UTC(),
		Steps:      make([]StepExecution, 0, len(workflow.Steps)),
		Context:    make(map[string]interface{}),
	}

	// Initialize context with workflow variables
	for k, v := range workflow.Variables {
		execution.Context[k] = v
	}

	// Execute each step
	for _, step := range workflow.Steps {
		stepExec := e.executeStep(ctx, step, execution)
		execution.Steps = append(execution.Steps, stepExec)

		// Check if step failed
		if stepExec.Status == StepStatusFailed {
			execution.Status = ExecutionStatusFailed
			execution.Error = fmt.Sprintf("step %s failed: %s", step.Name, stepExec.Error)
			now := time.Now().UTC()
			execution.CompletedAt = &now
			return execution, nil
		}

		// Check if step was skipped (condition not met)
		if stepExec.Status == StepStatusSkipped {
			continue
		}

		// Check for cancellation
		select {
		case <-ctx.Done():
			execution.Status = ExecutionStatusCancelled
			now := time.Now().UTC()
			execution.CompletedAt = &now
			return execution, ctx.Err()
		default:
		}
	}

	// All steps completed successfully
	execution.Status = ExecutionStatusCompleted
	now := time.Now().UTC()
	execution.CompletedAt = &now

	return execution, nil
}

// executeStep executes a single workflow step.
func (e *WorkflowEngine) executeStep(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) StepExecution {
	stepExec := StepExecution{
		StepName:  step.Name,
		Status:    StepStatusRunning,
		StartedAt: time.Now().UTC(),
		Output:    make(map[string]interface{}),
	}

	// Check condition
	if step.Condition != "" {
		if !e.evaluateCondition(step.Condition, execution.Context) {
			stepExec.Status = StepStatusSkipped
			now := time.Now().UTC()
			stepExec.CompletedAt = &now
			return stepExec
		}
	}

	// Execute action
	err := e.executeAction(ctx, step, execution)
	if err != nil {
		stepExec.Status = StepStatusFailed
		stepExec.Error = err.Error()
	} else {
		stepExec.Status = StepStatusCompleted
	}

	now := time.Now().UTC()
	stepExec.CompletedAt = &now

	return stepExec
}

// evaluateCondition evaluates a simple condition string.
// Supports basic conditions like:
// - "findings.critical > 0"
// - "findings.total > 10"
// - "severity == critical"
func (e *WorkflowEngine) evaluateCondition(condition string, context map[string]interface{}) bool {
	// This is a simplified condition evaluator
	// In a real implementation, you might want to use a proper expression evaluator

	condition = strings.TrimSpace(condition)

	// Handle "findings.critical > N" pattern
	if strings.Contains(condition, "findings.critical >") {
		parts := strings.Split(condition, ">")
		if len(parts) == 2 {
			thresholdStr := strings.TrimSpace(parts[1])
			threshold, err := strconv.Atoi(thresholdStr)
			if err == nil {
				if criticalCount, ok := context["findings.critical"].(int); ok {
					return criticalCount > threshold
				}
			}
		}
	}

	// Handle "findings.total > N" pattern
	if strings.Contains(condition, "findings.total >") {
		parts := strings.Split(condition, ">")
		if len(parts) == 2 {
			thresholdStr := strings.TrimSpace(parts[1])
			threshold, err := strconv.Atoi(thresholdStr)
			if err == nil {
				if totalCount, ok := context["findings.total"].(int); ok {
					return totalCount > threshold
				}
			}
		}
	}

	// Handle "severity == VALUE" pattern
	if strings.Contains(condition, "==") {
		parts := strings.Split(condition, "==")
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			expectedValue := strings.TrimSpace(parts[1])
			if actualValue, ok := context[key].(string); ok {
				return actualValue == expectedValue
			}
		}
	}

	// Handle boolean values
	if val, ok := context[condition].(bool); ok {
		return val
	}

	// Default to true if condition can't be evaluated
	return true
}

// executeAction executes a workflow step action.
func (e *WorkflowEngine) executeAction(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) error {
	switch step.Action {
	case "scan":
		return e.executeScanAction(ctx, step, execution)
	case "compare":
		return e.executeCompareAction(ctx, step, execution)
	case "notify":
		return e.executeNotifyAction(ctx, step, execution)
	case "report":
		return e.executeReportAction(ctx, step, execution)
	case "baseline":
		return e.executeBaselineAction(ctx, step, execution)
	case "webhook":
		return e.executeWebhookAction(ctx, step, execution)
	default:
		return fmt.Errorf("unsupported action: %s", step.Action)
	}
}

// executeScanAction executes a scan action.
func (e *WorkflowEngine) executeScanAction(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) error {
	target := step.Config["target"]
	if target == "" {
		return fmt.Errorf("scan action requires 'target' in config")
	}

	// Placeholder for actual scan execution
	fmt.Printf("Executing scan: target=%s, template=%s\n", target, step.Config["template"])

	// Store scan results in context
	execution.Context["last_scan_id"] = ulid.Make().String()
	execution.Context["findings.total"] = 5
	execution.Context["findings.critical"] = 1

	return nil
}

// executeCompareAction executes a compare action.
func (e *WorkflowEngine) executeCompareAction(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) error {
	fmt.Printf("Executing compare: %v\n", step.Config)
	return nil
}

// executeNotifyAction executes a notify action.
func (e *WorkflowEngine) executeNotifyAction(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) error {
	channel := step.Config["channel"]
	if channel == "" {
		return fmt.Errorf("notify action requires 'channel' in config")
	}

	fmt.Printf("Sending notification to: %s\n", channel)
	return nil
}

// executeReportAction executes a report action.
func (e *WorkflowEngine) executeReportAction(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) error {
	format := step.Config["format"]
	if format == "" {
		format = "md"
	}

	fmt.Printf("Generating report: format=%s\n", format)
	return nil
}

// executeBaselineAction executes a baseline action.
func (e *WorkflowEngine) executeBaselineAction(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) error {
	target := step.Config["target"]
	if target == "" {
		return fmt.Errorf("baseline action requires 'target' in config")
	}

	fmt.Printf("Setting baseline for: %s\n", target)
	return nil
}

// executeWebhookAction executes a webhook action.
func (e *WorkflowEngine) executeWebhookAction(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) error {
	url := step.Config["url"]
	if url == "" {
		return fmt.Errorf("webhook action requires 'url' in config")
	}

	fmt.Printf("Sending webhook to: %s\n", url)
	return nil
}
