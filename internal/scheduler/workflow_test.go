package scheduler

import (
	"context"
	"testing"
)

func TestParseWorkflowYAML(t *testing.T) {
	yamlData := `
name: Security Scan Workflow
description: Comprehensive security workflow
trigger:
  schedule: "0 2 * * *"
  manual: true
steps:
  - name: Initial Scan
    action: scan
    config:
      target: https://example.com
      template: bug-bounty
  - name: Compare Results
    action: compare
    condition: findings.total > 0
    config:
      baseline: true
  - name: Send Notification
    action: notify
    condition: findings.critical > 0
    config:
      channel: slack
variables:
  target: example.com
  severity_threshold: critical
`

	workflow, err := ParseWorkflowYAML([]byte(yamlData))
	if err != nil {
		t.Fatalf("ParseWorkflowYAML() error = %v", err)
	}

	if workflow.Name != "Security Scan Workflow" {
		t.Errorf("Name = %q, want %q", workflow.Name, "Security Scan Workflow")
	}

	if workflow.Trigger.Schedule != "0 2 * * *" {
		t.Errorf("Trigger.Schedule = %q, want %q", workflow.Trigger.Schedule, "0 2 * * *")
	}

	if !workflow.Trigger.Manual {
		t.Error("Trigger.Manual should be true")
	}

	if len(workflow.Steps) != 3 {
		t.Fatalf("Steps length = %d, want 3", len(workflow.Steps))
	}

	// Check first step
	if workflow.Steps[0].Name != "Initial Scan" {
		t.Errorf("Steps[0].Name = %q, want %q", workflow.Steps[0].Name, "Initial Scan")
	}
	if workflow.Steps[0].Action != "scan" {
		t.Errorf("Steps[0].Action = %q, want %q", workflow.Steps[0].Action, "scan")
	}

	// Check condition on second step
	if workflow.Steps[1].Condition != "findings.total > 0" {
		t.Errorf("Steps[1].Condition = %q, want %q", workflow.Steps[1].Condition, "findings.total > 0")
	}

	// Check variables
	if len(workflow.Variables) != 2 {
		t.Errorf("Variables length = %d, want 2", len(workflow.Variables))
	}
	if workflow.Variables["target"] != "example.com" {
		t.Errorf("Variables[target] = %q, want %q", workflow.Variables["target"], "example.com")
	}
}

func TestValidateWorkflow(t *testing.T) {
	tests := []struct {
		name      string
		workflow  *Workflow
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid workflow",
			workflow: &Workflow{
				Name: "Test",
				Trigger: WorkflowTrigger{
					Manual: true,
				},
				Steps: []WorkflowStep{
					{Name: "Step 1", Action: "scan"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			workflow: &Workflow{
				Trigger: WorkflowTrigger{Manual: true},
				Steps: []WorkflowStep{
					{Name: "Step 1", Action: "scan"},
				},
			},
			wantErr:   true,
			errSubstr: "name is required",
		},
		{
			name: "no steps",
			workflow: &Workflow{
				Name:    "Test",
				Trigger: WorkflowTrigger{Manual: true},
				Steps:   []WorkflowStep{},
			},
			wantErr:   true,
			errSubstr: "at least one step",
		},
		{
			name: "no triggers",
			workflow: &Workflow{
				Name:    "Test",
				Trigger: WorkflowTrigger{},
				Steps: []WorkflowStep{
					{Name: "Step 1", Action: "scan"},
				},
			},
			wantErr:   true,
			errSubstr: "at least one trigger",
		},
		{
			name: "step missing name",
			workflow: &Workflow{
				Name: "Test",
				Trigger: WorkflowTrigger{
					Manual: true,
				},
				Steps: []WorkflowStep{
					{Action: "scan"},
				},
			},
			wantErr:   true,
			errSubstr: "name is required",
		},
		{
			name: "step missing action",
			workflow: &Workflow{
				Name: "Test",
				Trigger: WorkflowTrigger{
					Manual: true,
				},
				Steps: []WorkflowStep{
					{Name: "Step 1"},
				},
			},
			wantErr:   true,
			errSubstr: "action is required",
		},
		{
			name: "invalid action",
			workflow: &Workflow{
				Name: "Test",
				Trigger: WorkflowTrigger{
					Manual: true,
				},
				Steps: []WorkflowStep{
					{Name: "Step 1", Action: "invalid_action"},
				},
			},
			wantErr:   true,
			errSubstr: "invalid action",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWorkflow(tt.workflow)
			if tt.wantErr {
				if err == nil {
					t.Error("validateWorkflow() expected error but got none")
				} else if tt.errSubstr != "" && !contains(err.Error(), tt.errSubstr) {
					t.Errorf("validateWorkflow() error = %v, want substring %q", err, tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Errorf("validateWorkflow() error = %v, want nil", err)
			}
		})
	}
}

func TestWorkflowEngineExecute(t *testing.T) {
	tmpDir := t.TempDir()

	storage, err := NewStorage(tmpDir)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}

	engine := NewWorkflowEngine(storage)

	// Create a simple workflow
	workflow := &Workflow{
		ID:   "test-workflow",
		Name: "Test Workflow",
		Trigger: WorkflowTrigger{
			Manual: true,
		},
		Steps: []WorkflowStep{
			{
				Name:   "Scan Target",
				Action: "scan",
				Config: map[string]string{
					"target": "https://example.com",
				},
			},
			{
				Name:   "Generate Report",
				Action: "report",
				Config: map[string]string{
					"format": "json",
				},
			},
		},
		Variables: map[string]string{
			"target": "example.com",
		},
	}

	ctx := context.Background()
	execution, err := engine.Execute(ctx, workflow)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if execution.WorkflowID != workflow.ID {
		t.Errorf("WorkflowID = %q, want %q", execution.WorkflowID, workflow.ID)
	}

	if execution.Status != ExecutionStatusCompleted {
		t.Errorf("Status = %v, want %v", execution.Status, ExecutionStatusCompleted)
	}

	if len(execution.Steps) != len(workflow.Steps) {
		t.Errorf("Steps length = %d, want %d", len(execution.Steps), len(workflow.Steps))
	}

	// Check that variables were initialized in context
	if execution.Context["target"] != "example.com" {
		t.Errorf("Context[target] = %v, want %q", execution.Context["target"], "example.com")
	}
}

func TestWorkflowEngineExecuteWithConditions(t *testing.T) {
	tmpDir := t.TempDir()

	storage, err := NewStorage(tmpDir)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}

	engine := NewWorkflowEngine(storage)

	// Create a workflow with conditions
	workflow := &Workflow{
		ID:   "test-workflow",
		Name: "Test Workflow",
		Trigger: WorkflowTrigger{
			Manual: true,
		},
		Steps: []WorkflowStep{
			{
				Name:   "Scan Target",
				Action: "scan",
				Config: map[string]string{
					"target": "https://example.com",
				},
			},
			{
				Name:      "Notify on Critical",
				Action:    "notify",
				Condition: "findings.critical > 0",
				Config: map[string]string{
					"channel": "slack",
				},
			},
			{
				Name:      "Never Execute",
				Action:    "notify",
				Condition: "findings.critical > 100",
				Config: map[string]string{
					"channel": "email",
				},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.Execute(ctx, workflow)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	// Check step statuses
	if execution.Steps[0].Status != StepStatusCompleted {
		t.Errorf("Step[0].Status = %v, want %v", execution.Steps[0].Status, StepStatusCompleted)
	}

	// Second step should complete (condition met because scan sets findings.critical = 1)
	if execution.Steps[1].Status != StepStatusCompleted {
		t.Errorf("Step[1].Status = %v, want %v", execution.Steps[1].Status, StepStatusCompleted)
	}

	// Third step should be skipped (condition not met)
	if execution.Steps[2].Status != StepStatusSkipped {
		t.Errorf("Step[2].Status = %v, want %v", execution.Steps[2].Status, StepStatusSkipped)
	}
}

func TestEvaluateCondition(t *testing.T) {
	tmpDir := t.TempDir()

	storage, err := NewStorage(tmpDir)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}

	engine := NewWorkflowEngine(storage)

	tests := []struct {
		name      string
		condition string
		context   map[string]interface{}
		expected  bool
	}{
		{
			name:      "critical findings greater than zero",
			condition: "findings.critical > 0",
			context: map[string]interface{}{
				"findings.critical": 5,
			},
			expected: true,
		},
		{
			name:      "total findings greater than threshold",
			condition: "findings.total > 10",
			context: map[string]interface{}{
				"findings.total": 15,
			},
			expected: true,
		},
		{
			name:      "boolean condition true",
			condition: "has_findings",
			context: map[string]interface{}{
				"has_findings": true,
			},
			expected: true,
		},
		{
			name:      "boolean condition false",
			condition: "has_findings",
			context: map[string]interface{}{
				"has_findings": false,
			},
			expected: false,
		},
		{
			name:      "double-digit numeric comparison - 10 > 9 should be true",
			condition: "findings.critical > 9",
			context: map[string]interface{}{
				"findings.critical": 10,
			},
			expected: true,
		},
		{
			name:      "double-digit numeric comparison - 100 > 9 should be true",
			condition: "findings.total > 9",
			context: map[string]interface{}{
				"findings.total": 100,
			},
			expected: true,
		},
		{
			name:      "numeric comparison - 5 > 9 should be false",
			condition: "findings.critical > 9",
			context: map[string]interface{}{
				"findings.critical": 5,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.evaluateCondition(tt.condition, tt.context)
			if result != tt.expected {
				t.Errorf("evaluateCondition() = %v, want %v", result, tt.expected)
			}
		})
	}
}
