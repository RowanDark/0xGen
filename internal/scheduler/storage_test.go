package scheduler

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStorageSaveAndLoadSchedule(t *testing.T) {
	// Create temporary directory for test
	tmpDir := t.TempDir()

	storage, err := NewStorage(tmpDir)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}

	// Create a test schedule
	now := time.Now().UTC()
	schedule := &Schedule{
		Name:        "Test Schedule",
		Description: "A test schedule",
		Enabled:     true,
		CronExpr:    "0 2 * * *",
		Target:      "https://example.com",
		Template:    "bug-bounty",
		ScanType:    "blitz",
		NextRun:     &now,
		Options:     map[string]string{"depth": "2"},
		Actions: []Action{
			{
				Type:   ActionReport,
				Config: map[string]string{"format": "json"},
			},
		},
	}

	// Save schedule
	if err := storage.SaveSchedule(schedule); err != nil {
		t.Fatalf("SaveSchedule() error = %v", err)
	}

	if schedule.ID == "" {
		t.Error("SaveSchedule() should generate an ID")
	}

	// Load schedule
	loaded, err := storage.LoadSchedule(schedule.ID)
	if err != nil {
		t.Fatalf("LoadSchedule() error = %v", err)
	}

	// Verify fields
	if loaded.Name != schedule.Name {
		t.Errorf("Name = %q, want %q", loaded.Name, schedule.Name)
	}
	if loaded.Description != schedule.Description {
		t.Errorf("Description = %q, want %q", loaded.Description, schedule.Description)
	}
	if loaded.Enabled != schedule.Enabled {
		t.Errorf("Enabled = %v, want %v", loaded.Enabled, schedule.Enabled)
	}
	if loaded.CronExpr != schedule.CronExpr {
		t.Errorf("CronExpr = %q, want %q", loaded.CronExpr, schedule.CronExpr)
	}
	if loaded.Target != schedule.Target {
		t.Errorf("Target = %q, want %q", loaded.Target, schedule.Target)
	}
	if len(loaded.Actions) != len(schedule.Actions) {
		t.Errorf("Actions length = %d, want %d", len(loaded.Actions), len(schedule.Actions))
	}
}

func TestStorageListSchedules(t *testing.T) {
	tmpDir := t.TempDir()

	storage, err := NewStorage(tmpDir)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}

	// Create multiple schedules
	schedules := []*Schedule{
		{
			Name:     "Schedule 1",
			Enabled:  true,
			CronExpr: "0 2 * * *",
			Target:   "https://example.com",
			ScanType: "blitz",
		},
		{
			Name:     "Schedule 2",
			Enabled:  false,
			CronExpr: "0 3 * * *",
			Target:   "https://example.org",
			ScanType: "raider",
		},
	}

	for _, sched := range schedules {
		if err := storage.SaveSchedule(sched); err != nil {
			t.Fatalf("SaveSchedule() error = %v", err)
		}
	}

	// List schedules
	list, err := storage.ListSchedules()
	if err != nil {
		t.Fatalf("ListSchedules() error = %v", err)
	}

	if len(list) != len(schedules) {
		t.Errorf("ListSchedules() returned %d schedules, want %d", len(list), len(schedules))
	}
}

func TestStorageDeleteSchedule(t *testing.T) {
	tmpDir := t.TempDir()

	storage, err := NewStorage(tmpDir)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}

	// Create a schedule
	schedule := &Schedule{
		Name:     "Test Schedule",
		Enabled:  true,
		CronExpr: "0 2 * * *",
		Target:   "https://example.com",
		ScanType: "blitz",
	}

	if err := storage.SaveSchedule(schedule); err != nil {
		t.Fatalf("SaveSchedule() error = %v", err)
	}

	// Delete schedule
	if err := storage.DeleteSchedule(schedule.ID); err != nil {
		t.Fatalf("DeleteSchedule() error = %v", err)
	}

	// Verify deletion
	_, err = storage.LoadSchedule(schedule.ID)
	if err == nil {
		t.Error("LoadSchedule() should return error for deleted schedule")
	}
}

func TestStorageFindScheduleByName(t *testing.T) {
	tmpDir := t.TempDir()

	storage, err := NewStorage(tmpDir)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}

	// Create schedules
	schedule := &Schedule{
		Name:     "My Test Schedule",
		Enabled:  true,
		CronExpr: "0 2 * * *",
		Target:   "https://example.com",
		ScanType: "blitz",
	}

	if err := storage.SaveSchedule(schedule); err != nil {
		t.Fatalf("SaveSchedule() error = %v", err)
	}

	// Find by name (case insensitive)
	found, err := storage.FindScheduleByName("my test schedule")
	if err != nil {
		t.Fatalf("FindScheduleByName() error = %v", err)
	}

	if found.ID != schedule.ID {
		t.Errorf("FindScheduleByName() found wrong schedule: got ID %s, want %s", found.ID, schedule.ID)
	}

	// Try to find non-existent
	_, err = storage.FindScheduleByName("Non-existent")
	if err == nil {
		t.Error("FindScheduleByName() should return error for non-existent schedule")
	}
}

func TestStorageSaveAndLoadWorkflow(t *testing.T) {
	tmpDir := t.TempDir()

	storage, err := NewStorage(tmpDir)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}

	// Create a test workflow
	workflow := &Workflow{
		Name:        "Test Workflow",
		Description: "A test workflow",
		Enabled:     true,
		Trigger: WorkflowTrigger{
			Schedule: "0 2 * * *",
			Manual:   true,
		},
		Steps: []WorkflowStep{
			{
				Name:   "Scan",
				Action: "scan",
				Config: map[string]string{"target": "https://example.com"},
			},
			{
				Name:   "Report",
				Action: "report",
				Config: map[string]string{"format": "json"},
			},
		},
		Variables: map[string]string{"target": "example.com"},
	}

	// Save workflow
	if err := storage.SaveWorkflow(workflow); err != nil {
		t.Fatalf("SaveWorkflow() error = %v", err)
	}

	if workflow.ID == "" {
		t.Error("SaveWorkflow() should generate an ID")
	}

	// Load workflow
	loaded, err := storage.LoadWorkflow(workflow.ID)
	if err != nil {
		t.Fatalf("LoadWorkflow() error = %v", err)
	}

	// Verify fields
	if loaded.Name != workflow.Name {
		t.Errorf("Name = %q, want %q", loaded.Name, workflow.Name)
	}
	if len(loaded.Steps) != len(workflow.Steps) {
		t.Errorf("Steps length = %d, want %d", len(loaded.Steps), len(workflow.Steps))
	}
	if loaded.Steps[0].Name != workflow.Steps[0].Name {
		t.Errorf("Step[0].Name = %q, want %q", loaded.Steps[0].Name, workflow.Steps[0].Name)
	}
}

func TestStorageWorkflowOperations(t *testing.T) {
	tmpDir := t.TempDir()

	storage, err := NewStorage(tmpDir)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}

	// Create workflow
	workflow := &Workflow{
		Name:    "Test Workflow",
		Enabled: true,
		Trigger: WorkflowTrigger{Manual: true},
		Steps: []WorkflowStep{
			{Name: "Step 1", Action: "scan"},
		},
	}

	if err := storage.SaveWorkflow(workflow); err != nil {
		t.Fatalf("SaveWorkflow() error = %v", err)
	}

	// List workflows
	list, err := storage.ListWorkflows()
	if err != nil {
		t.Fatalf("ListWorkflows() error = %v", err)
	}

	if len(list) != 1 {
		t.Errorf("ListWorkflows() returned %d workflows, want 1", len(list))
	}

	// Find by name
	found, err := storage.FindWorkflowByName("Test Workflow")
	if err != nil {
		t.Fatalf("FindWorkflowByName() error = %v", err)
	}

	if found.ID != workflow.ID {
		t.Errorf("FindWorkflowByName() found wrong workflow")
	}

	// Delete workflow
	if err := storage.DeleteWorkflow(workflow.ID); err != nil {
		t.Fatalf("DeleteWorkflow() error = %v", err)
	}

	// Verify deletion
	_, err = storage.LoadWorkflow(workflow.ID)
	if err == nil {
		t.Error("LoadWorkflow() should return error for deleted workflow")
	}
}

func TestStorageEnsureDirectories(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := NewStorage(tmpDir)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}

	// Check that directories were created
	schedulesPath := filepath.Join(tmpDir, schedulesDir)
	workflowsPath := filepath.Join(tmpDir, workflowsDir)

	if _, err := os.Stat(schedulesPath); os.IsNotExist(err) {
		t.Errorf("Schedules directory was not created: %s", schedulesPath)
	}

	if _, err := os.Stat(workflowsPath); os.IsNotExist(err) {
		t.Errorf("Workflows directory was not created: %s", workflowsPath)
	}
}
