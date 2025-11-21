package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/RowanDark/0xgen/internal/scheduler"
)

func runWorkflow(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: 0xgenctl workflow <command> [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Commands:")
		fmt.Fprintln(os.Stderr, "  import      Import a workflow from YAML file")
		fmt.Fprintln(os.Stderr, "  list        List all workflows")
		fmt.Fprintln(os.Stderr, "  show        Show workflow details")
		fmt.Fprintln(os.Stderr, "  run         Execute a workflow")
		fmt.Fprintln(os.Stderr, "  enable      Enable a workflow")
		fmt.Fprintln(os.Stderr, "  disable     Disable a workflow")
		fmt.Fprintln(os.Stderr, "  delete      Delete a workflow")
		return 2
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "import":
		return runWorkflowImport(subargs)
	case "list":
		return runWorkflowList(subargs)
	case "show":
		return runWorkflowShow(subargs)
	case "run":
		return runWorkflowRun(subargs)
	case "enable":
		return runWorkflowEnable(subargs)
	case "disable":
		return runWorkflowDisable(subargs)
	case "delete":
		return runWorkflowDelete(subargs)
	default:
		fmt.Fprintf(os.Stderr, "Unknown workflow command: %s\n", subcmd)
		return 2
	}
}

func runWorkflowImport(args []string) int {
	fs := flag.NewFlagSet("workflow import", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	enabled := fs.Bool("enabled", true, "enable workflow immediately")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: 0xgenctl workflow import <workflow.yaml>")
		return 2
	}

	workflowPath := fs.Args()[0]

	// Load workflow from file
	workflow, err := scheduler.LoadWorkflowFromFile(workflowPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading workflow: %v\n", err)
		return 1
	}

	workflow.Enabled = *enabled

	// Save workflow
	storage, err := scheduler.NewStorage("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if err := storage.SaveWorkflow(workflow); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving workflow: %v\n", err)
		return 1
	}

	fmt.Printf("Workflow imported: %s\n", workflow.ID)
	fmt.Printf("Name: %s\n", workflow.Name)
	fmt.Printf("Steps: %d\n", len(workflow.Steps))
	fmt.Printf("Enabled: %t\n", workflow.Enabled)

	// Show triggers
	var triggers []string
	if workflow.Trigger.Manual {
		triggers = append(triggers, "manual")
	}
	if workflow.Trigger.Schedule != "" {
		triggers = append(triggers, fmt.Sprintf("schedule (%s)", workflow.Trigger.Schedule))
	}
	if workflow.Trigger.Webhook {
		triggers = append(triggers, "webhook")
	}
	if len(triggers) > 0 {
		fmt.Printf("Triggers: %s\n", joinStrings(triggers, ", "))
	}

	return 0
}

func runWorkflowList(args []string) int {
	fs := flag.NewFlagSet("workflow list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	showAll := fs.Bool("all", false, "show all workflows (including disabled)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	storage, err := scheduler.NewStorage("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	workflows, err := storage.ListWorkflows()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading workflows: %v\n", err)
		return 1
	}

	if len(workflows) == 0 {
		fmt.Println("No workflows found.")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tSTEPS\tTRIGGERS\tENABLED")
	fmt.Fprintln(w, "--\t----\t-----\t--------\t-------")

	for _, workflow := range workflows {
		if !*showAll && !workflow.Enabled {
			continue
		}

		// Build triggers string
		var triggers []string
		if workflow.Trigger.Manual {
			triggers = append(triggers, "manual")
		}
		if workflow.Trigger.Schedule != "" {
			triggers = append(triggers, "schedule")
		}
		if workflow.Trigger.Webhook {
			triggers = append(triggers, "webhook")
		}
		triggersStr := joinStrings(triggers, ",")

		enabledStr := "no"
		if workflow.Enabled {
			enabledStr = "yes"
		}

		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n",
			workflow.ID[:8],
			workflow.Name,
			len(workflow.Steps),
			triggersStr,
			enabledStr)
	}

	w.Flush()

	return 0
}

func runWorkflowShow(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: 0xgenctl workflow show <workflow-id-or-name>")
		return 2
	}

	workflowIDOrName := args[0]

	storage, err := scheduler.NewStorage("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Try to load by ID first
	workflow, err := storage.LoadWorkflow(workflowIDOrName)
	if err != nil {
		// Try by name
		workflow, err = storage.FindWorkflowByName(workflowIDOrName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Workflow not found: %s\n", workflowIDOrName)
			return 1
		}
	}

	fmt.Printf("ID:          %s\n", workflow.ID)
	fmt.Printf("Name:        %s\n", workflow.Name)
	if workflow.Description != "" {
		fmt.Printf("Description: %s\n", workflow.Description)
	}
	fmt.Printf("Enabled:     %t\n", workflow.Enabled)
	fmt.Printf("Created:     %s\n", workflow.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Updated:     %s\n", workflow.UpdatedAt.Format(time.RFC3339))

	fmt.Println("\nTriggers:")
	if workflow.Trigger.Manual {
		fmt.Println("  ✓ Manual")
	}
	if workflow.Trigger.Schedule != "" {
		fmt.Printf("  ✓ Schedule: %s\n", workflow.Trigger.Schedule)
	}
	if workflow.Trigger.Webhook {
		fmt.Println("  ✓ Webhook")
	}

	if len(workflow.Variables) > 0 {
		fmt.Println("\nVariables:")
		for k, v := range workflow.Variables {
			fmt.Printf("  %s = %s\n", k, v)
		}
	}

	fmt.Printf("\nSteps (%d):\n", len(workflow.Steps))
	for i, step := range workflow.Steps {
		fmt.Printf("  %d. %s\n", i+1, step.Name)
		fmt.Printf("     Action: %s\n", step.Action)
		if step.Condition != "" {
			fmt.Printf("     Condition: %s\n", step.Condition)
		}
		if len(step.Config) > 0 {
			fmt.Println("     Config:")
			for k, v := range step.Config {
				fmt.Printf("       %s: %s\n", k, v)
			}
		}
	}

	return 0
}

func runWorkflowRun(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: 0xgenctl workflow run <workflow-id-or-name>")
		return 2
	}

	workflowIDOrName := args[0]

	storage, err := scheduler.NewStorage("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Try to load by ID first
	workflow, err := storage.LoadWorkflow(workflowIDOrName)
	if err != nil {
		// Try by name
		workflow, err = storage.FindWorkflowByName(workflowIDOrName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Workflow not found: %s\n", workflowIDOrName)
			return 1
		}
	}

	fmt.Printf("Executing workflow: %s\n", workflow.Name)
	fmt.Printf("Steps: %d\n", len(workflow.Steps))
	fmt.Println()

	// Execute workflow
	engine := scheduler.NewWorkflowEngine(storage)
	ctx := context.Background()

	execution, err := engine.Execute(ctx, workflow)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Workflow execution error: %v\n", err)
		return 1
	}

	// Print execution results
	fmt.Println("Execution Summary:")
	fmt.Printf("  ID: %s\n", execution.ID)
	fmt.Printf("  Status: %s\n", execution.Status)
	fmt.Printf("  Started: %s\n", execution.StartedAt.Format(time.RFC3339))
	if execution.CompletedAt != nil {
		fmt.Printf("  Completed: %s\n", execution.CompletedAt.Format(time.RFC3339))
		duration := execution.CompletedAt.Sub(execution.StartedAt)
		fmt.Printf("  Duration: %s\n", duration.Round(time.Millisecond))
	}

	if execution.Error != "" {
		fmt.Printf("  Error: %s\n", execution.Error)
	}

	fmt.Println("\nStep Results:")
	for i, step := range execution.Steps {
		statusIcon := "✓"
		if step.Status == scheduler.StepStatusFailed {
			statusIcon = "✗"
		} else if step.Status == scheduler.StepStatusSkipped {
			statusIcon = "⊘"
		}

		fmt.Printf("  %s %d. %s - %s\n", statusIcon, i+1, step.StepName, step.Status)
		if step.Error != "" {
			fmt.Printf("     Error: %s\n", step.Error)
		}
	}

	if execution.Status == scheduler.ExecutionStatusFailed {
		return 1
	}

	return 0
}

func runWorkflowEnable(args []string) int {
	return setWorkflowEnabled(args, true)
}

func runWorkflowDisable(args []string) int {
	return setWorkflowEnabled(args, false)
}

func setWorkflowEnabled(args []string, enabled bool) int {
	if len(args) == 0 {
		action := "enable"
		if !enabled {
			action = "disable"
		}
		fmt.Fprintf(os.Stderr, "Usage: 0xgenctl workflow %s <workflow-id-or-name>\n", action)
		return 2
	}

	workflowIDOrName := args[0]

	storage, err := scheduler.NewStorage("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Try to load by ID first
	workflow, err := storage.LoadWorkflow(workflowIDOrName)
	if err != nil {
		// Try by name
		workflow, err = storage.FindWorkflowByName(workflowIDOrName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Workflow not found: %s\n", workflowIDOrName)
			return 1
		}
	}

	workflow.Enabled = enabled

	if err := storage.SaveWorkflow(workflow); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving workflow: %v\n", err)
		return 1
	}

	action := "enabled"
	if !enabled {
		action = "disabled"
	}
	fmt.Printf("Workflow %s: %s\n", action, workflow.Name)

	return 0
}

func runWorkflowDelete(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: 0xgenctl workflow delete <workflow-id-or-name>")
		return 2
	}

	workflowIDOrName := args[0]

	storage, err := scheduler.NewStorage("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Try to load by ID first to get the name
	workflow, err := storage.LoadWorkflow(workflowIDOrName)
	if err != nil {
		// Try by name
		workflow, err = storage.FindWorkflowByName(workflowIDOrName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Workflow not found: %s\n", workflowIDOrName)
			return 1
		}
	}

	if err := storage.DeleteWorkflow(workflow.ID); err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting workflow: %v\n", err)
		return 1
	}

	fmt.Printf("Workflow deleted: %s\n", workflow.Name)

	return 0
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
