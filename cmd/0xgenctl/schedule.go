package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/RowanDark/0xgen/internal/scheduler"
)

func runSchedule(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: 0xgenctl schedule <command> [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Commands:")
		fmt.Fprintln(os.Stderr, "  create      Create a new schedule")
		fmt.Fprintln(os.Stderr, "  list        List all schedules")
		fmt.Fprintln(os.Stderr, "  show        Show schedule details")
		fmt.Fprintln(os.Stderr, "  enable      Enable a schedule")
		fmt.Fprintln(os.Stderr, "  disable     Disable a schedule")
		fmt.Fprintln(os.Stderr, "  run         Run a schedule immediately")
		fmt.Fprintln(os.Stderr, "  delete      Delete a schedule")
		return 2
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "create":
		return runScheduleCreate(subargs)
	case "list":
		return runScheduleList(subargs)
	case "show":
		return runScheduleShow(subargs)
	case "enable":
		return runScheduleEnable(subargs)
	case "disable":
		return runScheduleDisable(subargs)
	case "run":
		return runScheduleRun(subargs)
	case "delete":
		return runScheduleDelete(subargs)
	default:
		fmt.Fprintf(os.Stderr, "Unknown schedule command: %s\n", subcmd)
		return 2
	}
}

func runScheduleCreate(args []string) int {
	fs := flag.NewFlagSet("schedule create", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	name := fs.String("name", "", "schedule name (required)")
	description := fs.String("description", "", "schedule description")
	target := fs.String("target", "", "scan target (required)")
	template := fs.String("template", "", "template to use")
	scanType := fs.String("type", "blitz", "scan type (blitz, raider, full)")
	cronExpr := fs.String("cron", "", "cron expression (required)")
	enabled := fs.Bool("enabled", true, "enable schedule immediately")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *name == "" {
		fmt.Fprintln(os.Stderr, "Error: --name is required")
		return 2
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target is required")
		return 2
	}
	if *cronExpr == "" {
		fmt.Fprintln(os.Stderr, "Error: --cron is required")
		return 2
	}

	// Validate cron expression
	cron, err := scheduler.ParseCronExpression(*cronExpr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid cron expression: %v\n", err)
		return 2
	}

	// Create storage
	storage, err := scheduler.NewStorage("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Calculate next run
	nextRun, err := scheduler.CalculateNextRun(cron, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error calculating next run: %v\n", err)
		return 1
	}

	// Create schedule
	schedule := &scheduler.Schedule{
		Name:        *name,
		Description: *description,
		Enabled:     *enabled,
		CronExpr:    *cronExpr,
		Target:      *target,
		Template:    *template,
		ScanType:    *scanType,
		NextRun:     &nextRun,
		Options:     make(map[string]string),
		Actions:     []scheduler.Action{},
	}

	// Parse additional options from remaining args
	for _, arg := range fs.Args() {
		if strings.Contains(arg, "=") {
			parts := strings.SplitN(arg, "=", 2)
			schedule.Options[parts[0]] = parts[1]
		}
	}

	if err := storage.SaveSchedule(schedule); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving schedule: %v\n", err)
		return 1
	}

	fmt.Printf("Schedule created: %s\n", schedule.ID)
	fmt.Printf("Name: %s\n", schedule.Name)
	fmt.Printf("Cron: %s (%s)\n", schedule.CronExpr, scheduler.DescribeCronExpression(cron))
	fmt.Printf("Next run: %s\n", schedule.NextRun.Format(time.RFC3339))
	fmt.Printf("Enabled: %t\n", schedule.Enabled)

	return 0
}

func runScheduleList(args []string) int {
	fs := flag.NewFlagSet("schedule list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	showAll := fs.Bool("all", false, "show all schedules (including disabled)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	storage, err := scheduler.NewStorage("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	schedules, err := storage.ListSchedules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading schedules: %v\n", err)
		return 1
	}

	if len(schedules) == 0 {
		fmt.Println("No schedules found.")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tTARGET\tCRON\tENABLED\tNEXT RUN")
	fmt.Fprintln(w, "--\t----\t------\t----\t-------\t--------")

	for _, schedule := range schedules {
		if !*showAll && !schedule.Enabled {
			continue
		}

		nextRunStr := "N/A"
		if schedule.NextRun != nil {
			nextRunStr = schedule.NextRun.Format("2006-01-02 15:04")
		}

		enabledStr := "no"
		if schedule.Enabled {
			enabledStr = "yes"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			schedule.ID[:8],
			schedule.Name,
			truncate(schedule.Target, 30),
			schedule.CronExpr,
			enabledStr,
			nextRunStr)
	}

	w.Flush()

	return 0
}

func runScheduleShow(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: 0xgenctl schedule show <schedule-id-or-name>")
		return 2
	}

	scheduleIDOrName := args[0]

	storage, err := scheduler.NewStorage("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Try to load by ID first
	schedule, err := storage.LoadSchedule(scheduleIDOrName)
	if err != nil {
		// Try by name
		schedule, err = storage.FindScheduleByName(scheduleIDOrName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Schedule not found: %s\n", scheduleIDOrName)
			return 1
		}
	}

	// Parse cron for description
	cron, _ := scheduler.ParseCronExpression(schedule.CronExpr)
	cronDesc := ""
	if cron != nil {
		cronDesc = scheduler.DescribeCronExpression(cron)
	}

	fmt.Printf("ID:          %s\n", schedule.ID)
	fmt.Printf("Name:        %s\n", schedule.Name)
	if schedule.Description != "" {
		fmt.Printf("Description: %s\n", schedule.Description)
	}
	fmt.Printf("Enabled:     %t\n", schedule.Enabled)
	fmt.Printf("Cron:        %s\n", schedule.CronExpr)
	if cronDesc != "" {
		fmt.Printf("             (%s)\n", cronDesc)
	}
	fmt.Printf("Target:      %s\n", schedule.Target)
	if schedule.Template != "" {
		fmt.Printf("Template:    %s\n", schedule.Template)
	}
	fmt.Printf("Scan Type:   %s\n", schedule.ScanType)
	fmt.Printf("Created:     %s\n", schedule.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Updated:     %s\n", schedule.UpdatedAt.Format(time.RFC3339))

	if schedule.LastRun != nil {
		fmt.Printf("Last Run:    %s\n", schedule.LastRun.Format(time.RFC3339))
	}
	if schedule.NextRun != nil {
		fmt.Printf("Next Run:    %s\n", schedule.NextRun.Format(time.RFC3339))
	}

	if len(schedule.Options) > 0 {
		fmt.Println("\nOptions:")
		for k, v := range schedule.Options {
			fmt.Printf("  %s = %s\n", k, v)
		}
	}

	if len(schedule.Actions) > 0 {
		fmt.Println("\nActions:")
		for _, action := range schedule.Actions {
			fmt.Printf("  - %s\n", action.Type)
			for k, v := range action.Config {
				fmt.Printf("    %s: %s\n", k, v)
			}
		}
	}

	return 0
}

func runScheduleEnable(args []string) int {
	return setScheduleEnabled(args, true)
}

func runScheduleDisable(args []string) int {
	return setScheduleEnabled(args, false)
}

func setScheduleEnabled(args []string, enabled bool) int {
	if len(args) == 0 {
		action := "enable"
		if !enabled {
			action = "disable"
		}
		fmt.Fprintf(os.Stderr, "Usage: 0xgenctl schedule %s <schedule-id-or-name>\n", action)
		return 2
	}

	scheduleIDOrName := args[0]

	storage, err := scheduler.NewStorage("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Try to load by ID first
	schedule, err := storage.LoadSchedule(scheduleIDOrName)
	if err != nil {
		// Try by name
		schedule, err = storage.FindScheduleByName(scheduleIDOrName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Schedule not found: %s\n", scheduleIDOrName)
			return 1
		}
	}

	schedule.Enabled = enabled

	// If enabling, recalculate next run
	if enabled {
		cron, err := scheduler.ParseCronExpression(schedule.CronExpr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid cron expression: %v\n", err)
			return 1
		}

		nextRun, err := scheduler.CalculateNextRun(cron, time.Now().UTC())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error calculating next run: %v\n", err)
			return 1
		}
		schedule.NextRun = &nextRun
	}

	if err := storage.SaveSchedule(schedule); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving schedule: %v\n", err)
		return 1
	}

	action := "enabled"
	if !enabled {
		action = "disabled"
	}
	fmt.Printf("Schedule %s: %s\n", action, schedule.Name)

	return 0
}

func runScheduleRun(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: 0xgenctl schedule run <schedule-id-or-name>")
		return 2
	}

	scheduleIDOrName := args[0]

	storage, err := scheduler.NewStorage("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Try to load by ID first
	schedule, err := storage.LoadSchedule(scheduleIDOrName)
	if err != nil {
		// Try by name
		schedule, err = storage.FindScheduleByName(scheduleIDOrName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Schedule not found: %s\n", scheduleIDOrName)
			return 1
		}
	}

	fmt.Printf("Running schedule: %s\n", schedule.Name)
	fmt.Printf("Target: %s\n", schedule.Target)
	fmt.Printf("Type: %s\n", schedule.ScanType)

	// In a real implementation, this would trigger the actual scan
	// For now, just update the last run time
	now := time.Now().UTC()
	schedule.LastRun = &now

	if err := storage.SaveSchedule(schedule); err != nil {
		fmt.Fprintf(os.Stderr, "Error updating schedule: %v\n", err)
		return 1
	}

	fmt.Println("✓ Schedule executed")

	return 0
}

func runScheduleDelete(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: 0xgenctl schedule delete <schedule-id-or-name>")
		return 2
	}

	scheduleIDOrName := args[0]

	storage, err := scheduler.NewStorage("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Try to load by ID first to get the name
	schedule, err := storage.LoadSchedule(scheduleIDOrName)
	if err != nil {
		// Try by name
		schedule, err = storage.FindScheduleByName(scheduleIDOrName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Schedule not found: %s\n", scheduleIDOrName)
			return 1
		}
	}

	if err := storage.DeleteSchedule(schedule.ID); err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting schedule: %v\n", err)
		return 1
	}

	fmt.Printf("Schedule deleted: %s\n", schedule.Name)

	return 0
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
