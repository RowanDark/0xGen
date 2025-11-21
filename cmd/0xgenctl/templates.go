package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/RowanDark/0xgen/internal/templates"
	"gopkg.in/yaml.v3"
)

func runTemplates(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "templates subcommand required (list, show, save, export, import, edit, delete)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  0xgenctl templates list              - List all available templates")
		fmt.Fprintln(os.Stderr, "  0xgenctl templates show <name>       - Show template details")
		fmt.Fprintln(os.Stderr, "  0xgenctl templates save <name>       - Save current configuration as template")
		fmt.Fprintln(os.Stderr, "  0xgenctl templates export <name>     - Export template to file")
		fmt.Fprintln(os.Stderr, "  0xgenctl templates import <file>     - Import template from file")
		fmt.Fprintln(os.Stderr, "  0xgenctl templates edit <name>       - Edit custom template")
		fmt.Fprintln(os.Stderr, "  0xgenctl templates delete <name>     - Delete custom template")
		return 2
	}

	switch args[0] {
	case "list":
		return runTemplatesList(args[1:])
	case "show":
		return runTemplatesShow(args[1:])
	case "save":
		return runTemplatesSave(args[1:])
	case "export":
		return runTemplatesExport(args[1:])
	case "import":
		return runTemplatesImport(args[1:])
	case "edit":
		return runTemplatesEdit(args[1:])
	case "delete":
		return runTemplatesDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown templates subcommand: %s\n", args[0])
		return 2
	}
}

func runTemplatesList(args []string) int {
	mgr, err := templates.NewManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing template manager: %v\n", err)
		return 1
	}

	tmpls, err := mgr.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing templates: %v\n", err)
		return 1
	}

	if len(tmpls) == 0 {
		fmt.Println("No templates available")
		return 0
	}

	// Print built-in templates
	fmt.Println("Available Templates:")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	hasBuiltin := false
	for _, tmpl := range tmpls {
		if tmpl.IsBuiltin {
			if !hasBuiltin {
				hasBuiltin = true
			}
			fmt.Fprintf(w, "  %-20s\t- %s\n", tmpl.Name, tmpl.Description)
		}
	}

	// Print custom templates
	hasCustom := false
	for _, tmpl := range tmpls {
		if tmpl.IsCustom {
			if !hasCustom {
				fmt.Fprintln(w)
				fmt.Fprintln(w, "Custom Templates:")
				fmt.Fprintln(w)
				hasCustom = true
			}
			fmt.Fprintf(w, "  %-20s\t- %s\n", tmpl.Name, tmpl.Description)
		}
	}

	if hasCustom {
		fmt.Fprintf(w, "\n  Total: %d built-in, %d custom\n", countBuiltin(tmpls), countCustom(tmpls))
	}

	return 0
}

func runTemplatesShow(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: template name required")
		fmt.Fprintln(os.Stderr, "Usage: 0xgenctl templates show <name>")
		return 2
	}

	name := args[0]

	mgr, err := templates.NewManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing template manager: %v\n", err)
		return 1
	}

	tmpl, err := mgr.Get(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Print template details
	fmt.Printf("Template: %s\n", tmpl.Name)
	fmt.Printf("Description: %s\n", tmpl.Description)
	if tmpl.IsBuiltin {
		fmt.Println("Type: Built-in")
	} else {
		fmt.Println("Type: Custom")
		fmt.Printf("Path: %s\n", tmpl.Path)
	}
	fmt.Println()

	// Print configuration as YAML
	fmt.Println("Configuration:")
	data, err := yaml.Marshal(tmpl.Config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting configuration: %v\n", err)
		return 1
	}

	// Indent the YAML output
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line != "" {
			fmt.Printf("  %s\n", line)
		}
	}

	return 0
}

func runTemplatesSave(args []string) int {
	fs := flag.NewFlagSet("templates save", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	name := fs.String("name", "", "template name (required)")
	description := fs.String("description", "", "template description")

	// Scan configuration flags
	concurrency := fs.Int("concurrency", 0, "concurrent workers")
	rateLimit := fs.Float64("rate", 0, "requests per second")
	attackType := fs.String("attack", "", "attack type")
	markers := fs.String("markers", "", "marker delimiters")
	enableAnomaly := fs.Bool("anomaly", true, "enable anomaly detection")
	enableAI := fs.Bool("ai", false, "enable AI features")
	aiPayloads := fs.Bool("ai-payloads", false, "enable AI payloads")
	aiClassify := fs.Bool("ai-classify", false, "enable AI classification")
	aiFindings := fs.Bool("ai-findings", false, "enable AI findings")
	maxRetries := fs.Int("retries", 2, "maximum retries")
	patterns := fs.String("patterns", "", "comma-separated regex patterns")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *name == "" {
		fmt.Fprintln(os.Stderr, "Error: --name is required")
		return 2
	}

	// Build flags map
	flagsMap := make(map[string]interface{})
	if *concurrency > 0 {
		flagsMap["concurrency"] = *concurrency
	}
	if *rateLimit > 0 {
		flagsMap["rate"] = *rateLimit
	}
	if *attackType != "" {
		flagsMap["attack"] = *attackType
	}
	if *markers != "" {
		flagsMap["markers"] = *markers
	}
	flagsMap["anomaly"] = *enableAnomaly
	flagsMap["ai"] = *enableAI
	flagsMap["ai-payloads"] = *aiPayloads
	flagsMap["ai-classify"] = *aiClassify
	flagsMap["ai-findings"] = *aiFindings
	if *maxRetries > 0 {
		flagsMap["retries"] = *maxRetries
	}
	if *patterns != "" {
		flagsMap["patterns"] = *patterns
	}

	desc := *description
	if desc == "" {
		desc = "Custom scan template"
	}

	tmpl := templates.CreateFromFlags(*name, desc, flagsMap)

	mgr, err := templates.NewManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing template manager: %v\n", err)
		return 1
	}

	if err := mgr.Save(tmpl); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving template: %v\n", err)
		return 1
	}

	fmt.Printf("Template '%s' saved successfully\n", *name)
	return 0
}

func runTemplatesExport(args []string) int {
	fs := flag.NewFlagSet("templates export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	output := fs.String("output", "", "output file path (default: stdout)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "Error: template name required")
		fmt.Fprintln(os.Stderr, "Usage: 0xgenctl templates export <name> [--output file.yaml]")
		return 2
	}

	name := fs.Arg(0)

	mgr, err := templates.NewManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing template manager: %v\n", err)
		return 1
	}

	tmpl, err := mgr.Get(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	data, err := yaml.Marshal(tmpl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling template: %v\n", err)
		return 1
	}

	if *output == "" {
		// Write to stdout
		fmt.Print(string(data))
	} else {
		// Write to file
		if err := os.WriteFile(*output, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
			return 1
		}
		fmt.Printf("Template exported to: %s\n", *output)
	}

	return 0
}

func runTemplatesImport(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: template file required")
		fmt.Fprintln(os.Stderr, "Usage: 0xgenctl templates import <file.yaml>")
		return 2
	}

	path := args[0]

	mgr, err := templates.NewManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing template manager: %v\n", err)
		return 1
	}

	if err := mgr.Import(path); err != nil {
		fmt.Fprintf(os.Stderr, "Error importing template: %v\n", err)
		return 1
	}

	fmt.Printf("Template imported successfully from: %s\n", path)
	return 0
}

func runTemplatesEdit(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: template name required")
		fmt.Fprintln(os.Stderr, "Usage: 0xgenctl templates edit <name>")
		return 2
	}

	name := args[0]

	mgr, err := templates.NewManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing template manager: %v\n", err)
		return 1
	}

	tmpl, err := mgr.Get(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if tmpl.IsBuiltin {
		fmt.Fprintln(os.Stderr, "Error: cannot edit built-in templates")
		fmt.Fprintf(os.Stderr, "Tip: Export the template first, then import it as a custom template:\n")
		fmt.Fprintf(os.Stderr, "  0xgenctl templates export %s > my-template.yaml\n", name)
		fmt.Fprintf(os.Stderr, "  # Edit my-template.yaml\n")
		fmt.Fprintf(os.Stderr, "  0xgenctl templates import my-template.yaml\n")
		return 2
	}

	// Determine editor
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi" // Default to vi
	}

	// Open editor
	cmd := exec.Command(editor, tmpl.Path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error opening editor: %v\n", err)
		return 1
	}

	fmt.Printf("Template '%s' edited\n", name)
	return 0
}

func runTemplatesDelete(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: template name required")
		fmt.Fprintln(os.Stderr, "Usage: 0xgenctl templates delete <name>")
		return 2
	}

	name := args[0]

	mgr, err := templates.NewManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing template manager: %v\n", err)
		return 1
	}

	if err := mgr.Delete(name); err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting template: %v\n", err)
		return 1
	}

	fmt.Printf("Template '%s' deleted successfully\n", name)
	return 0
}

// Helper functions

func countBuiltin(tmpls []*templates.Template) int {
	count := 0
	for _, t := range tmpls {
		if t.IsBuiltin {
			count++
		}
	}
	return count
}

func countCustom(tmpls []*templates.Template) int {
	count := 0
	for _, t := range tmpls {
		if t.IsCustom {
			count++
		}
	}
	return count
}
