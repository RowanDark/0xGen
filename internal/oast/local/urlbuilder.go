package local

import (
	"fmt"
	"net/url"
	"strings"
)

// URLBuilder generates callback URLs with unique IDs.
type URLBuilder struct {
	baseURL   string // e.g., http://localhost:8443/callback
	generator *IDGenerator
}

// NewURLBuilder creates a new URL builder with the specified base URL.
func NewURLBuilder(baseURL string) *URLBuilder {
	return &URLBuilder{
		baseURL:   strings.TrimSuffix(baseURL, "/"),
		generator: NewIDGenerator("oast"),
	}
}

// NewURLBuilderWithPrefix creates a URL builder with a custom ID prefix.
func NewURLBuilderWithPrefix(baseURL, prefix string) *URLBuilder {
	return &URLBuilder{
		baseURL:   strings.TrimSuffix(baseURL, "/"),
		generator: NewIDGenerator(prefix),
	}
}

// CallbackURL represents a generated callback URL with its components.
type CallbackURL struct {
	ID       string // The unique callback ID
	URL      string // Full callback URL
	ShortURL string // Shortened URL for display
}

// Generate creates a new callback URL with a unique ID.
func (b *URLBuilder) Generate() *CallbackURL {
	id := b.generator.Generate()

	fullURL := fmt.Sprintf("%s/%s", b.baseURL, id)

	return &CallbackURL{
		ID:       id,
		URL:      fullURL,
		ShortURL: b.shortenForDisplay(fullURL),
	}
}

// GenerateWithPath creates a callback URL with an additional path suffix.
func (b *URLBuilder) GenerateWithPath(path string) *CallbackURL {
	id := b.generator.Generate()

	// Ensure path starts with /
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	fullURL := fmt.Sprintf("%s/%s%s", b.baseURL, id, path)

	return &CallbackURL{
		ID:       id,
		URL:      fullURL,
		ShortURL: b.shortenForDisplay(fullURL),
	}
}

// GenerateShort creates a callback URL with a short ID.
func (b *URLBuilder) GenerateShort() *CallbackURL {
	id := b.generator.GenerateShort()

	fullURL := fmt.Sprintf("%s/%s", b.baseURL, id)

	return &CallbackURL{
		ID:       id,
		URL:      fullURL,
		ShortURL: fullURL, // Short IDs don't need shortening
	}
}

// BuildURL constructs a callback URL for a given ID.
func (b *URLBuilder) BuildURL(id string) string {
	return fmt.Sprintf("%s/%s", b.baseURL, id)
}

// BuildURLWithPath constructs a callback URL with an additional path.
func (b *URLBuilder) BuildURLWithPath(id, path string) string {
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("%s/%s%s", b.baseURL, id, path)
}

// BuildURLWithQuery constructs a callback URL with query parameters.
func (b *URLBuilder) BuildURLWithQuery(id string, params map[string]string) string {
	baseURL := b.BuildURL(id)

	if len(params) == 0 {
		return baseURL
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}

	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	return u.String()
}

// GetBaseURL returns the base URL used by this builder.
func (b *URLBuilder) GetBaseURL() string {
	return b.baseURL
}

// shortenForDisplay truncates middle of URL for display.
// Example: http://localhost:8443/callback/oast-...2q-0001
func (b *URLBuilder) shortenForDisplay(fullURL string) string {
	if len(fullURL) <= 60 {
		return fullURL
	}

	// Keep protocol + host and last part of path
	u, err := url.Parse(fullURL)
	if err != nil {
		return fullURL
	}

	pathParts := strings.Split(u.Path, "/")
	if len(pathParts) > 0 {
		lastPart := pathParts[len(pathParts)-1]
		if len(lastPart) > 20 {
			// Shorten the ID itself
			lastPart = lastPart[:8] + "..." + lastPart[len(lastPart)-8:]
		}
		return fmt.Sprintf("%s://%s/.../%s", u.Scheme, u.Host, lastPart)
	}

	return fullURL
}

// ExtractIDFromURL extracts the callback ID from a full callback URL.
func (b *URLBuilder) ExtractIDFromURL(callbackURL string) (string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Remove base path
	baseU, err := url.Parse(b.baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	path := strings.TrimPrefix(u.Path, baseU.Path)
	path = strings.TrimPrefix(path, "/")

	// Get first path segment (the ID)
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", fmt.Errorf("no ID found in URL")
	}

	return parts[0], nil
}
