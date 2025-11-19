package local

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"sync"
	"time"
)

// IDGenerator generates unique, collision-resistant IDs for OAST callbacks.
type IDGenerator struct {
	prefix  string
	counter uint64
	mu      sync.Mutex
}

// NewIDGenerator creates a new ID generator with the specified prefix.
func NewIDGenerator(prefix string) *IDGenerator {
	return &IDGenerator{
		prefix: prefix,
	}
}

// Generate creates a unique, collision-resistant ID.
// Format: {prefix}-{timestamp}-{random}-{counter}
// Example: oast-1705420800-k7m3np2q-0001
func (g *IDGenerator) Generate() string {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Timestamp component (Unix timestamp)
	timestamp := time.Now().Unix()

	// Random component (8 chars, base32)
	randomBytes := make([]byte, 5) // 5 bytes = 8 base32 chars
	rand.Read(randomBytes)
	randomStr := strings.ToLower(base32.StdEncoding.EncodeToString(randomBytes))
	randomStr = randomStr[:8]

	// Counter component (4 digits)
	g.counter++
	counter := g.counter % 10000

	// Combine
	if g.prefix != "" {
		return fmt.Sprintf("%s-%d-%s-%04d", g.prefix, timestamp, randomStr, counter)
	}
	return fmt.Sprintf("%d-%s-%04d", timestamp, randomStr, counter)
}

// GenerateShort creates a shorter ID (for URL readability).
// Format: {random8}
// Example: k7m3np2q
func (g *IDGenerator) GenerateShort() string {
	randomBytes := make([]byte, 5)
	rand.Read(randomBytes)
	randomStr := strings.ToLower(base32.StdEncoding.EncodeToString(randomBytes))
	return randomStr[:8]
}

// IDMetadata contains parsed metadata from a generated ID.
type IDMetadata struct {
	Prefix    string
	Timestamp time.Time
	Random    string
	Counter   uint64
}

// ParseID extracts metadata from a generated ID.
func ParseID(id string) (*IDMetadata, error) {
	parts := strings.Split(id, "-")

	// Format: prefix-timestamp-random-counter or timestamp-random-counter
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid ID format: expected at least 3 parts, got %d", len(parts))
	}

	var metadata IDMetadata
	offset := 0

	// Check for prefix (4 parts = with prefix, 3 parts = without)
	if len(parts) == 4 {
		metadata.Prefix = parts[0]
		offset = 1
	} else if len(parts) != 3 {
		return nil, fmt.Errorf("invalid ID format: expected 3 or 4 parts, got %d", len(parts))
	}

	// Parse timestamp
	var timestamp int64
	_, err := fmt.Sscanf(parts[offset], "%d", &timestamp)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %w", err)
	}
	metadata.Timestamp = time.Unix(timestamp, 0)

	// Extract random
	metadata.Random = parts[offset+1]

	// Parse counter
	_, err = fmt.Sscanf(parts[offset+2], "%d", &metadata.Counter)
	if err != nil {
		return nil, fmt.Errorf("invalid counter: %w", err)
	}

	return &metadata, nil
}

// IsValidID checks if a string is a valid OAST ID format.
func IsValidID(id string) bool {
	_, err := ParseID(id)
	return err == nil
}
