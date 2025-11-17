package delta

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// Engine is the main diffing engine
type Engine struct {
	// Future: Add configuration options here
}

// NewEngine creates a new diff engine
func NewEngine() *Engine {
	return &Engine{}
}

// Diff performs a diff based on the request type
func (e *Engine) Diff(req DiffRequest) (*DiffResult, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	startTime := time.Now()

	var result *DiffResult
	var err error

	switch req.Type {
	case DiffTypeText:
		granularity := req.Granularity
		if granularity == "" {
			granularity = GranularityLine
		}
		result, err = e.diffText(req.Left, req.Right, granularity)
	case DiffTypeJSON:
		result, err = e.diffJSON(req.Left, req.Right)
	case DiffTypeXML:
		result, err = e.diffXML(req.Left, req.Right)
	default:
		return nil, fmt.Errorf("unsupported diff type: %s", req.Type)
	}

	if err != nil {
		return nil, err
	}

	result.ComputeTime = time.Since(startTime)
	return result, nil
}

// diffText performs text-based diffing
func (e *Engine) diffText(left, right []byte, granularity DiffGranularity) (*DiffResult, error) {
	switch granularity {
	case GranularityLine:
		return e.diffLines(left, right)
	case GranularityWord:
		return e.diffWords(left, right)
	case GranularityCharacter:
		return e.diffCharacters(left, right)
	default:
		return nil, fmt.Errorf("unsupported granularity: %s", granularity)
	}
}

// diffLines performs line-level diffing using Myers algorithm
func (e *Engine) diffLines(left, right []byte) (*DiffResult, error) {
	leftLines := splitLines(string(left))
	rightLines := splitLines(string(right))

	changes := myersDiff(leftLines, rightLines)

	// Convert to our Change format with line numbers
	// Track positions in both input sequences to handle unchanged lines
	var diffChanges []Change
	leftIdx := 0
	rightIdx := 0

	for _, change := range changes {
		switch change.Type {
		case ChangeTypeAdded:
			// Find where this addition occurs in the right sequence
			// Skip unchanged lines that appear in both sequences
			for rightIdx < len(rightLines) && rightLines[rightIdx] != change.NewValue {
				// This line is unchanged (appears in both left and right)
				leftIdx++
				rightIdx++
			}
			// Now rightLines[rightIdx] == change.NewValue
			diffChanges = append(diffChanges, Change{
				Type:       ChangeTypeAdded,
				NewValue:   change.NewValue,
				LineNumber: rightIdx + 1, // +1 for 1-based line numbers
			})
			rightIdx++ // Move past the added line

		case ChangeTypeRemoved:
			// Find where this removal occurs in the left sequence
			// Skip unchanged lines that appear in both sequences
			for leftIdx < len(leftLines) && leftLines[leftIdx] != change.OldValue {
				// This line is unchanged (appears in both left and right)
				leftIdx++
				rightIdx++
			}
			// Now leftLines[leftIdx] == change.OldValue
			diffChanges = append(diffChanges, Change{
				Type:       ChangeTypeRemoved,
				OldValue:   change.OldValue,
				LineNumber: leftIdx + 1, // +1 for 1-based line numbers
			})
			leftIdx++ // Move past the removed line

		case ChangeTypeModified:
			// Find where this modification occurs
			// Skip unchanged lines that appear in both sequences
			for leftIdx < len(leftLines) && leftLines[leftIdx] != change.OldValue {
				leftIdx++
				rightIdx++
			}
			diffChanges = append(diffChanges, Change{
				Type:       ChangeTypeModified,
				OldValue:   change.OldValue,
				NewValue:   change.NewValue,
				LineNumber: leftIdx + 1, // +1 for 1-based line numbers
			})
			leftIdx++
			rightIdx++
		}
	}

	similarity := calculateSimilarity(len(leftLines), len(rightLines), len(diffChanges))

	return &DiffResult{
		Type:            DiffTypeText,
		Changes:         diffChanges,
		SimilarityScore: similarity,
		LeftSize:        len(left),
		RightSize:       len(right),
		Granularity:     string(GranularityLine),
	}, nil
}

// diffWords performs word-level diffing
func (e *Engine) diffWords(left, right []byte) (*DiffResult, error) {
	leftWords := splitWords(string(left))
	rightWords := splitWords(string(right))

	changes := myersDiff(leftWords, rightWords)

	// Convert to our Change format
	var diffChanges []Change
	for _, change := range changes {
		diffChanges = append(diffChanges, Change{
			Type:     change.Type,
			OldValue: change.OldValue,
			NewValue: change.NewValue,
			Context:  change.Context,
		})
	}

	similarity := calculateSimilarity(len(leftWords), len(rightWords), len(diffChanges))

	return &DiffResult{
		Type:            DiffTypeText,
		Changes:         diffChanges,
		SimilarityScore: similarity,
		LeftSize:        len(left),
		RightSize:       len(right),
		Granularity:     string(GranularityWord),
	}, nil
}

// diffCharacters performs character-level diffing
func (e *Engine) diffCharacters(left, right []byte) (*DiffResult, error) {
	leftStr := string(left)
	rightStr := string(right)

	leftRunes := []rune(leftStr)
	rightRunes := []rune(rightStr)

	// Convert runes to strings for diff algorithm
	leftStrs := make([]string, len(leftRunes))
	rightStrs := make([]string, len(rightRunes))
	for i, r := range leftRunes {
		leftStrs[i] = string(r)
	}
	for i, r := range rightRunes {
		rightStrs[i] = string(r)
	}

	changes := myersDiff(leftStrs, rightStrs)

	// Convert to our Change format
	var diffChanges []Change
	for _, change := range changes {
		diffChanges = append(diffChanges, Change{
			Type:     change.Type,
			OldValue: change.OldValue,
			NewValue: change.NewValue,
		})
	}

	similarity := calculateSimilarity(len(leftRunes), len(rightRunes), len(diffChanges))

	return &DiffResult{
		Type:            DiffTypeText,
		Changes:         diffChanges,
		SimilarityScore: similarity,
		LeftSize:        len(left),
		RightSize:       len(right),
		Granularity:     string(GranularityCharacter),
	}, nil
}

// diffJSON performs semantic JSON diffing
func (e *Engine) diffJSON(left, right []byte) (*DiffResult, error) {
	// Try to parse as JSON
	var leftObj, rightObj interface{}

	if err := json.Unmarshal(left, &leftObj); err != nil {
		// Fall back to text diff
		return e.diffText(left, right, GranularityLine)
	}

	if err := json.Unmarshal(right, &rightObj); err != nil {
		// Fall back to text diff
		return e.diffText(left, right, GranularityLine)
	}

	// Perform structural diff
	changes := e.diffJSONValues("$", leftObj, rightObj)

	similarity := calculateJSONSimilarity(leftObj, rightObj, len(changes))

	return &DiffResult{
		Type:            DiffTypeJSON,
		Changes:         changes,
		SimilarityScore: similarity,
		LeftSize:        len(left),
		RightSize:       len(right),
	}, nil
}

// diffJSONValues recursively compares JSON values
func (e *Engine) diffJSONValues(path string, left, right interface{}) []Change {
	var changes []Change

	// Handle nil cases
	if left == nil && right == nil {
		return changes
	}
	if left == nil {
		changes = append(changes, Change{
			Type:     ChangeTypeAdded,
			Path:     path,
			NewValue: formatValue(right),
		})
		return changes
	}
	if right == nil {
		changes = append(changes, Change{
			Type:     ChangeTypeRemoved,
			Path:     path,
			OldValue: formatValue(left),
		})
		return changes
	}

	// Compare by type
	leftMap, leftIsMap := left.(map[string]interface{})
	rightMap, rightIsMap := right.(map[string]interface{})

	if leftIsMap && rightIsMap {
		return e.diffJSONObjects(path, leftMap, rightMap)
	}

	leftArray, leftIsArray := left.([]interface{})
	rightArray, rightIsArray := right.([]interface{})

	if leftIsArray && rightIsArray {
		return e.diffJSONArrays(path, leftArray, rightArray)
	}

	// Compare primitive values
	leftStr := formatValue(left)
	rightStr := formatValue(right)

	if leftStr != rightStr {
		changes = append(changes, Change{
			Type:     ChangeTypeModified,
			Path:     path,
			OldValue: leftStr,
			NewValue: rightStr,
		})
	}

	return changes
}

// diffJSONObjects compares two JSON objects
func (e *Engine) diffJSONObjects(path string, left, right map[string]interface{}) []Change {
	var changes []Change

	// Check for removed keys
	for key, leftVal := range left {
		if rightVal, exists := right[key]; exists {
			// Key exists in both, recurse
			keyPath := fmt.Sprintf("%s.%s", path, key)
			changes = append(changes, e.diffJSONValues(keyPath, leftVal, rightVal)...)
		} else {
			// Key removed
			changes = append(changes, Change{
				Type:     ChangeTypeRemoved,
				Path:     fmt.Sprintf("%s.%s", path, key),
				OldValue: formatValue(leftVal),
			})
		}
	}

	// Check for added keys
	for key, rightVal := range right {
		if _, exists := left[key]; !exists {
			changes = append(changes, Change{
				Type:     ChangeTypeAdded,
				Path:     fmt.Sprintf("%s.%s", path, key),
				NewValue: formatValue(rightVal),
			})
		}
	}

	return changes
}

// diffJSONArrays compares two JSON arrays
func (e *Engine) diffJSONArrays(path string, left, right []interface{}) []Change {
	var changes []Change

	maxLen := len(left)
	if len(right) > maxLen {
		maxLen = len(right)
	}

	for i := 0; i < maxLen; i++ {
		indexPath := fmt.Sprintf("%s[%d]", path, i)

		if i >= len(left) {
			// Element added
			changes = append(changes, Change{
				Type:     ChangeTypeAdded,
				Path:     indexPath,
				NewValue: formatValue(right[i]),
			})
		} else if i >= len(right) {
			// Element removed
			changes = append(changes, Change{
				Type:     ChangeTypeRemoved,
				Path:     indexPath,
				OldValue: formatValue(left[i]),
			})
		} else {
			// Compare elements
			changes = append(changes, e.diffJSONValues(indexPath, left[i], right[i])...)
		}
	}

	return changes
}

// diffXML performs semantic XML diffing
func (e *Engine) diffXML(left, right []byte) (*DiffResult, error) {
	// Try to parse as XML
	var leftNode, rightNode xmlNode

	if err := xml.Unmarshal(left, &leftNode); err != nil {
		// Fall back to text diff
		return e.diffText(left, right, GranularityLine)
	}

	if err := xml.Unmarshal(right, &rightNode); err != nil {
		// Fall back to text diff
		return e.diffText(left, right, GranularityLine)
	}

	// Perform structural diff
	changes := e.diffXMLNodes("/"+leftNode.XMLName.Local, &leftNode, &rightNode)

	similarity := calculateXMLSimilarity(&leftNode, &rightNode, len(changes))

	return &DiffResult{
		Type:            DiffTypeXML,
		Changes:         changes,
		SimilarityScore: similarity,
		LeftSize:        len(left),
		RightSize:       len(right),
	}, nil
}

// xmlNode represents a simplified XML node
type xmlNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr `xml:",any,attr"`
	Content  string     `xml:",chardata"`
	Children []xmlNode  `xml:",any"`
}

// diffXMLNodes recursively compares XML nodes
func (e *Engine) diffXMLNodes(path string, left, right *xmlNode) []Change {
	var changes []Change

	if left == nil && right == nil {
		return changes
	}

	if left == nil {
		changes = append(changes, Change{
			Type:     ChangeTypeAdded,
			Path:     path,
			NewValue: fmt.Sprintf("<%s>", right.XMLName.Local),
		})
		return changes
	}

	if right == nil {
		changes = append(changes, Change{
			Type:     ChangeTypeRemoved,
			Path:     path,
			OldValue: fmt.Sprintf("<%s>", left.XMLName.Local),
		})
		return changes
	}

	// Compare element names
	if left.XMLName.Local != right.XMLName.Local {
		changes = append(changes, Change{
			Type:     ChangeTypeModified,
			Path:     path,
			OldValue: left.XMLName.Local,
			NewValue: right.XMLName.Local,
		})
	}

	// Compare attributes
	leftAttrs := make(map[string]string)
	for _, attr := range left.Attrs {
		leftAttrs[attr.Name.Local] = attr.Value
	}

	rightAttrs := make(map[string]string)
	for _, attr := range right.Attrs {
		rightAttrs[attr.Name.Local] = attr.Value
	}

	// Check for changed/removed attributes
	for name, leftVal := range leftAttrs {
		attrPath := fmt.Sprintf("%s/@%s", path, name)
		if rightVal, exists := rightAttrs[name]; exists {
			if leftVal != rightVal {
				changes = append(changes, Change{
					Type:     ChangeTypeModified,
					Path:     attrPath,
					OldValue: leftVal,
					NewValue: rightVal,
				})
			}
		} else {
			changes = append(changes, Change{
				Type:     ChangeTypeRemoved,
				Path:     attrPath,
				OldValue: leftVal,
			})
		}
	}

	// Check for added attributes
	for name, rightVal := range rightAttrs {
		if _, exists := leftAttrs[name]; !exists {
			changes = append(changes, Change{
				Type:     ChangeTypeAdded,
				Path:     fmt.Sprintf("%s/@%s", path, name),
				NewValue: rightVal,
			})
		}
	}

	// Compare text content (trim whitespace)
	leftContent := strings.TrimSpace(left.Content)
	rightContent := strings.TrimSpace(right.Content)

	if leftContent != rightContent && leftContent != "" && rightContent != "" {
		changes = append(changes, Change{
			Type:     ChangeTypeModified,
			Path:     path + "/text()",
			OldValue: leftContent,
			NewValue: rightContent,
		})
	}

	// Compare children
	maxChildren := len(left.Children)
	if len(right.Children) > maxChildren {
		maxChildren = len(right.Children)
	}

	for i := 0; i < maxChildren; i++ {
		var leftChild, rightChild *xmlNode

		if i < len(left.Children) {
			leftChild = &left.Children[i]
		}
		if i < len(right.Children) {
			rightChild = &right.Children[i]
		}

		childPath := path
		if leftChild != nil {
			childPath = fmt.Sprintf("%s/%s[%d]", path, leftChild.XMLName.Local, i+1)
		} else if rightChild != nil {
			childPath = fmt.Sprintf("%s/%s[%d]", path, rightChild.XMLName.Local, i+1)
		}

		changes = append(changes, e.diffXMLNodes(childPath, leftChild, rightChild)...)
	}

	return changes
}

// Helper functions

// splitLines splits text into lines
func splitLines(text string) []string {
	if text == "" {
		return []string{}
	}
	// Preserve line endings for accurate diffing
	lines := strings.Split(text, "\n")
	return lines
}

// splitWords splits text into words
func splitWords(text string) []string {
	var words []string
	var current strings.Builder

	for _, r := range text {
		if unicode.IsSpace(r) || unicode.IsPunct(r) {
			if current.Len() > 0 {
				words = append(words, current.String())
				current.Reset()
			}
			// Include whitespace and punctuation as separate tokens
			words = append(words, string(r))
		} else {
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		words = append(words, current.String())
	}

	return words
}

// formatValue converts a value to a string representation
func formatValue(val interface{}) string {
	if val == nil {
		return "null"
	}

	switch v := val.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%g", v)
	case bool:
		return fmt.Sprintf("%t", v)
	case map[string]interface{}, []interface{}:
		b, _ := json.Marshal(v)
		return string(b)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// calculateSimilarity calculates similarity score for text diffs
func calculateSimilarity(leftLen, rightLen, changeCount int) float64 {
	if leftLen == 0 && rightLen == 0 {
		return 100.0
	}

	maxLen := leftLen
	if rightLen > maxLen {
		maxLen = rightLen
	}

	if maxLen == 0 {
		return 100.0
	}

	// Calculate based on unchanged content
	unchanged := maxLen - changeCount
	if unchanged < 0 {
		unchanged = 0
	}

	return (float64(unchanged) / float64(maxLen)) * 100.0
}

// calculateJSONSimilarity calculates similarity for JSON objects
func calculateJSONSimilarity(left, right interface{}, changeCount int) float64 {
	leftSize := countJSONNodes(left)
	rightSize := countJSONNodes(right)

	maxSize := leftSize
	if rightSize > maxSize {
		maxSize = rightSize
	}

	if maxSize == 0 {
		return 100.0
	}

	unchanged := maxSize - changeCount
	if unchanged < 0 {
		unchanged = 0
	}

	return (float64(unchanged) / float64(maxSize)) * 100.0
}

// calculateXMLSimilarity calculates similarity for XML documents
func calculateXMLSimilarity(left, right *xmlNode, changeCount int) float64 {
	leftSize := countXMLNodes(left)
	rightSize := countXMLNodes(right)

	maxSize := leftSize
	if rightSize > maxSize {
		maxSize = rightSize
	}

	if maxSize == 0 {
		return 100.0
	}

	unchanged := maxSize - changeCount
	if unchanged < 0 {
		unchanged = 0
	}

	return (float64(unchanged) / float64(maxSize)) * 100.0
}

// countJSONNodes counts the number of nodes in a JSON structure
func countJSONNodes(val interface{}) int {
	if val == nil {
		return 1
	}

	switch v := val.(type) {
	case map[string]interface{}:
		count := 1
		for _, child := range v {
			count += countJSONNodes(child)
		}
		return count
	case []interface{}:
		count := 1
		for _, child := range v {
			count += countJSONNodes(child)
		}
		return count
	default:
		return 1
	}
}

// countXMLNodes counts the number of nodes in an XML structure
func countXMLNodes(node *xmlNode) int {
	if node == nil {
		return 0
	}

	count := 1 // Current node
	count += len(node.Attrs)

	for i := range node.Children {
		count += countXMLNodes(&node.Children[i])
	}

	return count
}

// GenerateUnifiedDiff generates a unified diff format (for text diffs)
func GenerateUnifiedDiff(result *DiffResult, leftName, rightName string) string {
	if result.Type != DiffTypeText {
		return ""
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("--- %s\n", leftName))
	buf.WriteString(fmt.Sprintf("+++ %s\n", rightName))

	for _, change := range result.Changes {
		switch change.Type {
		case ChangeTypeAdded:
			buf.WriteString(fmt.Sprintf("+%s\n", change.NewValue))
		case ChangeTypeRemoved:
			buf.WriteString(fmt.Sprintf("-%s\n", change.OldValue))
		case ChangeTypeModified:
			buf.WriteString(fmt.Sprintf("-%s\n", change.OldValue))
			buf.WriteString(fmt.Sprintf("+%s\n", change.NewValue))
		}
	}

	return buf.String()
}
