// Package cipher provides encoding, decoding, and transformation operations
// for security testing and payload analysis.
package cipher

import (
	"context"
	"fmt"
)

// OperationType defines the category of transformation operation
type OperationType string

const (
	OperationTypeEncode     OperationType = "encode"
	OperationTypeDecode     OperationType = "decode"
	OperationTypeHash       OperationType = "hash"
	OperationTypeCompress   OperationType = "compress"
	OperationTypeDecompress OperationType = "decompress"
	OperationTypeEncrypt    OperationType = "encrypt"
	OperationTypeDecrypt    OperationType = "decrypt"
)

// Operation represents a single transformation operation that can be applied to data
type Operation interface {
	// Name returns the unique identifier for this operation
	Name() string

	// Type returns the category of this operation
	Type() OperationType

	// Description returns a human-readable description
	Description() string

	// Execute applies the operation to the input data
	Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error)

	// Reverse returns the inverse operation if available
	Reverse() (Operation, bool)
}

// OperationConfig represents configuration for an operation in a pipeline
type OperationConfig struct {
	Name       string                 `json:"name"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// Pipeline represents a chain of operations that can be applied sequentially
type Pipeline struct {
	Operations []OperationConfig `json:"operations"`
	Reversible bool              `json:"reversible"`
}

// Execute runs the pipeline on the input data
func (p *Pipeline) Execute(ctx context.Context, input []byte) ([]byte, error) {
	result := input
	var err error

	for i, opConfig := range p.Operations {
		op, exists := GetOperation(opConfig.Name)
		if !exists {
			return nil, fmt.Errorf("unknown operation at step %d: %s", i, opConfig.Name)
		}

		result, err = op.Execute(ctx, result, opConfig.Parameters)
		if err != nil {
			return nil, fmt.Errorf("operation %s failed at step %d: %w", opConfig.Name, i, err)
		}
	}

	return result, nil
}

// Reverse creates a reversed pipeline if all operations are reversible
func (p *Pipeline) Reverse() (*Pipeline, error) {
	if !p.Reversible {
		return nil, fmt.Errorf("pipeline is not reversible")
	}

	reversed := &Pipeline{
		Operations: make([]OperationConfig, len(p.Operations)),
		Reversible: true,
	}

	// Reverse the order and get inverse operations
	for i, opConfig := range p.Operations {
		op, exists := GetOperation(opConfig.Name)
		if !exists {
			return nil, fmt.Errorf("unknown operation: %s", opConfig.Name)
		}

		reverseOp, ok := op.Reverse()
		if !ok {
			return nil, fmt.Errorf("operation %s is not reversible", opConfig.Name)
		}

		reversed.Operations[len(p.Operations)-1-i] = OperationConfig{
			Name:       reverseOp.Name(),
			Parameters: opConfig.Parameters,
		}
	}

	return reversed, nil
}

// Recipe represents a named, reusable transformation pipeline
type Recipe struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags,omitempty"`
	Pipeline    Pipeline `json:"pipeline"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

// DetectionResult represents the result of automatic encoding detection
type DetectionResult struct {
	Encoding   string  `json:"encoding"`
	Confidence float64 `json:"confidence"` // 0.0 to 1.0
	Reasoning  string  `json:"reasoning"`
	Operation  string  `json:"operation"` // Suggested operation name to decode
}

// Detector identifies the encoding or format of input data
type Detector interface {
	// Detect attempts to identify the encoding of the input
	Detect(ctx context.Context, input []byte) ([]DetectionResult, error)

	// SupportedEncodings returns a list of encodings this detector can identify
	SupportedEncodings() []string
}

// BaseOperation provides common functionality for operations
type BaseOperation struct {
	NameValue        string
	TypeValue        OperationType
	DescriptionValue string
	ReverseOp        Operation
}

func (b *BaseOperation) Name() string {
	return b.NameValue
}

func (b *BaseOperation) Type() OperationType {
	return b.TypeValue
}

func (b *BaseOperation) Description() string {
	return b.DescriptionValue
}

func (b *BaseOperation) Reverse() (Operation, bool) {
	if b.ReverseOp == nil {
		return nil, false
	}
	return b.ReverseOp, true
}
