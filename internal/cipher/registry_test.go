package cipher

import (
	"context"
	"testing"
)

// mockOperation is a test implementation of Operation
type mockOperation struct {
	BaseOperation
}

func (m *mockOperation) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	return input, nil
}

func TestRegisterOperation(t *testing.T) {
	// Clean slate for each test
	ClearRegistry()

	op := &mockOperation{
		BaseOperation: BaseOperation{
			NameValue:        "mock",
			TypeValue:        OperationTypeEncode,
			DescriptionValue: "Mock operation for testing",
		},
	}

	err := RegisterOperation(op)
	if err != nil {
		t.Fatalf("failed to register operation: %v", err)
	}

	// Test duplicate registration
	err = RegisterOperation(op)
	if err == nil {
		t.Fatal("expected error when registering duplicate operation")
	}
}

func TestGetOperation(t *testing.T) {
	ClearRegistry()

	op := &mockOperation{
		BaseOperation: BaseOperation{
			NameValue:        "test-op",
			TypeValue:        OperationTypeEncode,
			DescriptionValue: "Test operation",
		},
	}

	RegisterOperation(op)

	retrieved, exists := GetOperation("test-op")
	if !exists {
		t.Fatal("operation should exist")
	}

	if retrieved.Name() != "test-op" {
		t.Errorf("expected name 'test-op', got '%s'", retrieved.Name())
	}

	_, exists = GetOperation("non-existent")
	if exists {
		t.Fatal("non-existent operation should not exist")
	}
}

func TestListOperations(t *testing.T) {
	ClearRegistry()

	ops := []Operation{
		&mockOperation{
			BaseOperation: BaseOperation{
				NameValue:        "op1",
				TypeValue:        OperationTypeEncode,
				DescriptionValue: "Operation 1",
			},
		},
		&mockOperation{
			BaseOperation: BaseOperation{
				NameValue:        "op2",
				TypeValue:        OperationTypeDecode,
				DescriptionValue: "Operation 2",
			},
		},
	}

	for _, op := range ops {
		RegisterOperation(op)
	}

	list := ListOperations()
	if len(list) != 2 {
		t.Errorf("expected 2 operations, got %d", len(list))
	}

	// Check they're sorted by name
	if list[0].Name() != "op1" || list[1].Name() != "op2" {
		t.Error("operations should be sorted by name")
	}
}

func TestListOperationsByType(t *testing.T) {
	ClearRegistry()

	RegisterOperation(&mockOperation{
		BaseOperation: BaseOperation{
			NameValue:        "encode1",
			TypeValue:        OperationTypeEncode,
			DescriptionValue: "Encoder 1",
		},
	})

	RegisterOperation(&mockOperation{
		BaseOperation: BaseOperation{
			NameValue:        "decode1",
			TypeValue:        OperationTypeDecode,
			DescriptionValue: "Decoder 1",
		},
	})

	RegisterOperation(&mockOperation{
		BaseOperation: BaseOperation{
			NameValue:        "encode2",
			TypeValue:        OperationTypeEncode,
			DescriptionValue: "Encoder 2",
		},
	})

	encoders := ListOperationsByType(OperationTypeEncode)
	if len(encoders) != 2 {
		t.Errorf("expected 2 encoders, got %d", len(encoders))
	}

	decoders := ListOperationsByType(OperationTypeDecode)
	if len(decoders) != 1 {
		t.Errorf("expected 1 decoder, got %d", len(decoders))
	}
}
