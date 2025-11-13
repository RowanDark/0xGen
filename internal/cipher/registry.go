package cipher

import (
	"fmt"
	"sort"
	"sync"
)

// Global operation registry
var (
	operationsRegistry = make(map[string]Operation)
	registryMu         sync.RWMutex
)

// RegisterOperation adds an operation to the global registry
func RegisterOperation(op Operation) error {
	if op == nil {
		return fmt.Errorf("cannot register nil operation")
	}

	name := op.Name()
	if name == "" {
		return fmt.Errorf("operation name cannot be empty")
	}

	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := operationsRegistry[name]; exists {
		return fmt.Errorf("operation %s is already registered", name)
	}

	operationsRegistry[name] = op
	return nil
}

// GetOperation retrieves an operation from the registry by name
func GetOperation(name string) (Operation, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	op, exists := operationsRegistry[name]
	return op, exists
}

// ListOperations returns all registered operations
func ListOperations() []Operation {
	registryMu.RLock()
	defer registryMu.RUnlock()

	ops := make([]Operation, 0, len(operationsRegistry))
	for _, op := range operationsRegistry {
		ops = append(ops, op)
	}

	// Sort by name for consistent ordering
	sort.Slice(ops, func(i, j int) bool {
		return ops[i].Name() < ops[j].Name()
	})

	return ops
}

// ListOperationsByType returns operations filtered by type
func ListOperationsByType(opType OperationType) []Operation {
	registryMu.RLock()
	defer registryMu.RUnlock()

	ops := make([]Operation, 0)
	for _, op := range operationsRegistry {
		if op.Type() == opType {
			ops = append(ops, op)
		}
	}

	sort.Slice(ops, func(i, j int) bool {
		return ops[i].Name() < ops[j].Name()
	})

	return ops
}

// UnregisterOperation removes an operation from the registry (mainly for testing)
func UnregisterOperation(name string) {
	registryMu.Lock()
	defer registryMu.Unlock()

	delete(operationsRegistry, name)
}

// ClearRegistry removes all operations (mainly for testing)
func ClearRegistry() {
	registryMu.Lock()
	defer registryMu.Unlock()

	operationsRegistry = make(map[string]Operation)
}
