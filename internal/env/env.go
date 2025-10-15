package env

import (
	"log"
	"os"
	"sync"
)

var (
	warnLogger func(format string, args ...any) = log.Printf
	warnMu     sync.Mutex
	warnedKeys sync.Map
)

// Lookup returns the value of newKey if it exists. When the legacy oldKey is
// present it is returned instead and a deprecation warning is logged once.
func Lookup(newKey, oldKey string) (string, bool) {
	if v, ok := os.LookupEnv(newKey); ok {
		return v, true
	}
	if v, ok := os.LookupEnv(oldKey); ok {
		logDeprecated(oldKey, newKey)
		return v, true
	}
	return "", false
}

func logDeprecated(oldKey, newKey string) {
	onceIface, _ := warnedKeys.LoadOrStore(oldKey, &sync.Once{})
	once := onceIface.(*sync.Once)
	once.Do(func() {
		warnMu.Lock()
		logger := warnLogger
		warnMu.Unlock()
		logger("%s is deprecated; use %s", oldKey, newKey)
	})
}

// ResetWarningsForTesting clears the cached once guards so tests can verify
// warning behaviour deterministically.
func ResetWarningsForTesting() {
	warnMu.Lock()
	warnedKeys = sync.Map{}
	warnMu.Unlock()
}

// SetWarnLoggerForTesting swaps the logger used for warnings. The returned
// function restores the previous logger and should be deferred in tests.
func SetWarnLoggerForTesting(fn func(format string, args ...any)) (restore func()) {
	warnMu.Lock()
	previous := warnLogger
	warnLogger = fn
	warnMu.Unlock()
	return func() {
		warnMu.Lock()
		warnLogger = previous
		warnMu.Unlock()
	}
}
