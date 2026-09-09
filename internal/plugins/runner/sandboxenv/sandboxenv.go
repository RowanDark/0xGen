// Package sandboxenv defines the environment variable contract used to pass
// resource limits from the 0xgen daemon (the parent process) into the
// sandboxcmd helper (the child process) without applying rlimits to the
// daemon itself.
//
// The parent sets these variables only on the sandbox helper's environment.
// The helper reads them after dropping privileges, applies the
// corresponding rlimits to itself, strips them from the environment, and
// only then execs the plugin binary — so the values never reach the plugin
// process and never touch the daemon's own limits.
package sandboxenv

const (
	// CPUSecondsEnv carries the RLIMIT_CPU value (seconds) to apply to the
	// sandboxed plugin process.
	CPUSecondsEnv = "OXGEN_SANDBOX_CPU_SECONDS"

	// MemoryBytesEnv carries the RLIMIT_AS value (bytes) to apply to the
	// sandboxed plugin process.
	MemoryBytesEnv = "OXGEN_SANDBOX_MEMORY_BYTES"
)
