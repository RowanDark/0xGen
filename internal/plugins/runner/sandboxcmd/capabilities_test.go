package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// capBoundSubprocessEnv, when set to "1", tells this test binary to run as
// the subprocess side of TestDropCapabilityBoundingSetClearsProcStatus
// rather than as the top-level test.
const capBoundSubprocessEnv = "SANDBOXCMD_TEST_CAPBSET_SUBPROCESS"

// TestDropCapabilityBoundingSetClearsProcStatus verifies that
// dropCapabilityBoundingSet does not just call PR_CAPBSET_DROP without
// error, but actually empties the kernel's record of the process's
// capability bounding set (/proc/self/status CapBnd), which is what makes
// the drop meaningful: a process with an empty bounding set can never gain
// a Linux capability again, even across a later setuid(0).
//
// The test re-execs the test binary as a subprocess so only the subprocess
// -- not the test runner itself -- has its bounding set torn down.
func TestDropCapabilityBoundingSetClearsProcStatus(t *testing.T) {
	if os.Getenv(capBoundSubprocessEnv) == "1" {
		if err := dropCapabilityBoundingSet(); err != nil {
			os.Stderr.WriteString("drop capability bounding set: " + err.Error() + "\n")
			os.Exit(1)
		}
		data, err := os.ReadFile("/proc/self/status")
		if err != nil {
			os.Stderr.WriteString("read /proc/self/status: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Stdout.Write(data)
		os.Exit(0)
	}

	if os.Geteuid() != 0 {
		t.Skip("dropping the capability bounding set requires CAP_SETPCAP (root)")
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestDropCapabilityBoundingSetClearsProcStatus$")
	cmd.Env = append(os.Environ(), capBoundSubprocessEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v output=%s", err, out)
	}

	var capBnd string
	for _, line := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(line, "CapBnd:"); ok {
			capBnd = strings.TrimSpace(rest)
		}
	}
	if capBnd == "" {
		t.Fatalf("CapBnd not found in subprocess /proc/self/status output:\n%s", out)
	}
	value, err := strconv.ParseUint(capBnd, 16, 64)
	if err != nil {
		t.Fatalf("parse CapBnd %q: %v", capBnd, err)
	}
	if value != 0 {
		t.Fatalf("CapBnd = %016x, want 0 (empty bounding set)", value)
	}
}
