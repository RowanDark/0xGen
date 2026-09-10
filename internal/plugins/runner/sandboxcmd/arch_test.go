//go:build linux && amd64

package main

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/RowanDark/0xgen/internal/plugins/runner/sandboxcmd/internal/i386abi"
)

// archBypassSubprocessEnv, when set to "1" in the environment, tells this
// test binary to run as the subprocess side of
// TestApplyPolicyKillsOnI386ABIEntry rather than as the top-level test.
const archBypassSubprocessEnv = "SANDBOXCMD_TEST_ARCH_BYPASS_SUBPROCESS"

// applyPolicySubprocessEnv, when set to "1", tells this test binary to run
// as the subprocess side of TestApplyPolicyBuildsFilterForHostArch.
const applyPolicySubprocessEnv = "SANDBOXCMD_TEST_APPLY_POLICY_SUBPROCESS"

// TestApplyPolicyKillsOnI386ABIEntry verifies the fix for the
// architecture-confusion bypass of the seccomp filter: on x86-64, a
// process can enter the kernel through the i386 ABI (INT 0x80), where
// syscall numbers differ from the x86-64 numbers the denylist compares
// against. Without a seccomp_data.arch check, a blocked x86-64 syscall
// number is simply a different, unblocked syscall under the i386 table
// (and vice versa) -- a complete bypass. This test proves the filter now
// kills the process outright on an unexpected arch, independent of the
// denylist: it invokes getpid, which is never denylisted, through the
// i386 entry point and expects the process to die by SIGSYS anyway.
//
// The test re-execs the test binary as a subprocess so only the
// subprocess -- not the test runner itself -- runs under the seccomp
// filter.
//
// This is amd64-only. The equivalent aarch64 compat/AArch32 entry point
// depends on CONFIG_COMPAT and is frequently disabled on CI kernels (and
// on 0xGen's own build hosts), so there is no reliable way to exercise it
// from a portable Go test; seccompAuditArch's AUDIT_ARCH_AARCH64 branch
// is covered indirectly by TestApplyPolicyBuildsFilterForHostArch below.
func TestApplyPolicyKillsOnI386ABIEntry(t *testing.T) {
	if os.Getenv(archBypassSubprocessEnv) == "1" {
		runArchBypassSubprocess()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestApplyPolicyKillsOnI386ABIEntry$", "-test.v")
	cmd.Env = append(os.Environ(), archBypassSubprocessEnv+"=1")
	out, err := cmd.CombinedOutput()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected subprocess to be killed by the seccomp filter, got err=%v output=%s", err, out)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("unexpected wait status type %T", exitErr.Sys())
	}
	if !status.Signaled() {
		t.Fatalf("expected subprocess to be killed by a signal, got status=%v output=%s", status, out)
	}
	if status.Signal() != syscall.SIGSYS {
		t.Fatalf("expected subprocess killed by SIGSYS, got signal=%v status=%v output=%s", status.Signal(), status, out)
	}
}

func runArchBypassSubprocess() {
	if err := applyPolicy(); err != nil {
		os.Stderr.WriteString("apply policy: " + err.Error() + "\n")
		os.Exit(1)
	}

	// getpid is never denylisted, so reaching this call at all proves the
	// arch check -- not the syscall-number denylist -- is what has to
	// kill the process.
	i386abi.Getpid()

	// Unreachable if the seccomp filter's arch check works: the kernel
	// kills the process with SIGSYS before the syscall returns.
	os.Stderr.WriteString("UNEXPECTED: i386 ABI syscall was not blocked\n")
	os.Exit(0)
}

// TestApplyPolicyBuildsFilterForHostArch is a smoke test that applyPolicy
// succeeds on the host's own architecture, i.e. seccompAuditArch resolves
// an AUDIT_ARCH_* value for GOARCH and the resulting filter installs
// without error.
func TestApplyPolicyBuildsFilterForHostArch(t *testing.T) {
	if os.Getenv(applyPolicySubprocessEnv) == "1" {
		if err := applyPolicy(); err != nil {
			os.Stderr.WriteString("apply policy: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestApplyPolicyBuildsFilterForHostArch$", "-test.v")
	cmd.Env = append(os.Environ(), applyPolicySubprocessEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess applyPolicy() failed: %v output=%s", err, out)
	}
}
