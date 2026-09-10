//go:build !slsa

package main

import (
	"fmt"
	"os"
)

// runVerifyBuild is a stub used when the binary is built without the
// "slsa" build tag. The real implementation (verify_build.go) pulls in
// github.com/slsa-framework/slsa-verifier/v2, which transitively drags in
// cosign, sigstore, rekor, fulcio, docker, kubernetes, trillian, the AWS and
// Azure SDKs, and the MongoDB driver. Keeping it opt-in keeps default builds
// of 0xgenctl usable in restricted-egress environments.
func runVerifyBuild(args []string) int {
	fmt.Fprintln(os.Stderr, "verify-build is unavailable in this build of 0xgenctl")
	fmt.Fprintln(os.Stderr, "rebuild with: go build -tags slsa ./cmd/0xgenctl")
	return 2
}
