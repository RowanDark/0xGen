package main

import (
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/RowanDark/Glyph/internal/proxy"
)

func runProxyTrust(args []string) int {
	fs := flag.NewFlagSet("proxy trust", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outPath := fs.String("out", "", "path to write the proxy root certificate (PEM format)")
	printCert := fs.Bool("print", false, "write the proxy root certificate to standard output")
	install := fs.Bool("install", false, "install the proxy root certificate into the current user's trust store (Windows only)")
	quiet := fs.Bool("quiet", false, "suppress informational output")
	certPath := fs.String("cert-path", "", "override the proxy certificate path (advanced)")
	keyPath := fs.String("key-path", "", "override the proxy certificate private key path (advanced)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument: %s\n", fs.Arg(0))
		return 2
	}

	if !*install && strings.TrimSpace(*outPath) == "" && !*printCert {
		fmt.Fprintln(os.Stderr, "no action requested: use --install, --out, or --print")
		return 2
	}

	certPEM, err := proxy.EnsureRootCertificate(*certPath, *keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load proxy certificate: %v\n", err)
		return 1
	}

	if *printCert {
		if _, err := os.Stdout.Write(certPEM); err != nil {
			fmt.Fprintf(os.Stderr, "write certificate: %v\n", err)
			return 1
		}
		if len(certPEM) == 0 || certPEM[len(certPEM)-1] != '\n' {
			fmt.Fprintln(os.Stdout)
		}
	}

	if strings.TrimSpace(*outPath) != "" {
		if err := os.WriteFile(*outPath, certPEM, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write certificate: %v\n", err)
			return 1
		}
		if !*quiet {
			fmt.Fprintf(os.Stdout, "wrote proxy certificate to %s\n", filepath.Clean(*outPath))
		}
	}

	if *install {
		if err := installRootCertificate(certPEM); err != nil {
			fmt.Fprintf(os.Stderr, "install proxy certificate: %v\n", err)
			return 1
		}
		if !*quiet {
			fmt.Fprintln(os.Stdout, "proxy certificate installed for the current user")
		}
	}

	return 0
}

func installRootCertificate(certPEM []byte) error {
	if runtime.GOOS != "windows" {
		return errors.New("certificate installation is only supported on Windows")
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || len(block.Bytes) == 0 {
		return errors.New("proxy certificate is not a valid PEM-encoded certificate")
	}

	temp, err := os.CreateTemp("", "glyph-proxy-ca-*.cer")
	if err != nil {
		return fmt.Errorf("create temporary certificate file: %w", err)
	}
	tempPath := temp.Name()
	if _, err := temp.Write(certPEM); err != nil {
		temp.Close()
		os.Remove(tempPath)
		return fmt.Errorf("write temporary certificate file: %w", err)
	}
	if err := temp.Close(); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("close temporary certificate file: %w", err)
	}
	defer os.Remove(tempPath)

	command := fmt.Sprintf("& { Import-Certificate -FilePath '%s' -CertStoreLocation Cert:\\CurrentUser\\Root | Out-Null }", escapeForPowerShell(tempPath))
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Import-Certificate failed: %v: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func escapeForPowerShell(path string) string {
	return strings.ReplaceAll(path, "'", "''")
}
