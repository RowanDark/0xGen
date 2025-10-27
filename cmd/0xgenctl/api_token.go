package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/config"
)

func runAPITokenNew(args []string) int {
	fs := flag.NewFlagSet("api-token new", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	subject := fs.String("subject", "ci-client", "subject claim for the issued token")
	audience := fs.String("audience", "0xgen-ci", "audience claim for the issued token")
	ttl := fs.Duration("ttl", time.Hour, "requested token lifetime")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 1
	}

	endpoint := strings.TrimSpace(cfg.APIEndpoint)
	if endpoint == "" {
		fmt.Fprintln(os.Stderr, "api_endpoint is not configured; set it in 0xgen.yml or via 0XGEN_API_ENDPOINT")
		return 1
	}
	if strings.TrimSpace(cfg.AuthToken) == "" {
		fmt.Fprintln(os.Stderr, "auth_token is not configured; set it before issuing API tokens")
		return 1
	}

	sub := strings.TrimSpace(*subject)
	if sub == "" {
		fmt.Fprintln(os.Stderr, "--subject must not be empty")
		return 2
	}
	aud := strings.TrimSpace(*audience)
	if aud == "" {
		aud = "0xgen-ci"
	}
	if *ttl <= 0 {
		*ttl = time.Hour
	}

	payload := map[string]any{
		"subject":     sub,
		"audience":    aud,
		"ttl_seconds": ttl.Seconds(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode request: %v\n", err)
		return 1
	}

	url := strings.TrimRight(endpoint, "/") + "/api/v1/api-tokens"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "build request: %v\n", err)
		return 1
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-0xgen-Token", cfg.AuthToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request api token: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		message := strings.TrimSpace(apiErr.Error)
		if message == "" {
			message = resp.Status
		}
		fmt.Fprintf(os.Stderr, "api rejected request: %s\n", message)
		return 1
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Fprintf(os.Stderr, "decode response: %v\n", err)
		return 1
	}
	token := strings.TrimSpace(result.Token)
	if token == "" {
		fmt.Fprintln(os.Stderr, "api returned empty token")
		return 1
	}
	fmt.Fprintln(os.Stdout, token)
	if trimmed := strings.TrimSpace(result.ExpiresAt); trimmed != "" {
		fmt.Fprintf(os.Stdout, "expires_at: %s\n", trimmed)
	}
	return 0
}
