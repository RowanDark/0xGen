package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/history"
	"github.com/RowanDark/0xgen/internal/proxy"
)

type setArgs []string

func (s *setArgs) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *setArgs) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func runRepeaterSend(args []string) int {
	fs := flag.NewFlagSet("repeater send", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	historyPath := fs.String("history", history.DefaultPath(), "path to the proxy history JSONL log")
	id := fs.String("id", "", "history entry identifier to replay")
	bodyOverride := fs.String("set-body", "", "override request body (prefix with @ to read from file)")
	timeout := fs.Duration("timeout", 30*time.Second, "request timeout")
	var overrides setArgs
	fs.Var(&overrides, "set", "override request attributes (e.g. Header:X-Token=value)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	trimmedID := strings.TrimSpace(*id)
	if trimmedID == "" {
		fmt.Fprintln(os.Stderr, "--id must be provided")
		return 2
	}

	idx, err := history.Load(*historyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load history: %v\n", err)
		return 1
	}
	record, ok := idx.Entry(trimmedID)
	if !ok {
		fmt.Fprintf(os.Stderr, "history entry %s not found\n", trimmedID)
		return 1
	}

	headers := normaliseHeaderMap(record.Record.RequestHeaders)
	body, err := readBodyOverride(*bodyOverride)
	if err != nil {
		fmt.Fprintf(os.Stderr, "set body: %v\n", err)
		return 2
	}

	for _, raw := range overrides {
		op, err := parseSetOperation(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --set value %q: %v\n", raw, err)
			return 2
		}
		applySetOperation(headers, op)
	}

	updateContentLength(headers, len(body))

	req, err := buildRequest(record.Record, headers, body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build request: %v\n", err)
		return 1
	}

	client := &http.Client{Timeout: *timeout}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay request: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read response: %v\n", err)
		return 1
	}
	latency := time.Since(start)

	clientIP := clientAddress(resp.Request)
	historyEntry := proxy.HistoryEntry{
		Timestamp:       time.Now().UTC(),
		ClientIP:        clientIP,
		Protocol:        strings.ToUpper(req.URL.Scheme),
		Method:          strings.ToUpper(req.Method),
		URL:             req.URL.String(),
		StatusCode:      resp.StatusCode,
		LatencyMillis:   latency.Milliseconds(),
		RequestSize:     len(body),
		ResponseSize:    len(respBody),
		RequestHeaders:  captureRequestHeaders(req),
		ResponseHeaders: cloneHTTPHeader(resp.Header),
	}

	if err := history.Append(*historyPath, historyEntry); err != nil {
		fmt.Fprintf(os.Stderr, "append history: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stdout, "%s %s -> %d (%d ms)\n", strings.ToUpper(req.Method), req.URL.String(), resp.StatusCode, latency.Milliseconds())
	return 0
}

func readBodyOverride(raw string) ([]byte, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "@") {
		path := strings.TrimSpace(trimmed[1:])
		if path == "" {
			return nil, errors.New("body file path missing after @")
		}
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil, fmt.Errorf("read body file: %w", err)
		}
		return data, nil
	}
	return []byte(raw), nil
}

func parseSetOperation(raw string) (setOperation, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return setOperation{}, errors.New("empty override")
	}
	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) != 2 {
		return setOperation{}, errors.New("expected format key:value")
	}
	key := strings.ToLower(strings.TrimSpace(parts[0]))
	rest := parts[1]
	switch key {
	case "header":
		nameValue := strings.SplitN(rest, "=", 2)
		if len(nameValue) != 2 {
			return setOperation{}, errors.New("expected Header:Name=value")
		}
		name := strings.TrimSpace(nameValue[0])
		if name == "" {
			return setOperation{}, errors.New("header name missing")
		}
		value := strings.TrimSpace(nameValue[1])
		return setOperation{kind: key, name: name, value: value}, nil
	default:
		return setOperation{}, fmt.Errorf("unknown override %q", key)
	}
}

func applySetOperation(headers map[string][]string, op setOperation) {
	if headers == nil {
		return
	}
	switch op.kind {
	case "header":
		canonical := http.CanonicalHeaderKey(op.name)
		headers[canonical] = []string{op.value}
	}
}

func updateContentLength(headers map[string][]string, size int) {
	if headers == nil {
		return
	}
	headers["Content-Length"] = []string{strconv.Itoa(size)}
}

func buildRequest(entry proxy.HistoryEntry, headers map[string][]string, body []byte) (*http.Request, error) {
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(entry.Method, entry.URL, reader)
	if err != nil {
		return nil, err
	}
	applyHeaders(req, headers)
	if reader == nil {
		req.ContentLength = 0
	} else {
		req.ContentLength = int64(len(body))
	}
	return req, nil
}

func applyHeaders(req *http.Request, headers map[string][]string) {
	if headers == nil {
		return
	}
	host := ""
	req.Header = make(http.Header)
	for name, values := range headers {
		if strings.EqualFold(name, "Host") {
			if len(values) > 0 {
				host = values[0]
			}
			continue
		}
		canonical := http.CanonicalHeaderKey(name)
		for _, value := range values {
			req.Header.Add(canonical, value)
		}
	}
	if host != "" {
		req.Host = host
	}
}

func captureRequestHeaders(req *http.Request) map[string][]string {
	if req == nil {
		return nil
	}
	result := make(map[string][]string, len(req.Header)+1)
	for name, values := range req.Header {
		result[name] = append([]string(nil), values...)
	}
	if req.Host != "" {
		result["Host"] = []string{req.Host}
	}
	return result
}

func cloneHTTPHeader(headers http.Header) map[string][]string {
	if len(headers) == 0 {
		return nil
	}
	result := make(map[string][]string, len(headers))
	for name, values := range headers {
		result[name] = append([]string(nil), values...)
	}
	return result
}

func normaliseHeaderMap(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return make(map[string][]string)
	}
	result := make(map[string][]string, len(in))
	for name, values := range in {
		canonical := http.CanonicalHeaderKey(name)
		result[canonical] = append([]string(nil), values...)
	}
	return result
}

func clientAddress(req *http.Request) string {
	if req == nil {
		return ""
	}
	addr, ok := req.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

type setOperation struct {
	kind  string
	name  string
	value string
}
