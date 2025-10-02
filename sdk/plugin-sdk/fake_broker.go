package pluginsdk

import (
	"context"
	"errors"
	"net/http"
	"sync"
)

// FakeBroker implements Broker for tests and local development.
type FakeBroker struct {
	mu sync.Mutex

	files       map[string][]byte
	secrets     map[string]string
	requests    []HTTPRequest
	responses   map[string]HTTPResult
	audits      []FakeAuditEntry
	denyFS      map[string]string
	denyNet     map[string]string
	denySecrets map[string]string
	denyAllFS   string
}

// FakeAuditEntry captures a broker operation and whether it was allowed.
type FakeAuditEntry struct {
	Operation string
	Target    string
	Allowed   bool
	Message   string
}

// NewFakeBroker creates a FakeBroker with empty storage.
func NewFakeBroker() *FakeBroker {
	return &FakeBroker{
		files:       make(map[string][]byte),
		secrets:     make(map[string]string),
		responses:   make(map[string]HTTPResult),
		denyFS:      make(map[string]string),
		denyNet:     make(map[string]string),
		denySecrets: make(map[string]string),
	}
}

// Filesystem implements Broker.
func (b *FakeBroker) Filesystem() FilesystemBroker { return (*fakeFS)(b) }

// Network implements Broker.
func (b *FakeBroker) Network() NetworkBroker { return (*fakeNet)(b) }

// Secrets implements Broker.
func (b *FakeBroker) Secrets() SecretsBroker { return (*fakeSecrets)(b) }

// SetFile seeds the fake filesystem.
func (b *FakeBroker) SetFile(path string, data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.files[path] = append([]byte(nil), data...)
}

// SetSecret seeds the fake secret store.
func (b *FakeBroker) SetSecret(name, value string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.secrets[name] = value
}

// SetHTTPResponse configures a canned response for the given URL and method.
func (b *FakeBroker) SetHTTPResponse(method, url string, res HTTPResult) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := method + " " + url
	b.responses[key] = res
}

// DenyFilesystem configures a denial for a specific path. Provide an empty path to
// reject all filesystem operations.
func (b *FakeBroker) DenyFilesystem(path, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if path == "" {
		b.denyAllFS = reason
		return
	}
	b.denyFS[path] = reason
}

// DenyNetwork configures a denial for a given method and URL.
func (b *FakeBroker) DenyNetwork(method, url, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := method + " " + url
	b.denyNet[key] = reason
}

// DenySecret configures a denial for a named secret.
func (b *FakeBroker) DenySecret(name, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.denySecrets[name] = reason
}

// Requests returns a snapshot of recorded HTTP requests.
func (b *FakeBroker) Requests() []HTTPRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]HTTPRequest, len(b.requests))
	copy(out, b.requests)
	return out
}

// AuditLog returns the recorded broker interactions.
func (b *FakeBroker) AuditLog() []FakeAuditEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]FakeAuditEntry, len(b.audits))
	copy(out, b.audits)
	return out
}

func (b *FakeBroker) record(op, target string, allowed bool, msg string) {
	b.audits = append(b.audits, FakeAuditEntry{Operation: op, Target: target, Allowed: allowed, Message: msg})
}

type fakeFS FakeBroker

type fakeNet FakeBroker

type fakeSecrets FakeBroker

func (f *fakeFS) ReadFile(ctx context.Context, path string) ([]byte, error) {
	fb := (*FakeBroker)(f)
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if reason := fb.denyAllFS; reason != "" {
		fb.record("fs.read", path, false, reason)
		return nil, errors.New(reason)
	}
	if reason, ok := fb.denyFS[path]; ok {
		fb.record("fs.read", path, false, reason)
		return nil, errors.New(reason)
	}
	data, ok := fb.files[path]
	if !ok {
		fb.record("fs.read", path, false, ErrNotFound.Error())
		return nil, ErrNotFound
	}
	out := make([]byte, len(data))
	copy(out, data)
	fb.record("fs.read", path, true, "ok")
	return out, nil
}

func (f *fakeFS) WriteFile(ctx context.Context, path string, data []byte) error {
	fb := (*FakeBroker)(f)
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if reason := fb.denyAllFS; reason != "" {
		fb.record("fs.write", path, false, reason)
		return errors.New(reason)
	}
	if reason, ok := fb.denyFS[path]; ok {
		fb.record("fs.write", path, false, reason)
		return errors.New(reason)
	}
	fb.files[path] = append([]byte(nil), data...)
	fb.record("fs.write", path, true, "ok")
	return nil
}

func (f *fakeFS) Remove(ctx context.Context, path string) error {
	fb := (*FakeBroker)(f)
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if reason := fb.denyAllFS; reason != "" {
		fb.record("fs.remove", path, false, reason)
		return errors.New(reason)
	}
	if reason, ok := fb.denyFS[path]; ok {
		fb.record("fs.remove", path, false, reason)
		return errors.New(reason)
	}
	delete(fb.files, path)
	fb.record("fs.remove", path, true, "ok")
	return nil
}

func (n *fakeNet) Do(ctx context.Context, req HTTPRequest) (HTTPResult, error) {
	fb := (*FakeBroker)(n)
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.requests = append(fb.requests, req)
	key := req.Method + " " + req.URL
	if reason, ok := fb.denyNet[key]; ok {
		fb.record("net.do", key, false, reason)
		return HTTPResult{}, errors.New(reason)
	}
	if res, ok := fb.responses[key]; ok {
		fb.record("net.do", key, true, "ok")
		return res, nil
	}
	fb.record("net.do", key, true, "ok")
	return HTTPResult{StatusCode: http.StatusOK, Headers: make(http.Header), Body: nil}, nil
}

func (s *fakeSecrets) Get(ctx context.Context, name string) (string, error) {
	fb := (*FakeBroker)(s)
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if reason, ok := fb.denySecrets[name]; ok {
		fb.record("secrets.get", name, false, reason)
		return "", errors.New(reason)
	}
	secret, ok := fb.secrets[name]
	if !ok {
		fb.record("secrets.get", name, false, ErrNotFound.Error())
		return "", ErrNotFound
	}
	fb.record("secrets.get", name, true, "ok")
	return secret, nil
}
