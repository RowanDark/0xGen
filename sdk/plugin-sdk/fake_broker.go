package pluginsdk

import (
	"context"
	"net/http"
	"sync"
)

// FakeBroker implements Broker for tests and local development.
type FakeBroker struct {
	mu sync.Mutex

	files     map[string][]byte
	secrets   map[string]string
	requests  []HTTPRequest
	responses map[string]HTTPResult
}

// NewFakeBroker creates a FakeBroker with empty storage.
func NewFakeBroker() *FakeBroker {
	return &FakeBroker{
		files:     make(map[string][]byte),
		secrets:   make(map[string]string),
		responses: make(map[string]HTTPResult),
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

// Requests returns a snapshot of recorded HTTP requests.
func (b *FakeBroker) Requests() []HTTPRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]HTTPRequest, len(b.requests))
	copy(out, b.requests)
	return out
}

type fakeFS FakeBroker

type fakeNet FakeBroker

type fakeSecrets FakeBroker

func (f *fakeFS) ReadFile(ctx context.Context, path string) ([]byte, error) {
	fb := (*FakeBroker)(f)
	fb.mu.Lock()
	defer fb.mu.Unlock()
	data, ok := fb.files[path]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

func (f *fakeFS) WriteFile(ctx context.Context, path string, data []byte) error {
	fb := (*FakeBroker)(f)
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.files[path] = append([]byte(nil), data...)
	return nil
}

func (f *fakeFS) Remove(ctx context.Context, path string) error {
	fb := (*FakeBroker)(f)
	fb.mu.Lock()
	defer fb.mu.Unlock()
	delete(fb.files, path)
	return nil
}

func (n *fakeNet) Do(ctx context.Context, req HTTPRequest) (HTTPResult, error) {
	fb := (*FakeBroker)(n)
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.requests = append(fb.requests, req)
	key := req.Method + " " + req.URL
	if res, ok := fb.responses[key]; ok {
		return res, nil
	}
	return HTTPResult{StatusCode: http.StatusOK, Headers: make(http.Header), Body: nil}, nil
}

func (s *fakeSecrets) Get(ctx context.Context, name string) (string, error) {
	fb := (*FakeBroker)(s)
	fb.mu.Lock()
	defer fb.mu.Unlock()
	secret, ok := fb.secrets[name]
	if !ok {
		return "", ErrNotFound
	}
	return secret, nil
}
