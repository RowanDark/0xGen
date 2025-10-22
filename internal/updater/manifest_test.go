package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func signManifest(t *testing.T, priv ed25519.PrivateKey, manifest []byte) string {
	t.Helper()
	sig := ed25519.Sign(priv, manifest)
	return base64.StdEncoding.EncodeToString(sig)
}

func TestFetchManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	manifest := Manifest{
		Version: "1.2.3",
		Channel: ChannelStable,
		Builds: []Build{{
			OS:   "linux",
			Arch: "amd64",
			Full: Artifact{
				URL:    "https://example.com/full",
				SHA256: "abc",
			},
		}},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	sig := signManifest(t, priv, data)

	mux := http.NewServeMux()
	mux.HandleFunc("/stable/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	})
	mux.HandleFunc("/stable/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sig))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("0XGEN_UPDATER_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))

	got, raw, err := FetchManifest(context.Background(), srv.Client(), srv.URL, ChannelStable)
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if string(raw) != string(data) {
		t.Fatalf("unexpected raw manifest")
	}
	if got.Version != manifest.Version {
		t.Fatalf("expected version %s, got %s", manifest.Version, got.Version)
	}
	if len(got.Builds) != 1 {
		t.Fatalf("expected 1 build, got %d", len(got.Builds))
	}
}

func TestFetchManifestInvalidSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	t.Setenv("0XGEN_UPDATER_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))

	manifest := []byte(`{"version":"1.0.0","channel":"stable","builds":[{"os":"linux","arch":"amd64","full":{"url":"https://example.com","sha256":"aa"}}]}`)

	mux := http.NewServeMux()
	mux.HandleFunc("/stable/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write(manifest)
	})
	mux.HandleFunc("/stable/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("invalid"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if _, _, err := FetchManifest(context.Background(), srv.Client(), srv.URL, ChannelStable); err == nil {
		t.Fatalf("expected signature error")
	}
}
