package updater

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kr/binarydist"
)

type updateServer struct {
	server       *httptest.Server
	fullData     []byte
	deltaData    []byte
	manifestData []byte
	signature    []byte
	fullHits     int
	deltaHits    int
}

func newUpdateServer(t *testing.T, manifest Manifest, full []byte, delta []byte, sig []byte) *updateServer {
	t.Helper()
	us := &updateServer{fullData: full, deltaData: delta, manifestData: mustJSON(t, manifest), signature: sig}
	mux := http.NewServeMux()
	mux.HandleFunc("/"+manifest.Channel+"/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write(us.manifestData)
	})
	mux.HandleFunc("/"+manifest.Channel+"/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) {
		w.Write(us.signature)
	})
	mux.HandleFunc("/artifacts/full", func(w http.ResponseWriter, r *http.Request) {
		us.fullHits++
		w.Write(us.fullData)
	})
	mux.HandleFunc("/artifacts/delta", func(w http.ResponseWriter, r *http.Request) {
		us.deltaHits++
		w.Write(us.deltaData)
	})
	us.server = httptest.NewServer(mux)
	return us
}

func (s *updateServer) Close() { s.server.Close() }

func mustJSON(t *testing.T, manifest Manifest) []byte {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return data
}

func sign(t *testing.T, priv ed25519.PrivateKey, msg []byte) []byte {
	t.Helper()
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)))
}

func TestClientUpdateAndRollback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows self-update semantics require elevated permissions in tests")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	t.Setenv("GLYPH_UPDATER_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))

	oldVersion := "1.0.0"
	newVersion := "1.1.0"
	oldBinary := []byte("glyphctl " + oldVersion)
	newBinary := []byte("glyphctl " + newVersion)

	var deltaBuf bytes.Buffer
	if err := binarydist.Diff(bytes.NewReader(oldBinary), bytes.NewReader(newBinary), &deltaBuf); err != nil {
		t.Fatalf("Diff: %v", err)
	}

	cfgDir := t.TempDir()
	store, err := NewStore(cfgDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	execPath := filepath.Join(t.TempDir(), "glyphctl")
	if err := os.WriteFile(execPath, oldBinary, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	manifest := Manifest{
		Version: newVersion,
		Channel: ChannelStable,
		Builds: []Build{{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
			Full: Artifact{
				URL:    "", // placeholder updated below
				SHA256: fmt.Sprintf("%x", sha256Sum(newBinary)),
			},
			Delta: &Delta{
				FromVersion: oldVersion,
				URL:         "", // placeholder updated below
				SHA256:      fmt.Sprintf("%x", sha256Sum(deltaBuf.Bytes())),
			},
		}},
	}

	server := newUpdateServer(t, manifest, newBinary, deltaBuf.Bytes(), sign(t, priv, mustJSON(t, manifest)))
	defer server.Close()

	manifest.Builds[0].Full.URL = server.server.URL + "/artifacts/full"
	manifest.Builds[0].Delta.URL = server.server.URL + "/artifacts/delta"
	server.manifestData = mustJSON(t, manifest)
	server.signature = sign(t, priv, server.manifestData)

	client := &Client{
		Store:          store,
		BaseURL:        server.server.URL,
		ExecPath:       execPath,
		CurrentVersion: oldVersion,
		Out:            io.Discard,
	}

	if err := client.Update(context.Background(), UpdateOptions{Channel: ChannelStable, PersistChannel: true}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	updatedData, err := os.ReadFile(execPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(updatedData, newBinary) {
		t.Fatalf("update did not write new binary")
	}
	if server.deltaHits == 0 {
		t.Fatalf("expected delta endpoint to be fetched")
	}

	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("Load config: %v", err)
	}
	if cfg.LastAppliedVersion != newVersion {
		t.Fatalf("expected last applied %s, got %s", newVersion, cfg.LastAppliedVersion)
	}
	if cfg.PreviousVersion != oldVersion {
		t.Fatalf("expected previous version %s, got %s", oldVersion, cfg.PreviousVersion)
	}
	backupData, err := os.ReadFile(cfg.BackupPath)
	if err != nil {
		t.Fatalf("Read backup: %v", err)
	}
	if !bytes.Equal(backupData, oldBinary) {
		t.Fatalf("backup mismatch")
	}

	// Simulate running new binary for rollback.
	client.CurrentVersion = newVersion
	if err := client.Rollback(context.Background(), RollbackOptions{ForceStable: true}); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	rolledData, err := os.ReadFile(execPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(rolledData, oldBinary) {
		t.Fatalf("rollback did not restore previous binary")
	}
}
