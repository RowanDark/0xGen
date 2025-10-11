package updater

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	update "github.com/inconshreveable/go-update"
)

// Client orchestrates manifest fetching, artifact validation, and binary swaps
// for glyphctl self-updates.
type Client struct {
	Store          *Store
	HTTPClient     *http.Client
	BaseURL        string
	ExecPath       string
	CurrentVersion string
	Out            io.Writer
}

// UpdateOptions controls how an update should be performed.
type UpdateOptions struct {
	Channel        string
	PersistChannel bool
}

// RollbackOptions controls how a rollback should behave.
type RollbackOptions struct {
	ForceStable bool
}

// Update downloads the manifest for opts.Channel and attempts to update the
// glyphctl binary in-place. When PersistChannel is true the channel preference
// in the config file is updated to match the effective channel.
func (c *Client) Update(ctx context.Context, opts UpdateOptions) error {
	if c.Store == nil {
		return errors.New("nil config store")
	}
	if c.Out == nil {
		c.Out = io.Discard
	}
	channel, err := NormalizeChannel(opts.Channel)
	if err != nil {
		return err
	}
	cfg, err := c.Store.Load()
	if err != nil {
		return err
	}

	manifest, _, err := FetchManifest(ctx, c.httpClient(), c.BaseURL, channel)
	if err != nil {
		return err
	}

	runtimeVersion := strings.TrimSpace(c.CurrentVersion)
	if runtimeVersion == "" {
		runtimeVersion = "dev"
	}

	if manifest.Version == runtimeVersion || strings.TrimSpace(cfg.LastAppliedVersion) == manifest.Version {
		fmt.Fprintf(c.Out, "glyphctl %s is already the newest build on the %s channel\n", runtimeVersion, channel)
		if opts.PersistChannel {
			cfg.Channel = channel
			if err := c.Store.Save(cfg); err != nil {
				return err
			}
		}
		return nil
	}

	build, ok := manifest.BuildFor(runtime.GOOS, runtime.GOARCH)
	if !ok {
		return fmt.Errorf("no build available for %s/%s in manifest", runtime.GOOS, runtime.GOARCH)
	}

	checksum, err := DecodeHex(build.Full.SHA256)
	if err != nil {
		return fmt.Errorf("decode full checksum: %w", err)
	}

	execPath, err := c.resolveExecPath()
	if err != nil {
		return err
	}

	info, err := os.Stat(execPath)
	if err != nil {
		return fmt.Errorf("stat executable: %w", err)
	}

	backupPath := filepath.Join(c.Store.Dir(), "glyphctl.previous")
	if err := os.MkdirAll(c.Store.Dir(), 0o755); err != nil {
		return fmt.Errorf("prepare backup dir: %w", err)
	}

	baseOpts := update.Options{
		TargetPath:  execPath,
		TargetMode:  info.Mode(),
		Checksum:    checksum,
		OldSavePath: backupPath,
		Hash:        cryptoHash(),
	}

	if err := baseOpts.CheckPermissions(); err != nil {
		return fmt.Errorf("insufficient permissions to update %s: %w", execPath, err)
	}

	appliedVersion := manifest.Version
	var applyErr error
	if build.Delta != nil && matchesCurrentVersion(build.Delta.FromVersion, runtimeVersion, cfg.LastAppliedVersion) {
		applyErr = c.applyDelta(ctx, build, baseOpts)
		if applyErr != nil {
			fmt.Fprintf(c.Out, "delta update failed (%v); falling back to full download\n", applyErr)
		}
	}
	if applyErr != nil || build.Delta == nil {
		applyErr = c.applyFull(ctx, build, baseOpts)
	}
	if applyErr != nil {
		// If the update failed and the stored channel points at beta switch back
		// to stable so unattended jobs become safer.
		if cfg.Channel == ChannelBeta {
			cfg.Channel = ChannelStable
			_ = c.Store.Save(cfg)
		}
		return applyErr
	}

	cfg.PreviousVersion = runtimeVersion
	cfg.LastAppliedVersion = appliedVersion
	cfg.BackupPath = backupPath
	cfg.LastAppliedAt = time.Now().UTC()
	if opts.PersistChannel {
		cfg.Channel = channel
	}
	if err := c.Store.Save(cfg); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "updated glyphctl to %s on the %s channel\n", appliedVersion, channel)
	return nil
}

func (c *Client) applyDelta(ctx context.Context, build Build, opts update.Options) error {
	patchData, err := c.download(ctx, build.Delta.URL)
	if err != nil {
		return fmt.Errorf("download delta: %w", err)
	}
	expected, err := DecodeHex(build.Delta.SHA256)
	if err != nil {
		return fmt.Errorf("decode delta checksum: %w", err)
	}
	actual := sha256.Sum256(patchData)
	if !bytes.Equal(actual[:], expected) {
		return fmt.Errorf("delta checksum mismatch: got %x want %x", actual, expected)
	}
	opts.Patcher = update.NewBSDiffPatcher()
	if err := update.Apply(bytes.NewReader(patchData), opts); err != nil {
		if rerr := update.RollbackError(err); rerr != nil {
			return fmt.Errorf("apply delta update: %v (rollback failed: %v)", err, rerr)
		}
		return fmt.Errorf("apply delta update: %w", err)
	}
	return nil
}

func (c *Client) applyFull(ctx context.Context, build Build, opts update.Options) error {
	data, err := c.download(ctx, build.Full.URL)
	if err != nil {
		return fmt.Errorf("download full artifact: %w", err)
	}
	if err := update.Apply(bytes.NewReader(data), opts); err != nil {
		if rerr := update.RollbackError(err); rerr != nil {
			return fmt.Errorf("apply update: %v (rollback failed: %v)", err, rerr)
		}
		return fmt.Errorf("apply update: %w", err)
	}
	return nil
}

// Rollback restores the previous glyphctl binary if one is available.
func (c *Client) Rollback(ctx context.Context, opts RollbackOptions) error {
	if c.Store == nil {
		return errors.New("nil config store")
	}
	if c.Out == nil {
		c.Out = io.Discard
	}
	cfg, err := c.Store.Load()
	if err != nil {
		return err
	}
	if cfg.BackupPath == "" {
		return errors.New("no rollback backup recorded")
	}
	backup, err := os.ReadFile(cfg.BackupPath)
	if err != nil {
		return fmt.Errorf("read backup binary: %w", err)
	}
	execPath, err := c.resolveExecPath()
	if err != nil {
		return err
	}
	info, err := os.Stat(execPath)
	if err != nil {
		return fmt.Errorf("stat executable: %w", err)
	}
	optsUpdate := update.Options{
		TargetPath:  execPath,
		TargetMode:  info.Mode(),
		OldSavePath: cfg.BackupPath,
		Checksum:    sha256Sum(backup),
		Hash:        cryptoHash(),
	}
	if err := update.Apply(bytes.NewReader(backup), optsUpdate); err != nil {
		if rerr := update.RollbackError(err); rerr != nil {
			return fmt.Errorf("rollback failed: %v (rollback error: %v)", err, rerr)
		}
		return fmt.Errorf("rollback failed: %w", err)
	}
	cfg.LastAppliedAt = time.Now().UTC()
	cfg.LastAppliedVersion, cfg.PreviousVersion = cfg.PreviousVersion, cfg.LastAppliedVersion
	if opts.ForceStable {
		cfg.Channel = ChannelStable
	}
	if err := c.Store.Save(cfg); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "rolled back glyphctl to %s\n", cfg.LastAppliedVersion)
	return nil
}

func (c *Client) resolveExecPath() (string, error) {
	if strings.TrimSpace(c.ExecPath) != "" {
		return c.ExecPath, nil
	}
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("determine executable path: %w", err)
	}
	return path, nil
}

func (c *Client) download(ctx context.Context, targetURL string) ([]byte, error) {
	client := c.httpClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("construct request: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent())
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", targetURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return nil, fmt.Errorf("download %s: unexpected status %d: %s", targetURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	buf := &bytes.Buffer{}
	if _, err := io.Copy(buf, resp.Body); err != nil {
		return nil, fmt.Errorf("read %s: %w", targetURL, err)
	}
	return buf.Bytes(), nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) userAgent() string {
	version := strings.TrimSpace(c.CurrentVersion)
	if version == "" {
		version = "dev"
	}
	return fmt.Sprintf("glyphctl/%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)
}

func matchesCurrentVersion(from string, current string, lastApplied string) bool {
	from = strings.TrimSpace(from)
	if from == "" {
		return false
	}
	current = strings.TrimSpace(current)
	lastApplied = strings.TrimSpace(lastApplied)
	if current != "" && current == from {
		return true
	}
	if lastApplied != "" && lastApplied == from {
		return true
	}
	return false
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func cryptoHash() crypto.Hash {
	return crypto.SHA256
}
