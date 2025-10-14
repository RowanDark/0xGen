package replay

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/RowanDark/0xgen/internal/observability/tracing"
)

// isWithinBase reports whether the target path resides within the base directory.
func isWithinBase(base, target string) (bool, error) {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return false, err
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(absBase, absTarget)
	if err != nil {
		return false, err
	}
	if rel == "." {
		return true, nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false, nil
	}
	return true, nil
}

const (
	manifestName = "manifest.json"
	filesDir     = "files"
)

// CreateArtifact writes the replay manifest and referenced files to a gzipped tarball.
func CreateArtifact(path string, manifest Manifest, files map[string][]byte) error {
	return CreateArtifactWithContext(context.Background(), path, manifest, files)
}

// CreateArtifactWithContext writes the replay manifest and referenced files to a gzipped tarball using the provided context for tracing.
func CreateArtifactWithContext(ctx context.Context, path string, manifest Manifest, files map[string][]byte) error {
	attrs := map[string]any{
		"glyph.replay.artifact_path": strings.TrimSpace(path),
		"glyph.replay.file_count":    len(files),
	}
	_, span := tracing.StartSpan(ctx, "replay.create_artifact", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(attrs))
	status := tracing.StatusOK
	statusMsg := ""
	record := func(err error, msg string) error {
		if span != nil && err != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = msg
		return err
	}
	defer func() {
		if span != nil {
			span.EndWithStatus(status, statusMsg)
		}
	}()

	if strings.TrimSpace(path) == "" {
		return record(errors.New("artefact path is required"), "missing artifact path")
	}
	if manifest.Version == "" {
		manifest.Version = ManifestVersion
	}
	if manifest.Runner.GlyphctlVersion == "" && manifest.Runner.GlyphdVersion == "" {
		manifest.Runner = DefaultRunnerInfo()
	}
	var err error
	manifest.FindingsFile, err = normalizeFileRef(manifest.FindingsFile)
	if err != nil {
		return record(err, "normalise findings file")
	}
	manifest.CasesFile, err = normalizeFileRef(manifest.CasesFile)
	if err != nil {
		return record(err, "normalise cases file")
	}
	if strings.TrimSpace(manifest.FlowsFile) != "" {
		manifest.FlowsFile, err = normalizeFileRef(manifest.FlowsFile)
		if err != nil {
			return record(err, "normalise flows file")
		}
	}
	for i := range manifest.Responses {
		if manifest.Responses[i].BodyFile == "" {
			continue
		}
		manifest.Responses[i].BodyFile, err = normalizeFileRef(manifest.Responses[i].BodyFile)
		if err != nil {
			return record(fmt.Errorf("normalise response[%d] body file: %w", i, err), "normalise response file")
		}
	}
	for i := range manifest.Robots {
		if manifest.Robots[i].BodyFile == "" {
			continue
		}
		manifest.Robots[i].BodyFile, err = normalizeFileRef(manifest.Robots[i].BodyFile)
		if err != nil {
			return record(fmt.Errorf("normalise robots[%d] body file: %w", i, err), "normalise robots file")
		}
	}
	manifest.Normalize()

	if err := manifest.Validate(); err != nil {
		return record(err, "validate manifest")
	}

	findingsKey := strings.TrimPrefix(manifest.FindingsFile, filesDir+"/")
	if _, ok := files[findingsKey]; !ok {
		return record(fmt.Errorf("findings_file %q not provided", findingsKey), "missing findings file")
	}
	casesKey := strings.TrimPrefix(manifest.CasesFile, filesDir+"/")
	if _, ok := files[casesKey]; !ok {
		return record(fmt.Errorf("cases_file %q not provided", casesKey), "missing cases file")
	}
	if strings.TrimSpace(manifest.FlowsFile) != "" {
		key := strings.TrimPrefix(manifest.FlowsFile, filesDir+"/")
		if _, ok := files[key]; !ok {
			return record(fmt.Errorf("flows file %q not provided", key), "missing flows file")
		}
	}
	for _, resp := range manifest.Responses {
		if resp.BodyFile == "" {
			continue
		}
		key := strings.TrimPrefix(resp.BodyFile, filesDir+"/")
		if _, ok := files[key]; !ok {
			return record(fmt.Errorf("response body file %q not provided", key), "missing response body")
		}
	}
	for _, rob := range manifest.Robots {
		if rob.BodyFile == "" {
			continue
		}
		key := strings.TrimPrefix(rob.BodyFile, filesDir+"/")
		if _, ok := files[key]; !ok {
			return record(fmt.Errorf("robots body file %q not provided", key), "missing robots body")
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return record(fmt.Errorf("create artefact directory: %w", err), "create artifact directory")
	}

	file, err := os.Create(path)
	if err != nil {
		return record(fmt.Errorf("create artefact: %w", err), "create artifact file")
	}
	defer func() {
		_ = file.Close()
	}()

	gz := gzip.NewWriter(file)
	defer func() {
		_ = gz.Close()
	}()

	tw := tar.NewWriter(gz)
	defer func() {
		_ = tw.Close()
	}()

	// Encode manifest with indentation for readability.
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return record(fmt.Errorf("encode manifest: %w", err), "encode manifest")
	}
	if err := writeTarFile(tw, manifestName, manifestData, 0o644); err != nil {
		return record(err, "write manifest")
	}

	for name, data := range files {
		clean := sanitizeFileName(name)
		if clean == "" {
			return record(fmt.Errorf("invalid file name %q", name), "sanitize file name")
		}
		fullPath := filepath.ToSlash(filepath.Join(filesDir, clean))
		if err := writeTarFile(tw, fullPath, data, 0o644); err != nil {
			return record(err, "write artifact file")
		}
	}
	return nil
}

// ExtractArtifact expands the artefact under the destination directory and returns the manifest.
func ExtractArtifact(path, dest string) (Manifest, error) {
	return ExtractArtifactWithContext(context.Background(), path, dest)
}

func ExtractArtifactWithContext(ctx context.Context, path, dest string) (Manifest, error) {
	var manifest Manifest
	if strings.TrimSpace(path) == "" {
		return manifest, errors.New("artefact path is required")
	}
	if strings.TrimSpace(dest) == "" {
		return manifest, errors.New("destination path is required")
	}
	attrs := map[string]any{
		"glyph.replay.artifact_path": strings.TrimSpace(path),
		"glyph.replay.extract_dest":  strings.TrimSpace(dest),
	}
	_, span := tracing.StartSpan(ctx, "replay.extract_artifact", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(attrs))
	status := tracing.StatusOK
	statusMsg := ""
	record := func(err error, msg string) (Manifest, error) {
		if span != nil && err != nil {
			span.RecordError(err)
		}
		status = tracing.StatusError
		statusMsg = msg
		return manifest, err
	}
	defer func() {
		if span != nil {
			span.EndWithStatus(status, statusMsg)
		}
	}()

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return record(fmt.Errorf("create destination: %w", err), "create destination")
	}

	file, err := os.Open(path)
	if err != nil {
		return record(fmt.Errorf("open artefact: %w", err), "open artifact")
	}
	defer func() {
		_ = file.Close()
	}()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return record(fmt.Errorf("open gzip reader: %w", err), "open gzip")
	}
	defer func() {
		_ = gz.Close()
	}()

	tr := tar.NewReader(gz)
	manifestSeen := false

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return record(fmt.Errorf("read tar entry: %w", err), "read tar entry")
		}

		name := filepath.Clean(hdr.Name)
		if strings.HasPrefix(name, "..") {
			return record(fmt.Errorf("invalid entry name %q", hdr.Name), "invalid entry name")
		}
		target := filepath.Join(dest, name)
		within, err := isWithinBase(dest, target)
		if err != nil {
			return record(fmt.Errorf("validate entry path for %q: %w", hdr.Name, err), "validate entry path")
		}
		if !within {
			return record(fmt.Errorf("entry %q would escape destination", hdr.Name), "entry escapes destination")
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return record(fmt.Errorf("create directory %s: %w", name, err), "create directory")
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return record(fmt.Errorf("create parent directory for %s: %w", name, err), "create parent directory")
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode))
			if err != nil {
				return record(fmt.Errorf("create file %s: %w", name, err), "create file")
			}
			if _, err := io.Copy(out, tr); err != nil {
				_ = out.Close()
				return record(fmt.Errorf("extract file %s: %w", name, err), "write file")
			}
			if err := out.Close(); err != nil {
				return record(fmt.Errorf("close file %s: %w", name, err), "close file")
			}
			if name == manifestName {
				manifestSeen = true
				data, err := os.ReadFile(target)
				if err != nil {
					return record(fmt.Errorf("read manifest: %w", err), "read manifest")
				}
				if err := json.Unmarshal(data, &manifest); err != nil {
					return record(fmt.Errorf("decode manifest: %w", err), "decode manifest")
				}
			}
		default:
			// Skip unsupported entries to avoid breaking on extraneous metadata.
		}
	}

	if !manifestSeen {
		return record(errors.New("manifest not found in artefact"), "missing manifest")
	}
	return manifest, nil
}

func writeTarFile(tw *tar.Writer, name string, data []byte, mode int64) error {
	hdr := &tar.Header{
		Name: name,
		Mode: mode,
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write tar header for %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("write tar payload for %s: %w", name, err)
	}
	return nil
}

func sanitizeFileName(name string) string {
	clean := filepath.Clean(name)
	clean = strings.TrimPrefix(clean, string(filepath.Separator))
	if clean == "." || strings.HasPrefix(clean, "..") {
		return ""
	}
	return clean
}

func normalizeFileRef(ref string) (string, error) {
	clean := sanitizeFileName(ref)
	if clean == "" {
		return "", fmt.Errorf("invalid file reference %q", ref)
	}
	return filepath.ToSlash(filepath.Join(filesDir, clean)), nil
}
