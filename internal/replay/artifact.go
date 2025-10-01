package replay

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	manifestName = "manifest.json"
	filesDir     = "files"
)

// CreateArtifact writes the replay manifest and referenced files to a gzipped tarball.
func CreateArtifact(path string, manifest Manifest, files map[string][]byte) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("artefact path is required")
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
		return err
	}
	manifest.CasesFile, err = normalizeFileRef(manifest.CasesFile)
	if err != nil {
		return err
	}
	for i := range manifest.Responses {
		if manifest.Responses[i].BodyFile == "" {
			continue
		}
		manifest.Responses[i].BodyFile, err = normalizeFileRef(manifest.Responses[i].BodyFile)
		if err != nil {
			return fmt.Errorf("normalise response[%d] body file: %w", i, err)
		}
	}
	for i := range manifest.Robots {
		if manifest.Robots[i].BodyFile == "" {
			continue
		}
		manifest.Robots[i].BodyFile, err = normalizeFileRef(manifest.Robots[i].BodyFile)
		if err != nil {
			return fmt.Errorf("normalise robots[%d] body file: %w", i, err)
		}
	}
	if err := manifest.Validate(); err != nil {
		return err
	}

	findingsKey := strings.TrimPrefix(manifest.FindingsFile, filesDir+"/")
	if _, ok := files[findingsKey]; !ok {
		return fmt.Errorf("findings_file %q not provided", findingsKey)
	}
	casesKey := strings.TrimPrefix(manifest.CasesFile, filesDir+"/")
	if _, ok := files[casesKey]; !ok {
		return fmt.Errorf("cases_file %q not provided", casesKey)
	}
	for _, resp := range manifest.Responses {
		if resp.BodyFile == "" {
			continue
		}
		key := strings.TrimPrefix(resp.BodyFile, filesDir+"/")
		if _, ok := files[key]; !ok {
			return fmt.Errorf("response body file %q not provided", key)
		}
	}
	for _, rob := range manifest.Robots {
		if rob.BodyFile == "" {
			continue
		}
		key := strings.TrimPrefix(rob.BodyFile, filesDir+"/")
		if _, ok := files[key]; !ok {
			return fmt.Errorf("robots body file %q not provided", key)
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create artefact directory: %w", err)
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create artefact: %w", err)
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
		return fmt.Errorf("encode manifest: %w", err)
	}
	if err := writeTarFile(tw, manifestName, manifestData, 0o644); err != nil {
		return err
	}

	for name, data := range files {
		clean := sanitizeFileName(name)
		if clean == "" {
			return fmt.Errorf("invalid file name %q", name)
		}
		fullPath := filepath.ToSlash(filepath.Join(filesDir, clean))
		if err := writeTarFile(tw, fullPath, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// ExtractArtifact expands the artefact under the destination directory and returns the manifest.
func ExtractArtifact(path, dest string) (Manifest, error) {
	var manifest Manifest
	if strings.TrimSpace(path) == "" {
		return manifest, errors.New("artefact path is required")
	}
	if strings.TrimSpace(dest) == "" {
		return manifest, errors.New("destination path is required")
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return manifest, fmt.Errorf("create destination: %w", err)
	}

	file, err := os.Open(path)
	if err != nil {
		return manifest, fmt.Errorf("open artefact: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return manifest, fmt.Errorf("open gzip reader: %w", err)
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
			return manifest, fmt.Errorf("read tar entry: %w", err)
		}

		name := filepath.Clean(hdr.Name)
		if strings.HasPrefix(name, "..") {
			return manifest, fmt.Errorf("invalid entry name %q", hdr.Name)
		}
		target := filepath.Join(dest, name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return manifest, fmt.Errorf("create directory %s: %w", name, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return manifest, fmt.Errorf("create parent directory for %s: %w", name, err)
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode))
			if err != nil {
				return manifest, fmt.Errorf("create file %s: %w", name, err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				_ = out.Close()
				return manifest, fmt.Errorf("extract file %s: %w", name, err)
			}
			if err := out.Close(); err != nil {
				return manifest, fmt.Errorf("close file %s: %w", name, err)
			}
			if name == manifestName {
				manifestSeen = true
				data, err := os.ReadFile(target)
				if err != nil {
					return manifest, fmt.Errorf("read manifest: %w", err)
				}
				if err := json.Unmarshal(data, &manifest); err != nil {
					return manifest, fmt.Errorf("decode manifest: %w", err)
				}
			}
		default:
			// Skip unsupported entries to avoid breaking on extraneous metadata.
		}
	}

	if !manifestSeen {
		return manifest, errors.New("manifest not found in artefact")
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
