package runner

import (
	"fmt"
	"io"
	"os"
)

func copyExecutable(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source %q: %w", src, err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("create destination %q: %w", dst, err)
	}
	defer func() {
		_ = out.Close()
	}()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy %q to %q: %w", src, dst, err)
	}

	if err := out.Close(); err != nil {
		return fmt.Errorf("finalize %q: %w", dst, err)
	}

	if err := os.Chmod(dst, perm); err != nil {
		return fmt.Errorf("set permissions on %q: %w", dst, err)
	}
	return nil
}
