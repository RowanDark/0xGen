package runner

import (
	"path/filepath"
	"runtime"
)

func executablePath(dir, base string) string {
	name := base
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(dir, name)
}
