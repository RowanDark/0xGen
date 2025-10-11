package wslpath

import (
	"fmt"
	"strings"
)

// ToWindows converts a WSL-style path (e.g. /mnt/c/Users) to a Windows path (e.g. C:\Users).
func ToWindows(path string) (string, error) {
	cleaned := strings.TrimSpace(path)
	if cleaned == "" {
		return "", fmt.Errorf("path must not be empty")
	}
	if !strings.HasPrefix(cleaned, "/mnt/") {
		return "", fmt.Errorf("not a recognised WSL path: %s", path)
	}

	remainder := cleaned[len("/mnt/"):len(cleaned)]
	segments := strings.SplitN(remainder, "/", 2)
	if len(segments) == 0 || len(segments[0]) == 0 {
		return "", fmt.Errorf("missing drive letter in WSL path: %s", path)
	}
	drive := segments[0]
	if len(drive) != 1 || drive[0] < 'a' || drive[0] > 'z' {
		return "", fmt.Errorf("invalid drive letter in WSL path: %s", path)
	}

	rest := ""
	if len(segments) == 2 {
		rest = segments[1]
	}
	rest = strings.ReplaceAll(rest, "/", "\\")
	if rest != "" {
		return fmt.Sprintf("%s:\\%s", strings.ToUpper(drive), rest), nil
	}
	return fmt.Sprintf("%s:", strings.ToUpper(drive)), nil
}

// ToWSL converts a Windows path (e.g. C:\\Users) to its WSL representation (/mnt/c/Users).
func ToWSL(path string) (string, error) {
	cleaned := strings.TrimSpace(path)
	if cleaned == "" {
		return "", fmt.Errorf("path must not be empty")
	}
	cleaned = strings.ReplaceAll(cleaned, "/", "\\")
	if len(cleaned) < 2 || cleaned[1] != ':' {
		return "", fmt.Errorf("not a recognised Windows drive path: %s", path)
	}

	drive := cleaned[0]
	if drive >= 'a' && drive <= 'z' {
		drive -= 32
	}
	if drive < 'A' || drive > 'Z' {
		return "", fmt.Errorf("invalid drive letter: %s", path)
	}

	remainder := ""
	if len(cleaned) > 2 {
		remainder = strings.TrimPrefix(cleaned[2:], "\\")
	}
	remainder = strings.ReplaceAll(remainder, "\\", "/")
	if remainder != "" {
		return fmt.Sprintf("/mnt/%s/%s", strings.ToLower(string(drive)), remainder), nil
	}
	return fmt.Sprintf("/mnt/%s", strings.ToLower(string(drive))), nil
}
