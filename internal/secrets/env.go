package secrets

import "strings"

const envPrefix = "GLYPH_SECRET_"

// FromEnv parses environment variables and returns a plugin -> secret map.
// Variables must follow the pattern GLYPH_SECRET_<PLUGIN>__<SECRET>=value.
func FromEnv(env []string) map[string]map[string]string {
	secrets := make(map[string]map[string]string)
	for _, entry := range env {
		if !strings.HasPrefix(entry, envPrefix) {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimPrefix(parts[0], envPrefix)
		value := parts[1]
		segments := strings.SplitN(key, "__", 2)
		if len(segments) != 2 {
			continue
		}
		plugin := normalise(strings.ReplaceAll(segments[0], "_", "-"))
		secret := normalise(segments[1])
		if plugin == "" || secret == "" || strings.TrimSpace(value) == "" {
			continue
		}
		if secrets[plugin] == nil {
			secrets[plugin] = make(map[string]string)
		}
		secrets[plugin][secret] = value
	}
	if len(secrets) == 0 {
		return nil
	}
	return secrets
}
