package env

import "os"

// Lookup returns the value of key if it exists in the environment.
func Lookup(key string) (string, bool) {
	return os.LookupEnv(key)
}
