package domainfront

import (
	"os"
	"path/filepath"
)

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return data, err
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// Owner-only: the cached fronting config and fronts both reveal circumvention
	// infrastructure (domains/IPs), which shouldn't be world-readable to other
	// local users on shared devices. The parent dir is already 0o700.
	return os.WriteFile(path, data, 0o600)
}
