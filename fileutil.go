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
	// The parent dir is created 0700 (owner-only), which already gates access
	// regardless of file mode. Keep the historical 0644 rather than tightening
	// to 0600: the tunnel and app processes' on-disk sharing model is OS-specific
	// and tightening needs per-OS validation first.
	return os.WriteFile(path, data, 0o644)
}
