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
	// 0644, not owner-only: on some platforms the tunnel and app run as separate
	// processes (potentially different users) that both read these caches, so the
	// file must stay cross-process readable. Hardening to 0600 would need per-OS
	// validation of that two-process model first.
	return os.WriteFile(path, data, 0o644)
}
