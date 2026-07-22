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
	// Keep the historical 0644 rather than tightening to 0600. MkdirAll above
	// sets 0700 only on a dir it creates; it leaves an existing dir's perms
	// untouched, so in a pre-existing shared dir the file mode still matters —
	// and the tunnel and app processes' on-disk sharing model is OS-specific.
	// Tightening needs per-OS validation first.
	return os.WriteFile(path, data, 0o644)
}
