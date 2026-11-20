package handlers

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeFileAtomic writes via a temp file and rename so a reader never observes a
// partially written file — a truncated authorized_keys or sudoers file is an
// access failure, not a cosmetic problem.
func writeFileAtomic(path string, content []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".orchestrator-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to chmod %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file for %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to install %s: %w", path, err)
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
