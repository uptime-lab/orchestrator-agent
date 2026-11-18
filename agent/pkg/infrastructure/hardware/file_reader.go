//go:build linux

package hardware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AllowedFilePaths is the list of allowed file paths (initially only config files)
var AllowedFilePaths = []string{
	"/boot/firmware/config.txt",
	"/boot/config.txt",
}

// FileReader handles reading and writing files
type FileReader struct{}

// NewFileReader creates a new file reader
func NewFileReader() *FileReader {
	return &FileReader{}
}

// ReadFile reads a file from the first available path in the allowed list
func (r *FileReader) ReadFile() (string, string, error) {
	for _, path := range AllowedFilePaths {
		content, err := os.ReadFile(path)
		if err == nil {
			return path, string(content), nil
		}
		// Continue to next path if file doesn't exist
		if os.IsNotExist(err) {
			continue
		}
		// Return error for other errors
		return "", "", fmt.Errorf("failed to read file at %s: %w", path, err)
	}

	return "", "", fmt.Errorf("file not found in any allowed path")
}

// ReadConfigFile reads the config file (edge case - checks config files first)
func (r *FileReader) ReadConfigFile() (string, string, error) {
	return r.ReadFile()
}

// GetFileHash calculates the SHA256 hash of file content
func (r *FileReader) GetFileHash(content string) string {
	hashBytes := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hashBytes[:])
}

// WriteFile writes content to the specified file path
func (r *FileReader) WriteFile(path, content string) error {
	// Validate path is in allowed list
	if !r.isAllowedPath(path) {
		return fmt.Errorf("path %s is not in allowed list", path)
	}

	// Write a fresh file beside it and rename, rather than truncating in place.
	//
	// The only paths this writes are the boot config on a FAT partition, and a
	// bare os.WriteFile truncates it first: a power cut in that window leaves a
	// ZERO-LENGTH config.txt and a board that does not boot. The verification
	// that follows this call cannot see it either — it re-reads through the page
	// cache and gets the content it just wrote, so the command settles green on
	// a device that is already lost. The sibling handler that edits the same file
	// (patch_file, through the anchored writer) was hardened for exactly this;
	// this path never was.
	//
	// A rename is a directory-entry update, so the file the firmware finds is
	// either the old content or the new one, never half of either.
	return writeFileDurable(path, []byte(content), 0o644)
}

// writeFileDurable writes content to path via a temp file in the same directory,
// fsyncs it, renames it into place and fsyncs the directory.
//
// The chmod is best-effort ON PURPOSE: the boot partition is vfat, where
// permissions are a mount option rather than a file attribute and fchmod can
// return EPERM. Failing the write there would trade a rare power-cut corruption
// for a certain refusal on the one filesystem this function exists to protect.
func writeFileDurable(path string, content []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".orchestrator-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create a temporary file next to %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		// vfat and friends: not fatal, see above.
		_ = err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to flush %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close the temporary file for %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to install %s: %w", path, err)
	}
	// Without this the rename itself can be lost on a power cut even though the
	// data was flushed, and these devices lose power.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// WriteConfigFile writes config file (edge case wrapper)
func (r *FileReader) WriteConfigFile(path, content string) error {
	return r.WriteFile(path, content)
}

// isAllowedPath checks if a path is in the allowed list
func (r *FileReader) isAllowedPath(path string) bool {
	for _, allowedPath := range AllowedFilePaths {
		if path == allowedPath {
			return true
		}
	}
	return false
}

// VerifyFileHash reads the file and verifies its hash matches the expected hash
func (r *FileReader) VerifyFileHash(path, expectedHash string) (bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("failed to read file for verification: %w", err)
	}

	actualHash := r.GetFileHash(string(content))
	return strings.EqualFold(actualHash, expectedHash), nil
}
