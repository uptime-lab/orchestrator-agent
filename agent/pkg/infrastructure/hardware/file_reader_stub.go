//go:build !linux

package hardware

import (
	"fmt"
)

// FileReader handles reading and writing files (stub for non-Linux)
type FileReader struct{}

// NewFileReader creates a new file reader (stub for non-Linux)
func NewFileReader() *FileReader {
	return &FileReader{}
}

// ReadFile reads a file (stub - returns error on non-Linux)
func (r *FileReader) ReadFile() (string, string, error) {
	return "", "", fmt.Errorf("file reading not supported on this platform")
}

// ReadConfigFile reads the config file (edge case wrapper - stub for non-Linux)
func (r *FileReader) ReadConfigFile() (string, string, error) {
	return r.ReadFile()
}

// GetFileHash calculates the SHA256 hash of file content (stub)
func (r *FileReader) GetFileHash(content string) string {
	return ""
}

// WriteFile writes content to the specified file path (stub - returns error on non-Linux)
func (r *FileReader) WriteFile(path, content string) error {
	return fmt.Errorf("file writing not supported on this platform")
}

// WriteConfigFile writes config file (edge case wrapper - stub for non-Linux)
func (r *FileReader) WriteConfigFile(path, content string) error {
	return r.WriteFile(path, content)
}

// VerifyFileHash reads the file and verifies its hash matches (stub - returns error on non-Linux)
func (r *FileReader) VerifyFileHash(path, expectedHash string) (bool, error) {
	return false, fmt.Errorf("file verification not supported on this platform")
}
