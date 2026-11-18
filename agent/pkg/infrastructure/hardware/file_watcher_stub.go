//go:build !linux

package hardware

import (
	"context"
	"log/slog"
)

// FileWatcher watches files for changes (stub for non-Linux)
type FileWatcher struct {
	logger *slog.Logger
}

// NewFileWatcher creates a new file watcher (stub for non-Linux)
func NewFileWatcher(reader *FileReader, onChange func(path, content, hash string) error, logger *slog.Logger) (*FileWatcher, error) {
	return &FileWatcher{
		logger: logger,
	}, nil
}

// Start starts watching files (stub - no-op on non-Linux)
func (w *FileWatcher) Start(ctx context.Context) error {
	w.logger.Info("file watcher not supported on this platform")
	return nil
}

// Close closes the watcher (stub - no-op on non-Linux)
func (w *FileWatcher) Close() error {
	return nil
}
