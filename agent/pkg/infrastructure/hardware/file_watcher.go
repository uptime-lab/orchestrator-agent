//go:build linux

package hardware

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// FileWatcher watches files for changes
type FileWatcher struct {
	watcher      *fsnotify.Watcher
	reader       *FileReader
	onChange     func(path, content, hash string) error
	logger       *slog.Logger
	watchedPaths map[string]bool
}

// NewFileWatcher creates a new file watcher
func NewFileWatcher(reader *FileReader, onChange func(path, content, hash string) error, logger *slog.Logger) (*FileWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	return &FileWatcher{
		watcher:      watcher,
		reader:       reader,
		onChange:     onChange,
		logger:       logger,
		watchedPaths: make(map[string]bool),
	}, nil
}

// Start starts watching files
func (w *FileWatcher) Start(ctx context.Context) error {
	// Watch file paths and their parent directories
	for _, path := range AllowedFilePaths {
		// Watch the file itself
		if err := w.watcher.Add(path); err != nil {
			// If file doesn't exist, watch the parent directory instead
			parentDir := filepath.Dir(path)
			if err := w.watcher.Add(parentDir); err != nil {
				w.logger.Warn("failed to watch file path", "path", path, "error", err)
				continue
			}
			w.logger.Info("watching parent directory for file", "path", path, "parent", parentDir)
		} else {
			w.watchedPaths[path] = true
			w.logger.Info("watching file", "path", path)
		}
	}

	// Start event loop
	go w.eventLoop(ctx)

	return nil
}

// eventLoop processes file system events
func (w *FileWatcher) eventLoop(ctx context.Context) {
	// Debounce timer to avoid multiple rapid events
	var debounceTimer *time.Timer
	debounceDelay := 500 * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("file watcher stopped")
			return

		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}

			// Only process write and create events for watched files
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				// Check if this is a file we care about
				if w.isWatchedFile(event.Name) {
					// Cancel previous debounce timer if it exists
					if debounceTimer != nil {
						debounceTimer.Stop()
					}

					// Set new debounce timer
					debounceTimer = time.AfterFunc(debounceDelay, func() {
						w.handleFileChange(event.Name)
					})
				}
			}

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			w.logger.Error("file watcher error", "error", err)
		}
	}
}

// isWatchedFile checks if a path is one of the allowed files
func (w *FileWatcher) isWatchedFile(path string) bool {
	for _, allowedPath := range AllowedFilePaths {
		if path == allowedPath {
			return true
		}
	}
	return false
}

// handleFileChange handles a file change event
func (w *FileWatcher) handleFileChange(path string) {
	w.logger.Info("file changed", "path", path)

	// Read the specific file that changed
	content, err := os.ReadFile(path)
	if err != nil {
		w.logger.Error("failed to read file after change", "path", path, "error", err)
		// File might have been created, try to watch it now
		if !w.watchedPaths[path] {
			if err := w.watcher.Add(path); err == nil {
				w.watchedPaths[path] = true
				w.logger.Info("started watching newly created file", "path", path)
			}
		}
		return
	}

	// Calculate hash
	hash := w.reader.GetFileHash(string(content))

	// Call onChange callback with the specific path that changed
	if w.onChange != nil {
		if err := w.onChange(path, string(content), hash); err != nil {
			w.logger.Error("onChange callback failed", "path", path, "error", err)
		}
	}
}

// Close closes the watcher
func (w *FileWatcher) Close() error {
	if w.watcher != nil {
		return w.watcher.Close()
	}
	return nil
}
