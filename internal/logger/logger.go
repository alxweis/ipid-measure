package logger

import (
	"fmt"
	"io"
	"log"
	"os"
)

// SetupFile redirects the standard logger to a tee that writes to both stderr
// and the given path. The returned closer flushes and closes the file; callers
// should defer it. If path is empty, this is a no-op and the returned closer
// does nothing.
func SetupFile(path string) (func(), error) {
	if path == "" {
		return func() {}, nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return func() {}, fmt.Errorf("open log file %s: %w", path, err)
	}

	log.SetOutput(io.MultiWriter(os.Stderr, f))

	return func() {
		_ = f.Sync()
		_ = f.Close()
	}, nil
}
