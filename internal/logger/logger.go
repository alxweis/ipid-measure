package logger

import (
	"fmt"
	"io"
	"log"
	"os"
)

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
