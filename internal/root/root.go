package root

import (
	"fmt"
	"os"
	"path/filepath"
)

var Root = MustResolveProjectRoot(workspace())

func workspace() string {
	if value := os.Getenv("IPID_MEASURE_WORKSPACE"); value != "" {
		return value
	}
	return "."
}

func MustResolveProjectRoot(path string) string {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		panic(fmt.Errorf("resolve project root: %w", err))
	}

	return absolutePath
}
