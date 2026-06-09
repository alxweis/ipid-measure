package root

import (
	"fmt"
	"path/filepath"
)

var Root = MustResolveProjectRoot(".")

func MustResolveProjectRoot(path string) string {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		panic(fmt.Errorf("resolve project root: %w", err))
	}

	return absolutePath
}
