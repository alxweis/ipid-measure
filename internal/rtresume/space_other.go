//go:build !linux

package rtresume

import "fmt"

func CheckSpace(string, *Plan) error { return fmt.Errorf("legacy RT recovery is Linux-only") }
