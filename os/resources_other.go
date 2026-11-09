//go:build !unix

package os

import "github.com/alxweis/ipid-measure/internal/config"

func validateProbeResources(c *config.OSConfig) error { return nil }
