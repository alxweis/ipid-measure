package config

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/alxweis/ipid-measure/internal/dirs"
	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/root"
	"github.com/alxweis/ipid-measure/internal/types"
)

type ZMapReference struct {
	ZMapID     string `yaml:"zmap"`
	TargetFile string `yaml:"target_file,omitempty"`

	ZMapPayload   types.Payload `yaml:"-"`
	ZMapPort      *uint16       `yaml:"-"`
	ZMapTimestamp time.Time     `yaml:"-"`
	ZMapFilePath  string        `yaml:"-"`
}

func (r *ZMapReference) ValidateAndParseZMap() error {
	payload, port, timestamp, err := paths.ParseMeasurementID(r.ZMapID)
	if err != nil {
		return err
	}

	r.ZMapPayload = payload
	r.ZMapPort = port
	r.ZMapTimestamp = timestamp

	if r.TargetFile == "" {
		path := filepath.Join(root.Root, dirs.ZMapDir, dirs.RawDir, r.ZMapID)
		r.ZMapFilePath = filepath.Join(path, files.ZMapMeasurementFile)
		return nil
	}

	targetFile, err := filepath.Abs(r.TargetFile)
	if err != nil {
		return fmt.Errorf("resolve target_file: %w", err)
	}
	if err := files.IsFile(targetFile, "target_file", "*.pq"); err != nil {
		return err
	}
	r.TargetFile = targetFile
	r.ZMapFilePath = targetFile

	return nil
}
