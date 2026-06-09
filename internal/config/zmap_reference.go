package config

import (
	"github.com/alxweis/ipid-measure/internal/dirs"
	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/root"
	"github.com/alxweis/ipid-measure/internal/types"
	"path/filepath"
	"time"
)

type ZMapReference struct {
	ZMapID string `yaml:"zmap"`

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

	path := filepath.Join(root.Root, dirs.ZMapDir, dirs.RawDir, r.ZMapID)
	r.ZMapFilePath = filepath.Join(path, files.ZMapMeasurementFile)

	return nil
}
