package paths

import (
	"github.com/alxweis/ipid-measure/internal/dirs"
	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/root"
	"github.com/alxweis/ipid-measure/internal/types"
	"path/filepath"
	"time"
)

func NewZMapMeasurement(payload types.Payload, port *uint16, timestamp time.Time) *ZMapMeasurement {
	id := GetMeasurementID(payload, port, timestamp)
	path := filepath.Join(root.Root, dirs.ZMapDir, dirs.RawDir, id)

	return &ZMapMeasurement{
		Measurement{
			ID:                  id,
			Path:                path,
			MeasurementFilePath: filepath.Join(path, files.ZMapMeasurementFile),
			MetadataFilePath:    filepath.Join(path, files.ZMapMetadataFile),
			ConfigSnapshotPath:  filepath.Join(path, files.ZMapConfigSnapshotFile),
			LogFilePath:         filepath.Join(path, files.ZMapLogFile),
		},
	}
}
