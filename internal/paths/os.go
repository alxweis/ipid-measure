package paths

import (
	"github.com/alxweis/ipid-measure/internal/dirs"
	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/root"
	"github.com/alxweis/ipid-measure/internal/types"
	"path/filepath"
	"time"
)

func NewOSMeasurement(payload types.Payload, port *uint16, timestamp time.Time) *OSMeasurement {
	id := GetMeasurementID(payload, port, timestamp)
	path := filepath.Join(root.Root, dirs.OSDir, dirs.RawDir, id)

	return &OSMeasurement{
		ZMapLinkedMeasurement{
			Measurement: Measurement{
				ID:                  id,
				Path:                path,
				MeasurementFilePath: filepath.Join(path, files.OSMeasurementFile),
				MetadataFilePath:    filepath.Join(path, files.OSMetadataFile),
				ConfigSnapshotPath:  filepath.Join(path, files.OSConfigSnapshotFile),
				LogFilePath:         filepath.Join(path, files.OSLogFile),
			},
			ZMapLinkPath: filepath.Join(path, files.ZMapLink),
		},
	}
}
