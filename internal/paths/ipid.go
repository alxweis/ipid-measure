package paths

import (
	"github.com/netd-tud/ipid-measure/internal/dirs"
	"github.com/netd-tud/ipid-measure/internal/files"
	"github.com/netd-tud/ipid-measure/internal/root"
	"github.com/netd-tud/ipid-measure/internal/types"
	"path/filepath"
	"time"
)

func NewIPIDMeasurement(payload types.Payload, port *uint16, timestamp time.Time) *IPIDMeasurement {
	id := GetMeasurementID(payload, port, timestamp)
	path := filepath.Join(root.Root, dirs.IPIDDir, dirs.RawDir, id)

	return &IPIDMeasurement{
		ZMapLinkedMeasurement{
			Measurement: Measurement{
				ID:                  id,
				Path:                path,
				MeasurementFilePath: filepath.Join(path, files.IPIDMeasurementFile),
				MetadataFilePath:    filepath.Join(path, files.IPIDMetadataFile),
				ConfigSnapshotPath:  filepath.Join(path, files.IPIDConfigSnapshotFile),
			},
			ZMapLinkPath: filepath.Join(path, files.ZMapLink),
		},
	}
}
