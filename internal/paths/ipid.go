package paths

import (
	"github.com/alxweis/ipid-measure/internal/dirs"
	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/root"
	"github.com/alxweis/ipid-measure/internal/types"
	"path/filepath"
	"strings"
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
				ConfigSnapshotPath:  filepath.Join(path, files.IPIDConfigSnapshotFile),
				LogFilePath:         filepath.Join(path, files.IPIDLogFile),
			},
			ZMapLinkPath: filepath.Join(path, files.ZMapLink),
		},
	}
}

func NewInterProtocolMeasurement(protocols []types.Payload, timestamp time.Time) *IPIDMeasurement {
	names := make([]string, len(protocols))
	for index, protocol := range protocols {
		names[index] = strings.ReplaceAll(string(protocol), "-dns", "")
	}
	id := "interprotocol-" + strings.Join(names, "-") + "_" + timestamp.Format(TimestampFormat)
	path := filepath.Join(root.Root, dirs.IPIDDir, dirs.RawDir, id)
	return &IPIDMeasurement{
		ZMapLinkedMeasurement: ZMapLinkedMeasurement{
			Measurement: Measurement{
				ID: id, Path: path,
				MeasurementFilePath: filepath.Join(path, files.InterProtocolMeasurementFile),
				ConfigSnapshotPath:  filepath.Join(path, files.InterProtocolConfigSnapshotFile),
				LogFilePath:         filepath.Join(path, files.IPIDLogFile),
			},
			ZMapLinkPath: filepath.Join(path, files.InterProtocolTargetLink),
		},
	}
}
