package files

import (
	"github.com/netd-tud/ipid-measure/internal/dirs"
	"github.com/netd-tud/ipid-measure/internal/root"
	"path/filepath"
)

const (
	ParquetExtension        = ".pq"
	ConfigExtension         = ".yaml"
	ConfigSnapshotExtension = ".snapshot" + ConfigExtension
	MetadataExtension       = ".json"
)

const (
	ZMapMeasurementFile = "zmap" + ParquetExtension
	OSMeasurementFile   = "os" + ParquetExtension
	IPIDMeasurementFile = "ipid" + ParquetExtension

	ZMapConfigFile = "zmap" + ConfigExtension
	OSConfigFile   = "os" + ConfigExtension
	IPIDConfigFile = "ipid" + ConfigExtension

	ZMapConfigSnapshotFile = "zmap" + ConfigSnapshotExtension
	OSConfigSnapshotFile   = "os" + ConfigSnapshotExtension
	IPIDConfigSnapshotFile = "ipid" + ConfigSnapshotExtension

	ZMapMetadataFile = "zmap" + MetadataExtension
	OSMetadataFile   = "os" + MetadataExtension
	IPIDMetadataFile = "ipid" + MetadataExtension

	ZMapLink = "zmap"
)

var (
	IPIDConfigFilePath = filepath.Join(root.Root, dirs.ConfigDir, IPIDConfigFile)
	OSConfigFilePath   = filepath.Join(root.Root, dirs.ConfigDir, OSConfigFile)
	ZMapConfigFilePath = filepath.Join(root.Root, dirs.ConfigDir, ZMapConfigFile)
)
