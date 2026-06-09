package files

import (
	"fmt"
	"github.com/alxweis/ipid-measure/internal/dirs"
	"github.com/alxweis/ipid-measure/internal/root"
	"os"
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

func IsFile(path, field string, patterns ...string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s: file does not exist: %s", field, path)
		}
		return fmt.Errorf("%s: cannot stat %s: %w", field, path, err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file: %s", field, path)
	}

	// No patterns specified -> require executable file.
	if len(patterns) == 0 {
		if info.Mode().Perm()&0111 == 0 {
			return fmt.Errorf("%s: file is not executable: %s", field, path)
		}
		return nil
	}

	filename := filepath.Base(path)

	for _, pattern := range patterns {
		match, err := filepath.Match(pattern, filename)
		if err != nil {
			return fmt.Errorf(
				"%s: invalid file pattern %q: %w",
				field,
				pattern,
				err,
			)
		}

		if match {
			return nil
		}
	}

	return fmt.Errorf(
		"%s: file %q does not match any allowed pattern %v",
		field,
		filename,
		patterns,
	)
}
