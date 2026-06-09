package paths

import (
	"fmt"
	"io"
	"os"
)

type Measurement struct {
	ID                  string
	Path                string
	MeasurementFilePath string
	MetadataFilePath    string
	ConfigSnapshotPath  string
}

type ZMapLinkedMeasurement struct {
	Measurement
	ZMapLinkPath string
}

type ZMapMeasurement struct {
	Measurement
}

type OSMeasurement struct {
	ZMapLinkedMeasurement
}

type IPIDMeasurement struct {
	ZMapLinkedMeasurement
}

func (p *Measurement) CreateDirectory() error {
	if _, err := os.Stat(p.Path); err == nil {
		return fmt.Errorf("measurement directory already exists: %s", p.Path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat measurement directory: %w", err)
	}

	return os.MkdirAll(p.Path, 0755)
}

func (p *Measurement) CreateConfigSnapshot(configFilePath string) error {
	srcInfo, err := os.Stat(configFilePath)
	if err != nil {
		return fmt.Errorf("stat config source: %w", err)
	}

	src, err := os.Open(configFilePath)
	if err != nil {
		return fmt.Errorf("open config source: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(
		p.ConfigSnapshotPath,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		srcInfo.Mode(),
	)
	if err != nil {
		return fmt.Errorf("create config snapshot: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy config snapshot: %w", err)
	}

	return nil
}

func (p *ZMapLinkedMeasurement) CreateZMapLink(zmapFilePath string) error {
	_ = os.Remove(p.ZMapLinkPath)

	if err := os.Symlink(zmapFilePath, p.ZMapLinkPath); err != nil {
		return fmt.Errorf("create zmap symlink: %w", err)
	}

	return nil
}
