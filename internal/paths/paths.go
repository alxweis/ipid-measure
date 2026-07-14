package paths

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Measurement struct {
	ID                  string
	Path                string
	MeasurementFilePath string
	ConfigSnapshotPath  string
	LogFilePath         string
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

func (p *Measurement) CreateConfigSnapshot(config any) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal effective config: %w", err)
	}

	if err := os.WriteFile(p.ConfigSnapshotPath, data, 0644); err != nil {
		return fmt.Errorf("write config snapshot: %w", err)
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
