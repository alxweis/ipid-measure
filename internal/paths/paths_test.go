package paths

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestCreateConfigSnapshotWritesEffectiveConfig(t *testing.T) {
	type testConfig struct {
		Value    string        `yaml:"value"`
		Interval time.Duration `yaml:"interval"`
	}

	path := filepath.Join(t.TempDir(), "config.snapshot.yaml")
	measurement := Measurement{ConfigSnapshotPath: path}
	effective := testConfig{Value: "command-line-override", Interval: 20 * time.Millisecond}

	if err := measurement.CreateConfigSnapshot(&effective); err != nil {
		t.Fatalf("CreateConfigSnapshot() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var got testConfig
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got != effective {
		t.Fatalf("snapshot = %#v, want %#v", got, effective)
	}
}
