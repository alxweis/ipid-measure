package upload

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alxweis/ipid-measure/internal/paths"
)

func TestCompletionBindsRTResumeProvenance(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"ipid.pq", "ipid.snapshot.yaml", "resume-evidence.json"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	path, err := WriteCompletion(paths.Measurement{ID: "icmp_resumed", Path: directory})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var marker struct {
		Files map[string]FileEvidence `json:"files"`
	}
	if err := json.Unmarshal(data, &marker); err != nil {
		t.Fatal(err)
	}
	actual, err := Evidence(filepath.Join(directory, "resume-evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	if marker.Files["resume-evidence.json"] != actual {
		t.Fatal("resume provenance is not bound by the raw completion marker")
	}
}
