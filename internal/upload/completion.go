package upload

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/alxweis/ipid-measure/internal/paths"
)

type FileEvidence struct {
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
}

func Evidence(path string) (FileEvidence, error) {
	f, err := os.Open(path)
	if err != nil {
		return FileEvidence{}, err
	}
	defer f.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, f)
	return FileEvidence{size, hex.EncodeToString(digest.Sum(nil))}, err
}

// A scoped step may be adopted after a lost subprocess exit only after every
// raw data/snapshot upload has completed. Logs remain mutable and are excluded.
func completeScoped(destination string, m paths.Measurement) error {
	if os.Getenv("IPID_MEASURE_WORKSPACE") == "" {
		return nil
	}
	path, err := WriteCompletion(m)
	if err != nil {
		return err
	}
	command := exec.Command("s3cmd", "put", "--no-progress", path, strings.TrimRight(destination, "/")+"/"+m.ID+"/measurement-complete.json")
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

// WriteCompletion commits closed local OS files before the parent's upload.
// The S3 copy of this marker is still published only after successful sync.
func WriteCompletion(m paths.Measurement) (string, error) {
	entries, err := os.ReadDir(m.Path)
	if err != nil {
		return "", err
	}
	files := map[string]FileEvidence{}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !(strings.HasSuffix(name, ".pq") || strings.HasSuffix(name, ".snapshot.yaml") || name == "os-coverage.json") {
			continue
		}
		value, err := Evidence(filepath.Join(m.Path, name))
		if err != nil {
			return "", err
		}
		files[name] = value
	}
	value := map[string]any{"version": 1, "measurement_id": m.ID, "files": files}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(m.Path, "measurement-complete.json")
	if err = os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		return "", err
	}
	return path, nil
}
