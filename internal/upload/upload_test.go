package upload

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/paths"
)

// Execute a copy of this test binary as s3cmd, capturing the real subprocess
// arguments without invoking a shell, installed s3cmd, credentials or S3.
func TestMain(m *testing.M) {
	if path := os.Getenv("IPID_TEST_S3CMD_LOG"); path != "" {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}
		if err = json.NewEncoder(file).Encode(os.Args[1:]); err != nil {
			panic(err)
		}
		if err = file.Close(); err != nil {
			panic(err)
		}
		if os.Getenv("IPID_TEST_S3CMD_FAIL_SYNC") == "1" && len(os.Args) > 1 && os.Args[1] == "sync" {
			os.Exit(64)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeS3cmd(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	name := "s3cmd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err = os.WriteFile(filepath.Join(directory, name), data, 0755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(directory, "commands.jsonl")
	t.Setenv("PATH", directory)
	t.Setenv("IPID_TEST_S3CMD_LOG", log)
	t.Setenv("IPID_TEST_S3CMD_FAIL_SYNC", "")
	return log
}

func commands(t *testing.T, log string) [][]string {
	t.Helper()
	file, err := os.Open(log)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	var calls [][]string
	for {
		var args []string
		if err = decoder.Decode(&args); err == io.EOF {
			return calls
		} else if err != nil {
			t.Fatal(err)
		}
		calls = append(calls, args)
	}
}

func TestSyncToS3CommandArguments(t *testing.T) {
	log := fakeS3cmd(t)
	measurement := paths.Measurement{ID: "icmp_2026-10-27_00-49-59", Path: filepath.Join(t.TempDir(), "raw with spaces", "icmp_2026-10-27_00-49-59")}
	for _, test := range []struct{ name, source, destination, expected string }{
		{"classic", measurement.Path, "s3://bucket/raw/zmap/", "s3://bucket/raw/zmap/"},
		{"classic-ipid", measurement.Path, "s3://bucket/raw/ipid/", "s3://bucket/raw/ipid/"},
		{"geographic", measurement.Path, "s3://netds3o:aweis/ipid-2/raw/continental/geo-test-200k/eu/zmap", "s3://netds3o:aweis/ipid-2/raw/continental/geo-test-200k/eu/zmap/"},
		{"geographic-existing-slash", measurement.Path + "/", "s3://bucket/raw/continental/round/as/ipid/", "s3://bucket/raw/continental/round/as/ipid/"},
		{"repeated-slashes", measurement.Path + "///", "s3://bucket/raw/continental/round/as/zmap///", "s3://bucket/raw/continental/round/as/zmap/"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := syncToS3(test.source, test.destination); err != nil {
				t.Fatal(err)
			}
			calls := commands(t, log)
			want := []string{"sync", measurement.Path, test.expected}
			if !reflect.DeepEqual(calls[len(calls)-1], want) {
				t.Fatalf("s3cmd arguments = %q; want %q", calls[len(calls)-1], want)
			}
			remote := RemoteMeasurementURI(config.UploadConfig{S3Destination: test.destination}, measurement)
			if remote != test.expected+measurement.ID {
				t.Fatalf("remote measurement layout changed: %s", remote)
			}
		})
	}
}

func TestUploadScopedPublicationOrderAndFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "sync-failure"
		}
		t.Run(name, func(t *testing.T) {
			log := fakeS3cmd(t)
			t.Setenv("IPID_MEASURE_WORKSPACE", t.TempDir())
			if fail {
				t.Setenv("IPID_TEST_S3CMD_FAIL_SYNC", "1")
			}
			measurement := paths.Measurement{ID: "icmp_2026-10-27_00-49-59"}
			measurement.Path = filepath.Join(t.TempDir(), measurement.ID)
			if err := os.Mkdir(measurement.Path, 0755); err != nil {
				t.Fatal(err)
			}
			for _, file := range []string{"zmap.pq", "zmap.snapshot.yaml"} {
				if err := os.WriteFile(filepath.Join(measurement.Path, file), []byte(file), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cfg := config.UploadConfig{Enable: true, S3Destination: "s3://bucket/raw/continental/round/eu/zmap", DeleteLocal: fail}
			err := Upload(cfg, measurement)
			calls := commands(t, log)
			want := [][]string{{"sync", measurement.Path, cfg.S3Destination + "/"}}
			marker := filepath.Join(measurement.Path, "measurement-complete.json")
			if fail {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 64 {
					t.Fatalf("sync failure was not preserved: %v", err)
				}
				if _, err = os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed sync created completion: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				want = append(want, []string{"put", "--no-progress", marker, cfg.S3Destination + "/" + measurement.ID + "/measurement-complete.json"})
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("publication commands = %q; want %q", calls, want)
			}
			for _, file := range []string{"zmap.pq", "zmap.snapshot.yaml"} {
				data, err := os.ReadFile(filepath.Join(measurement.Path, file))
				if err != nil || strings.TrimSpace(string(data)) != file {
					t.Fatalf("source changed or was deleted: %s: %v", file, err)
				}
			}
		})
	}
}
