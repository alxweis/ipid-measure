package postprocessworkflow

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type recordingRunner struct {
	calls [][]string
}

func (r *recordingRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	return nil, nil
}

func writeConfig(t *testing.T, path, destination, workflowPrefix string) {
	t.Helper()
	content := "upload:\n  s3_destination: " + destination + "\n"
	if workflowPrefix != "" {
		content += "analysis_workflow:\n  s3_prefix: " + workflowPrefix + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestPublishWritesPersistentJobAndUploadsRequestLast(t *testing.T) {
	root := t.TempDir()
	zmapConfig := filepath.Join(root, "zmap.yaml")
	osConfig := filepath.Join(root, "os.yaml")
	ipidConfig := filepath.Join(root, "ipid.yaml")
	writeConfig(t, zmapConfig, "s3://bucket/raw/zmap/", "")
	writeConfig(t, osConfig, "s3://bucket/raw/os/", "")
	writeConfig(t, ipidConfig, "s3://bucket/raw/ipid/", "s3://bucket/workflow/")

	measurements := Measurements{
		ZMap:             "tcp-80_2026-07-22_10-00-00",
		OS:               "tcp-80_2026-07-22_10-00-01",
		RTBase:           "tcp-80_2026-07-22_10-00-02",
		FixedMass:        "tcp-80_2026-07-22_10-00-03",
		FixedBase:        "tcp-80_2026-07-22_10-00-04",
		ConnectionRTBase: "tcp-80_2026-07-22_10-00-05",
		ConnectionFIBase: "tcp-80_2026-07-22_10-00-06",
	}
	sampleDirectory := filepath.Join(root, "zmap", measurements.ZMap)
	if err := os.MkdirAll(sampleDirectory, 0755); err != nil {
		t.Fatal(err)
	}
	measurements.FixedBaseTarget = filepath.Join(sampleDirectory, "zmap-fixed-base-sample.pq")
	if err := os.WriteFile(measurements.FixedBaseTarget, []byte("sample"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(sampleDirectory, "zmap-fixed-base-sample.json"),
		[]byte("{}\n"),
		0644,
	); err != nil {
		t.Fatal(err)
	}
	measurements.ConnectionTarget = filepath.Join(sampleDirectory, "zmap-connection-sample.pq")
	for _, name := range []string{"zmap-connection-sample.pq", "zmap-connection-sample.json"} {
		if err := os.WriteFile(filepath.Join(sampleDirectory, name), []byte("sample"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	runner := &recordingRunner{}
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.FixedZone("CEST", 2*60*60))

	requestURI, err := publish(
		context.Background(), runner, measurements,
		ConfigPaths{ZMap: zmapConfig, OS: osConfig, IPID: ipidConfig},
		filepath.Join(root, "jobs"), now,
	)
	if err != nil {
		t.Fatal(err)
	}

	jobPrefix := "s3://bucket/workflow/analysis-jobs/" + measurements.ZMap
	if requestURI != jobPrefix+"/request.json" {
		t.Fatalf("unexpected request URI: %s", requestURI)
	}
	if len(runner.calls) != 6 {
		t.Fatalf("expected six uploads, got %d", len(runner.calls))
	}
	fixedBaseTargetURI := "s3://bucket/raw/zmap/" + measurements.ZMap + "/zmap-fixed-base-sample.pq"
	if got := runner.calls[0][len(runner.calls[0])-1]; got != fixedBaseTargetURI {
		t.Fatalf("sample target must be uploaded first, got %s", got)
	}
	if got := runner.calls[1][len(runner.calls[1])-1]; got != "s3://bucket/raw/zmap/"+measurements.ZMap+"/zmap-fixed-base-sample.json" {
		t.Fatalf("sample metadata must be uploaded second, got %s", got)
	}
	if got := runner.calls[4][len(runner.calls[4])-1]; got != jobPrefix+"/manifest.json" {
		t.Fatalf("manifest must be uploaded first, got %s", got)
	}
	if got := runner.calls[5][len(runner.calls[5])-1]; got != requestURI {
		t.Fatalf("request must be uploaded last, got %s", got)
	}

	jobDirectory := filepath.Join(root, "jobs", measurements.ZMap)
	var request Request
	data, err := os.ReadFile(filepath.Join(jobDirectory, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	if request.JobID != measurements.ZMap || request.Protocol != "tcp" {
		t.Fatalf("unexpected request: %+v", request)
	}
	if request.FixedBaseTargetURI != fixedBaseTargetURI {
		t.Fatalf("unexpected fixed-base target URI: %s", request.FixedBaseTargetURI)
	}
	connectionURI := "s3://bucket/raw/zmap/" + measurements.ZMap + "/zmap-connection-sample.pq"
	if request.ConnectionTargetURI != connectionURI || runner.calls[2][3] != connectionURI {
		t.Fatal("connection sample was not published")
	}
	if runner.calls[3][3] != "s3://bucket/raw/zmap/"+measurements.ZMap+"/zmap-connection-sample.json" {
		t.Fatal("connection sample metadata was not published")
	}
	if request.CreatedAt.Location() != time.UTC || !request.CreatedAt.Equal(now) {
		t.Fatalf("unexpected creation time: %s", request.CreatedAt)
	}

	var gotManifest map[string]ProtocolMeasurements
	data, err = os.ReadFile(filepath.Join(jobDirectory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &gotManifest); err != nil {
		t.Fatal(err)
	}
	if gotManifest["tcp"].ConnectionTarget != "zmap-connection-sample.pq" {
		t.Fatal("manifest lost the connection target")
	}
	wantManifest := manifest("tcp", measurements)
	if !reflect.DeepEqual(gotManifest, wantManifest) {
		t.Fatalf("manifest mismatch:\n got: %#v\nwant: %#v", gotManifest, wantManifest)
	}
}

func TestValidateMeasurementsRejectsMixedProtocols(t *testing.T) {
	_, err := validateMeasurements(Measurements{
		ZMap:      "icmp_2026-07-22_10-00-00",
		OS:        "icmp_2026-07-22_10-00-01",
		RTBase:    "icmp_2026-07-22_10-00-02",
		FixedMass: "icmp_2026-07-22_10-00-03",
		FixedBase: "tcp-80_2026-07-22_10-00-04",
	})
	if err == nil {
		t.Fatal("expected protocol mismatch to fail")
	}
}

func TestPublishFixedBaseSampleForICMPAndUDP(t *testing.T) {
	for prefix, protocol := range map[string]string{"icmp": "icmp", "udp-dns-53": "udp-dns"} {
		t.Run(prefix, func(t *testing.T) {
			root := t.TempDir()
			configs := ConfigPaths{
				ZMap: filepath.Join(root, "zmap.yaml"),
				OS:   filepath.Join(root, "os.yaml"),
				IPID: filepath.Join(root, "ipid.yaml"),
			}
			writeConfig(t, configs.ZMap, "s3://bucket/raw/zmap/", "")
			writeConfig(t, configs.OS, "s3://bucket/raw/os/", "")
			writeConfig(t, configs.IPID, "s3://bucket/raw/ipid/", "s3://bucket/workflow/")
			m := Measurements{
				ZMap:            prefix + "_2026-07-22_10-00-00",
				OS:              prefix + "_2026-07-22_10-00-01",
				RTBase:          prefix + "_2026-07-22_10-00-02",
				FixedMass:       prefix + "_2026-07-22_10-00-03",
				FixedBase:       prefix + "_2026-07-22_10-00-04",
				FixedBaseTarget: filepath.Join(root, "zmap-fixed-base-sample.pq"),
			}
			for _, name := range []string{"zmap-fixed-base-sample.pq", "zmap-fixed-base-sample.json"} {
				if err := os.WriteFile(filepath.Join(root, name), []byte("sample"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			r := &recordingRunner{}
			output := filepath.Join(root, "jobs")
			uri, err := publish(context.Background(), r, m, configs, output, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			targetPrefix := "s3://bucket/raw/zmap/" + m.ZMap + "/"
			jobPrefix := "s3://bucket/workflow/analysis-jobs/" + m.ZMap + "/"
			want := []string{
				targetPrefix + "zmap-fixed-base-sample.pq",
				targetPrefix + "zmap-fixed-base-sample.json",
				jobPrefix + "manifest.json",
				jobPrefix + "request.json",
			}
			var got []string
			for _, call := range r.calls {
				got = append(got, call[len(call)-1])
			}
			if !reflect.DeepEqual(got, want) || uri != want[3] {
				t.Fatalf("unexpected uploads: %v, request: %s", got, uri)
			}
			data, err := os.ReadFile(filepath.Join(output, m.ZMap, "request.json"))
			if err != nil {
				t.Fatal(err)
			}
			var request Request
			if err := json.Unmarshal(data, &request); err != nil {
				t.Fatal(err)
			}
			if request.Protocol != protocol || request.FixedBaseTargetURI != want[0] || request.ConnectionTargetURI != "" {
				t.Fatalf("unexpected request: %+v", request)
			}
		})
	}
}
