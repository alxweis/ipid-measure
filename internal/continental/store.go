// Package continental adds isolated campaign orchestration around the existing
// measurement executables. Scientific probing and analysis formats stay there.
package continental

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var Sites = []string{"eu", "as", "af", "na", "sa", "au"}
var Protocols = []string{"icmp", "tcp", "udp-dns"}
var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$`)

type Descriptor struct {
	Version   int      `json:"version"`
	Campaign  string   `json:"campaign_id"`
	Sites     []string `json:"sites"`
	Protocols []string `json:"protocols"`
	RawRoot   string   `json:"raw_root"`
}

type Store interface {
	Read(context.Context, string) ([]byte, bool, error)
	Put(context.Context, string, []byte) error
	PutFile(context.Context, string, string) error
	GetFile(context.Context, string, string) error
}

type S3 struct{ Directory string }

// Only an exact missing-object response is absence. AccessDenied, network and
// provider errors must never authorize overwriting a control object.
func Missing(output string) bool {
	return strings.Contains(output, "ERROR: S3 error: 404 (NoSuchKey)") || strings.Contains(output, "ERROR: S3 error: 404 (Not Found)")
}

func (s S3) Read(ctx context.Context, uri string) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "s3cmd", "get", "--no-progress", uri, "-")
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if Missing(stderr.String()) || strings.TrimSpace(stderr.String()) == fmt.Sprintf("ERROR: Parameter problem: Source object '%s' does not exist.", uri) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read %s: %w: %s", uri, err, stderr.String())
	}
	return out.Bytes(), true, nil
}

func (s S3) Put(ctx context.Context, uri string, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := os.MkdirAll(s.Directory, 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.Directory, "publication-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	output, err := exec.CommandContext(ctx, "s3cmd", "put", "--no-progress", f.Name(), uri).CombinedOutput()
	if err != nil {
		return fmt.Errorf("publish %s: %w: %s", uri, err, output)
	}
	return nil
}

func Join(prefix string, parts ...string) string {
	return strings.TrimRight(prefix, "/") + "/" + strings.Join(parts, "/")
}
func Encode(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
}
func JSONEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return bytes.Equal(Encode(x), Encode(y))
}

func Immutable(ctx context.Context, store Store, uri string, value any) error {
	data := Encode(value)
	old, exists, err := store.Read(ctx, uri)
	if err != nil {
		return err
	}
	if exists {
		if !JSONEqual(old, data) {
			return fmt.Errorf("immutable publication differs: %s", uri)
		}
		return nil
	}
	if err = store.Put(ctx, uri, data); err != nil {
		return err
	}
	old, exists, err = store.Read(ctx, uri)
	if err != nil {
		return err
	}
	if !exists || !JSONEqual(old, data) {
		return fmt.Errorf("publication verification failed: %s", uri)
	}
	return nil
}

func AtomicJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(path+".part", Encode(value), 0600); err != nil {
		return err
	}
	return os.Rename(path+".part", path)
}

func Validate(campaign, site string) error {
	if !safeID.MatchString(campaign) {
		return fmt.Errorf("campaign requires a safe explicit ID (1..80 characters)")
	}
	for _, value := range Sites {
		if value == site {
			return nil
		}
	}
	return fmt.Errorf("site must be one of eu,as,af,na,sa,au")
}

func (s S3) PutFile(ctx context.Context, uri, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	output, err := exec.CommandContext(ctx, "s3cmd", "put", "--no-progress", path, uri).CombinedOutput()
	if err != nil {
		return fmt.Errorf("upload %s: %w: %s", uri, err, output)
	}
	return nil
}
func (s S3) GetFile(ctx context.Context, uri, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	output, err := exec.CommandContext(ctx, "s3cmd", "get", "--no-progress", uri, path+".part").CombinedOutput()
	if err != nil {
		return fmt.Errorf("download %s: %w: %s", uri, err, output)
	}
	return os.Rename(path+".part", path)
}

// RetryOSFailure is explicit operator recovery: archive only this campaign's
// terminal failure, never remove source data or a successful marker.
func (s S3) RetryOSFailure(ctx context.Context, job string) error {
	if _, exists, err := s.Read(ctx, Join(job, "done.json")); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("OS scan already completed")
	}
	data, exists, err := s.Read(ctx, Join(job, "failed.json"))
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("OS job has no failure to retry")
	}
	if err = s.Put(ctx, Join(job, "attempts", fmt.Sprint(time.Now().UnixNano()), "failed.json"), data); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, "s3cmd", "del", Join(job, "failed.json")).CombinedOutput()
	if err != nil {
		return fmt.Errorf("remove archived OS failure: %w: %s", err, output)
	}
	return nil
}
