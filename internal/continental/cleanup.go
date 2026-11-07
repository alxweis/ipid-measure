package continental

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/alxweis/ipid-measure/internal/upload"
)

// This write-ahead receipt authorizes absence of exactly one bulk file. It is
// bound to both this workspace's configuration and the unchanged S3 commit.
// All snapshots, logs, ZMap inputs and analysis-produced targets stay local.
type cleanupReceipt struct {
	Version      int                 `json:"version"`
	Binding      string              `json:"binding"`
	ID           string              `json:"measurement_id"`
	MarkerSHA256 string              `json:"completion_sha256"`
	File         string              `json:"file"`
	Evidence     upload.FileEvidence `json:"evidence"`
}

func bulkFile(id string) string {
	if strings.HasPrefix(id, "interprotocol-") {
		return "interprotocol.pq"
	}
	return "ipid.pq"
}

func (r *Runner) cleanupReceiptPath(id string) (string, error) {
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, `/\`) {
		return "", fmt.Errorf("unsafe cleanup measurement id: %q", id)
	}
	return filepath.Join(r.Workspace, "cleanup", id+".json"), nil
}

func (r *Runner) readCleanupReceipt(kind, id string) (*cleanupReceipt, error) {
	if kind != "ipid" {
		return nil, nil
	}
	path, err := r.cleanupReceiptPath(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read cleanup receipt: %w", err)
	}
	var receipt cleanupReceipt
	if err = json.Unmarshal(data, &receipt); err != nil {
		return nil, fmt.Errorf("decode cleanup receipt: %w", err)
	}
	return &receipt, nil
}

func (r *Runner) validateCleanupReceipt(receipt *cleanupReceipt, id string, marker []byte, files map[string]upload.FileEvidence) error {
	expected, exists := files[bulkFile(id)]
	if !exists || receipt.Version != 1 || receipt.Binding != r.state.Binding ||
		receipt.ID != id || receipt.MarkerSHA256 != digest(marker) ||
		receipt.File != bulkFile(id) || receipt.Evidence != expected {
		return fmt.Errorf("cleanup receipt differs from committed measurement %s", id)
	}
	return nil
}

// Resolve the parent before unlinking. A relocated/symlinked workspace is fine,
// but a measurement directory pointing outside that workspace is not.
func (r *Runner) checkedCleanupParent(path string) error {
	root, err := filepath.EvalSymlinks(r.Workspace)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, parent)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("cleanup path leaves workspace: %s", path)
	}
	return nil
}

func (r *Runner) checkedCleanupPath(path string) error {
	if err := r.checkedCleanupParent(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("cleanup requires a regular file: %s", path)
	}
	return nil
}

// Persist and fsync the authorization before unlinking the data. A crash before
// or after unlink is recoverable: present files are still checked against S3;
// absent files are accepted only with this receipt and the same S3 marker.
func (r *Runner) writeCleanupReceipt(path string, receipt cleanupReceipt) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if err := r.checkedCleanupParent(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(directory, ".cleanup-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := r.checkedCleanupPath(f.Name()); err != nil {
		return err
	}
	if _, err = f.Write(Encode(receipt)); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Called only after committed has verified every retained local file against
// the completion marker published after successful sync. It never deletes a
// directory, follows a data symlink, or touches a remote object.
func (r *Runner) cleanupMeasurement(kind, id string, marker []byte, files map[string]upload.FileEvidence, receipt *cleanupReceipt) error {
	if kind != "ipid" || r.Protocol == "" || r.RetainLocal {
		return nil
	}
	name := bulkFile(id)
	path := r.rawPath(kind, id, name)
	if err := r.checkedCleanupPath(path); err != nil {
		if os.IsNotExist(err) && receipt != nil {
			return nil
		}
		return fmt.Errorf("check cleanup source: %w", err)
	}
	if receipt == nil {
		receipt = &cleanupReceipt{Version: 1, Binding: r.state.Binding, ID: id,
			MarkerSHA256: digest(marker), File: name, Evidence: files[name]}
	}
	receiptPath, err := r.cleanupReceiptPath(id)
	if err != nil {
		return err
	}
	if err = r.writeCleanupReceipt(receiptPath, *receipt); err != nil {
		return fmt.Errorf("persist cleanup receipt: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove committed local bulk file: %w", err)
	}
	log.Printf("freed committed local bulk file: %s (%d bytes); S3 copy retained", path, receipt.Evidence.Size)
	return nil
}
