package upload

import (
	"fmt"
	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/paths"
	"log"
	"os"
	"os/exec"
	"strings"
)

// syncToS3 mirrors the measurement directory into the S3 destination using s3cmd (creds from the local ~/.s3cfg).
func syncToS3(localDir, destination string) error {
	src := strings.TrimRight(localDir, "/")
	cmd := exec.Command("s3cmd", "sync", src, destination)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func Upload(c config.UploadConfig, m paths.Measurement) error {
	if !c.Enable {
		return nil
	}

	log.Printf("uploading measurement to %s", c.S3Destination)
	if err := syncToS3(m.Path, c.S3Destination); err != nil {
		// Upload failed: keep the local data so it can be retried.
		return fmt.Errorf("sync to s3: %w", err)
	}
	log.Printf("upload completed: %s", c.S3Destination)

	if c.DeleteLocal {
		if err := os.RemoveAll(m.Path); err != nil {
			return fmt.Errorf("delete local measurement directory: %w", err)
		}
		log.Printf("deleted local measurement directory: %s", m.Path)
	}
	return nil
}
