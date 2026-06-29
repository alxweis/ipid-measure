package config

import (
	"fmt"
)

type UploadConfig struct {
	Enable        bool   `yaml:"enable"`
	S3Destination string `yaml:"s3_destination"`
	DeleteLocal   bool   `yaml:"delete_local"`
}

func validateUpload(c UploadConfig) error {
	if c.Enable {
		if c.S3Destination == "" {
			return fmt.Errorf("s3_destination must be set")
		}
	} else if c.DeleteLocal {
		return fmt.Errorf("delete_local must be false if enable_upload is false")
	}
	return nil
}
