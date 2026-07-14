package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/alxweis/ipid-measure/internal/types"
)

type AnalysisWorkflowConfig struct {
	Enable       bool          `yaml:"enable"`
	S3Prefix     string        `yaml:"s3_prefix"`
	PollInterval time.Duration `yaml:"poll_interval"`
	Timeout      time.Duration `yaml:"timeout"`
}

func validateAnalysisWorkflow(c *IPIDConfig) error {
	w := c.AnalysisWorkflowConfig
	if !w.Enable {
		return nil
	}
	if !strings.HasPrefix(w.S3Prefix, "s3://") || len(strings.TrimPrefix(w.S3Prefix, "s3://")) == 0 {
		return fmt.Errorf("analysis_workflow.s3_prefix must be a non-empty s3:// URI")
	}
	if w.PollInterval < time.Second || w.PollInterval > 10*time.Minute {
		return fmt.Errorf("analysis_workflow.poll_interval must be in [1s, 10m]")
	}
	if w.Timeout < w.PollInterval || w.Timeout > 7*24*time.Hour {
		return fmt.Errorf("analysis_workflow.timeout must be in [poll_interval, 168h]")
	}
	if !c.UploadConfig.Enable {
		return fmt.Errorf("analysis_workflow requires upload.enable=true")
	}
	if c.UploadConfig.DeleteLocal {
		return fmt.Errorf("analysis_workflow requires upload.delete_local=false")
	}
	if c.ZMapPayload != types.PayloadTCP ||
		c.MeasurementMode != types.MeasurementModeRTBased ||
		c.TCPConfig.EstablishConnection {
		return fmt.Errorf("analysis_workflow is only valid for stateless TCP rt-based measurements")
	}
	return nil
}
