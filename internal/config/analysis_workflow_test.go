package config

import (
	"strings"
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/types"
)

func workflowConfig(payload types.Payload) IPIDConfig {
	return IPIDConfig{
		ZMapReference:   ZMapReference{ZMapPayload: payload},
		MeasurementMode: types.MeasurementModeRTBased,
		UploadConfig: UploadConfig{
			Enable: true,
		},
		AnalysisWorkflowConfig: AnalysisWorkflowConfig{
			Enable:       true,
			S3Prefix:     "s3://bucket/workflow",
			PollInterval: time.Second,
			Timeout:      time.Minute,
		},
	}
}

func TestAnalysisWorkflowSupportsAllMeasurementProtocols(t *testing.T) {
	for _, payload := range []types.Payload{
		types.PayloadICMP,
		types.PayloadTCP,
		types.PayloadUDPDNS,
	} {
		t.Run(string(payload), func(t *testing.T) {
			config := workflowConfig(payload)
			if err := validateAnalysisWorkflow(&config); err != nil {
				t.Fatalf("validateAnalysisWorkflow() error = %v", err)
			}
		})
	}
}

func TestAnalysisWorkflowRejectsFixedIntervalAndEstablishedTCP(t *testing.T) {
	fixed := workflowConfig(types.PayloadICMP)
	fixed.MeasurementMode = types.MeasurementModeFixedInterval
	if err := validateAnalysisWorkflow(&fixed); err == nil || !strings.Contains(err.Error(), "rt-based") {
		t.Fatalf("fixed-interval error = %v", err)
	}

	established := workflowConfig(types.PayloadTCP)
	established.TCPConfig.EstablishConnection = true
	if err := validateAnalysisWorkflow(&established); err == nil || !strings.Contains(err.Error(), "stateless TCP") {
		t.Fatalf("established TCP error = %v", err)
	}
}

func TestAnalysisWorkflowRejectsUnsupportedPayload(t *testing.T) {
	config := workflowConfig(types.Payload("sctp"))
	if err := validateAnalysisWorkflow(&config); err == nil || !strings.Contains(err.Error(), "does not support payload") {
		t.Fatalf("unsupported payload error = %v", err)
	}
}
