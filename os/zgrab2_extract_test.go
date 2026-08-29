package os

import "testing"

func TestExtractZGrab2HTTPServerIgnoresHeterogeneousHeaders(t *testing.T) {
	line := `{"ip":"192.0.2.1","data":{"http":{"result":{"response":{"headers":{"Server":["Microsoft-IIS/10.0"],"X-Object":{"nested":true}}}}}}}`
	got, ok := parseZGrab2Line(line)
	if !ok || got.HTTPServer != "Microsoft-IIS/10.0" {
		t.Fatalf("result = %+v, ok=%v", got, ok)
	}
}

func TestExtractZGrab2SMBSupportsNTLMShapes(t *testing.T) {
	for _, line := range []string{
		`{"ip":"192.0.2.1","data":{"smb":{"result":{"native_os":"Windows Server 2022"}}}}`,
		`{"ip":"192.0.2.1","data":{"smb":{"result":{"ntlm":{"native_os":"Windows 10 Enterprise"}}}}}`,
		`{"ip":"192.0.2.1","data":{"smb":{"result":{"ntlm":"Windows Server 2019"}}}}`,
	} {
		got, ok := parseZGrab2Line(line)
		if !ok || got.SMBNativeOS == "" {
			t.Fatalf("result = %+v, ok=%v for %s", got, ok, line)
		}
	}
}
