//go:build unix

package os

import "testing"

func TestOSProbeResourceAdmission(t *testing.T) {
	if err := checkProbeResources(10000, 10000, 10000, 4, 65536, 32768, 60999); err != nil {
		t.Fatal(err)
	}
	for _, limits := range [][3]int{{1024, 32768, 60999}, {32768, 32768, 60999}, {65536, 50000, 60999}} {
		if err := checkProbeResources(10000, 10000, 10000, 4, uint64(limits[0]), limits[1], limits[2]); err == nil {
			t.Fatalf("unsafe limits accepted %v", limits)
		}
	}
}

func TestOSTCP20KResourceAdmission(t *testing.T) {
	if err := checkProbeResources(10000, 10000, 20000, 4, 131072, 32768, 60999); err != nil {
		t.Fatal(err)
	}
	if err := checkProbeResources(10000, 10000, 20000, 4, 65536, 32768, 60999); err == nil {
		t.Fatal("TCP profile exceeds conservative descriptor budget")
	}
	// Isolate the TCP check from the independent UDP port reservation.
	if err := checkProbeResources(1000, 1000, 20000, 4, 131072, 40000, 60999); err == nil {
		t.Fatal("TCP profile exceeds active-sender port headroom")
	}
}
