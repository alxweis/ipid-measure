package receiver

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReceiveBufferHonorsKernelLimit(t *testing.T) {
	data, err := os.ReadFile("/proc/sys/net/core/rmem_max")
	if err != nil {
		t.Skipf("kernel limit unavailable: %v", err)
	}
	limit, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	before, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := configureReceiveBuffer(fd)
	if err != nil {
		t.Fatal(err)
	}
	want := max(256, 2*min(receiveBufferBytes, limit))
	if before >= 2*receiveBufferBytes {
		want = before
	}
	if actual != want {
		t.Fatalf("receive buffer = %d, want %d (kernel limit %d)", actual, want, limit)
	}
	readback, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil || actual != readback {
		t.Fatalf("reported buffer %d differs from kernel %d: %v", actual, readback, err)
	}
}

func TestReceiveBufferInvalidSocket(t *testing.T) {
	actual, err := configureReceiveBuffer(-1)
	if err == nil || actual != -1 {
		t.Fatalf("invalid socket returned buffer=%d err=%v", actual, err)
	}
}
