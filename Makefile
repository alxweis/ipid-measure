# IPID measurement toolchain.
#
# The capture path links against libpcap (github.com/google/gopacket/pcap), so
# building requires the libpcap development headers:
#   Debian/Ubuntu:  sudo apt-get install libpcap-dev
#
# The binaries open AF_PACKET raw sockets and therefore must run as root or with
# CAP_NET_RAW (e.g. `sudo setcap cap_net_raw+ep ./bin/measure-ipid`).

GO      ?= go
BIN_DIR ?= bin

# -trimpath for reproducible builds; ldflags strip symbol/debug info to shrink
# the binary. CGO is required by gopacket/pcap, so it is left enabled.
BUILD_FLAGS ?= -trimpath -ldflags="-s -w"

CMDS := measure-ipid measure-os measure-zmap

.PHONY: all build $(CMDS) vet test tidy clean

all: build

build: $(CMDS)

$(CMDS):
	@mkdir -p $(BIN_DIR)
	$(GO) build $(BUILD_FLAGS) -o $(BIN_DIR)/$@ ./cmd/$@

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN_DIR)
