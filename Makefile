# IPID measurement toolchain.
#
# The capture path links against libpcap (github.com/google/gopacket/pcap), so
# building requires the libpcap development headers:
#   Debian/Ubuntu:  sudo apt-get install libpcap-dev
#
# The binaries open AF_PACKET raw sockets and therefore must run as root or with
# CAP_NET_RAW (e.g. `sudo setcap cap_net_raw+ep ./bin/measure-ipid`).
#
# `make setcap` builds and (re)applies the file capabilities in one step. Run it
# instead of a bare `make` whenever you intend to run a measurement afterwards,
# since `go build` writes a fresh file and drops the capability each time.

GO      ?= go
BIN_DIR ?= bin

# -trimpath for reproducible builds; ldflags strip symbol/debug info to shrink
# the binary. CGO is required by gopacket/pcap, so it is left enabled.
BUILD_FLAGS ?= -trimpath -ldflags="-s -w"

CMDS := measure-ipid measure-os measure-zmap

# Binaries that open raw sockets and need CAP_NET_RAW / CAP_NET_ADMIN.
CAP_CMDS := measure-ipid measure-zmap
CAPS     := cap_net_raw,cap_net_admin+ep

# Blocklist repo
BLOCKLIST_REPO ?= git@github.com:netd-tud/active-measurements-blocklists.git
BLOCKLIST_DIR  ?= ../active-measurements-blocklists

.PHONY: all build setcap pull-blocklist $(CMDS) vet test tidy clean

all: build

build: $(CMDS)

$(CMDS):
	@mkdir -p $(BIN_DIR)
	$(GO) build $(BUILD_FLAGS) -o $(BIN_DIR)/$@ ./cmd/$@

# Builds, then re-applies file capabilities (needs sudo; prompts once).
setcap: build
	sudo setcap $(foreach b,$(CAP_CMDS),$(CAPS) $(BIN_DIR)/$(b))

# Refresh the zmap blocklist (self-bootstrapping clone).
pull-blocklist:
	@if [ -d "$(BLOCKLIST_DIR)/.git" ]; then \
		git -C "$(BLOCKLIST_DIR)" pull --ff-only; \
	else \
		git clone --depth 1 "$(BLOCKLIST_REPO)" "$(BLOCKLIST_DIR)"; \
	fi

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN_DIR)
