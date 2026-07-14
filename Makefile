# IPID measurement toolchain.
#
# The capture path links against libpcap (github.com/google/gopacket/pcap), so
# building requires the libpcap development headers:
#   Debian/Ubuntu:  sudo apt-get install libpcap-dev
#
# The binaries open AF_PACKET raw sockets and therefore must run as root or with
# CAP_NET_RAW (e.g. `sudo setcap cap_net_raw,cap_net_admin+eip ./bin/measure-ipid`).
#
# `make setcap` builds and (re)applies the file capabilities in one step. Run it
# instead of a bare `make` whenever you intend to run a measurement afterwards,
# since `go build` writes a fresh file and drops the capability each time.
#
# The run-* targets are thin wrappers around the already-built binaries; they do
# NOT rebuild (that would drop the file capabilities). Build once with
# `make build` / `make setcap`, then use `make run-*`. Invoking the binaries
# directly (./bin/measure-* ...) works exactly the same.

GO      ?= go
BIN_DIR ?= bin

# -trimpath for reproducible builds; ldflags strip symbol/debug info to shrink
# the binary. CGO is required by gopacket/pcap, so it is left enabled.
BUILD_FLAGS ?= -trimpath -ldflags="-s -w"

# Measurement tools. Each builds to $(BIN_DIR)/measure-<tool> from
# ./cmd/measure-<tool>.
TOOLS := ipid os zmap

# Tools whose binaries open raw sockets and need CAP_NET_RAW / CAP_NET_ADMIN.
CAP_TOOLS := ipid zmap
CAPS      := cap_net_raw,cap_net_admin+eip

# Extra arguments forwarded verbatim to the binary by the run-* targets, e.g.:
#   make run-zmap ARGS="--payload tcp --port 80 --print-id"
ARGS ?=

# Blocklist repo (only the zmap stage consumes it).
BLOCKLIST_REPO ?= git@github.com:netd-tud/active-measurements-blocklists.git
BLOCKLIST_DIR  ?= ../active-measurements-blocklists

BUILD_TARGETS := $(addprefix build-,$(TOOLS))
RUN_TARGETS   := $(addprefix run-,$(TOOLS))

.PHONY: all build setcap pull-blocklist \
        $(BUILD_TARGETS) $(RUN_TARGETS) \
        run-all-icmp run-all-tcp run-all-udp \
        vet test tidy clean

all: build

# --- build -------------------------------------------------------------------

build: $(BUILD_TARGETS)

$(BUILD_TARGETS): build-%:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(BUILD_FLAGS) -o $(BIN_DIR)/measure-$* ./cmd/measure-$*

# Builds, then re-applies file capabilities (needs sudo; prompts once).
setcap: build
	sudo setcap $(foreach t,$(CAP_TOOLS),$(CAPS) $(BIN_DIR)/measure-$(t))

# --- run ---------------------------------------------------------------------

# run-<tool> runs the (already-built) binary with $(ARGS). It does not rebuild.
$(RUN_TARGETS): run-%:
	./$(BIN_DIR)/measure-$* $(ARGS)

# The zmap stage always refreshes the blocklist first.
run-zmap: pull-blocklist

# Per-protocol sweeps. run-all.sh pulls the blocklist once up front.
run-all-icmp:
	./scripts/run-all.sh icmp

run-all-tcp:
	./scripts/run-all.sh tcp

run-all-udp:
	./scripts/run-all.sh udp

# --- blocklist ---------------------------------------------------------------

# Refresh the zmap blocklist (self-bootstrapping clone).
pull-blocklist:
	@if [ -d "$(BLOCKLIST_DIR)/.git" ]; then \
		git -C "$(BLOCKLIST_DIR)" pull --ff-only; \
	else \
		git clone --depth 1 "$(BLOCKLIST_REPO)" "$(BLOCKLIST_DIR)"; \
	fi

# --- housekeeping ------------------------------------------------------------

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN_DIR)
