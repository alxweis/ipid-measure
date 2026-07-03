#!/usr/bin/env bash
#
# run-all.sh -- one full IPID measurement sweep across all three protocols.
#
# For each protocol it runs the pipeline without any manual YAML editing:
#   1. measure-zmap  (per-protocol deltas passed as flags)  -> prints the run id
#   2. measure-os    --zmap <id>   (common config/os.yaml)
#   3. measure-ipid  --zmap <id> -config config/ipid/<proto>.yaml
#
# The zmap run id is threaded through with --zmap, so os.yaml/ipid.yaml never
# need the timestamp pasted in. `set -e` aborts the protocol if measure-zmap
# fails, so os/ipid never run against a stale zmap result.
#
# Prerequisites: the binaries must already be built and capped:
#   make setcap
# and the real config files must exist (config/zmap.yaml, config/os.yaml,
# config/ipid/{icmp,tcp-80,udp-dns-53}.yaml). This script does NOT build.

set -euo pipefail

cd "$(dirname "$0")/.."

run() {
	local proto="$1"
	shift # remaining args are measure-zmap flags for this protocol

	echo "=== ${proto}: zmap ==="
	local id
	id="$(./bin/measure-zmap "$@" --print-id | tail -n1)"
	echo "=== ${proto}: zmap id = ${id} ==="

	echo "=== ${proto}: os ==="
	./bin/measure-os --zmap "${id}"

	echo "=== ${proto}: ipid ==="
	./bin/measure-ipid --zmap "${id}" -config "config/ipid/${proto}.yaml"
}

run icmp        --payload icmp
run tcp-80      --payload tcp     --port 80
run udp-dns-53  --payload udp-dns --port 53 --probe-args "A,www.example.com"

echo "=== all protocols done ==="
