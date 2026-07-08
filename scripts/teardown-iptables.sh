#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "usage: $0 <dst-port> <iface-a-ip> [<iface-b-ip>]" >&2
    exit 1
fi

DST_PORT="$1"
IFACE_A_IP="$2"
IFACE_B_IP="${3:-}"

ips=("$IFACE_A_IP")
if [[ -n "$IFACE_B_IP" ]]; then
    ips+=("$IFACE_B_IP")
fi

echo "Removing ipid-measure iptables rules for dst-port=$DST_PORT, src-ips=${ips[*]}"

for ip in "${ips[@]}"; do
    iptables -t raw -D OUTPUT     -p tcp -s "$ip" --dport "$DST_PORT" -j NOTRACK 2>/dev/null || true
    iptables -t raw -D PREROUTING -p tcp -d "$ip" --sport "$DST_PORT" -j NOTRACK 2>/dev/null || true
    iptables       -D OUTPUT -p tcp --tcp-flags RST RST \
        -s "$ip" --dport "$DST_PORT" -j DROP 2>/dev/null || true
done

echo "done."
