#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "usage: $0 <dst-port> <iface-a-ip> [<iface-b-ip>]" >&2
    exit 1
fi

DST_PORT="$1"
IFACE_A_IP="$2"
IFACE_B_IP="${3:-}"

# Sanity-check args
if ! [[ "$DST_PORT" =~ ^[0-9]+$ ]] || (( DST_PORT < 1 || DST_PORT > 65535 )); then
    echo "error: dst-port must be 1..65535 (got: $DST_PORT)" >&2
    exit 1
fi

ips=("$IFACE_A_IP")
if [[ -n "$IFACE_B_IP" ]]; then
    ips+=("$IFACE_B_IP")
fi

echo "Installing ipid-measure iptables rules:"
echo "  dst-port = $DST_PORT"
echo "  src-ips  = ${ips[*]}"

for ip in "${ips[@]}"; do
    # 1) Bypass conntrack for outgoing scan packets and incoming replies.
    iptables -t raw -A OUTPUT     -p tcp -s "$ip" --dport "$DST_PORT" -j NOTRACK
    iptables -t raw -A PREROUTING -p tcp -d "$ip" --sport "$DST_PORT" -j NOTRACK

    # 2) Drop outbound RSTs the kernel would send to a scan target.
    iptables -A OUTPUT -p tcp --tcp-flags RST RST \
        -s "$ip" --dport "$DST_PORT" -j DROP
done

echo "done."
echo "Verify with:"
echo "  sudo iptables -t raw -L OUTPUT -nv | grep NOTRACK"
echo "  sudo iptables       -L OUTPUT -nv | grep 'tcp flags:0x04/0x04'"
