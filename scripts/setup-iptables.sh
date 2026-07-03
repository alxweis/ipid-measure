#!/usr/bin/env bash
# Configure iptables to support ipid measurement with
# `tcp.establish_connection: true`.
#
# Background
# ----------
# measure-ipid builds TCP packets directly via AF_PACKET, bypassing the kernel's
# TCP stack. When establish_connection=true the kernel still sees incoming
# SYN-ACKs from scan targets and, finding no matching socket, sends RST in
# response. That RST aborts the connection before measure-ipid can send its
# ACK + PSH-ACK requests for the remaining sequence numbers.
#
# These rules:
#   1) bypass conntrack for scan packets to save memory/CPU at large scale;
#   2) drop outbound RSTs that the kernel would generate for scan packets,
#      preventing it from killing our handshake.
#
# Usage
# -----
#   sudo ./scripts/setup-iptables.sh <dst-port> <iface-a-ip> [<iface-b-ip>]
#
#   sudo ./scripts/setup-iptables.sh 80 141.76.94.12 141.76.94.15
#
# To remove the rules later, run scripts/teardown-iptables.sh with the same args.

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
