#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")/.."

make pull-blocklist

# --- collected measurement ids (printed as a summary at the end) --------------
SUMMARY=()
print_summary() {
    echo
    echo "=== measurement ids ==="
    if [ ${#SUMMARY[@]} -eq 0 ]; then
        echo "  (none)"
    else
        printf '  %s\n' "${SUMMARY[@]}"
    fi
}
# Print the summary even if the sweep aborts partway (set -e).
trap print_summary EXIT

# Newest run id under <tool>/raw (the run just created, since runs are sequential).
latest_id() { ls -t "$1/raw" 2>/dev/null | head -n1; }

# --- swept ipid parameterisations --------------------------------------------
RT_CONNECTION_COUNT=4;   RT_REQUESTS_PER_CON=4
FI_CONNECTION_COUNT_1=4; FI_REQUESTS_PER_CON_1=4;  FI_REQUEST_INTERVAL_1=20ms; FI_MIN_REPLY_RATE_1=1.0
FI_CONNECTION_COUNT_2=4; FI_REQUESTS_PER_CON_2=25; FI_REQUEST_INTERVAL_2=20ms; FI_MIN_REPLY_RATE_2=0.8

# spec fields: mode:connection_count:requests_per_connection:request_interval:minimum_reply_rate
MODES=(
    "rt-based:${RT_CONNECTION_COUNT}:${RT_REQUESTS_PER_CON}::"
    "fixed-interval:${FI_CONNECTION_COUNT_1}:${FI_REQUESTS_PER_CON_1}:${FI_REQUEST_INTERVAL_1}:${FI_MIN_REPLY_RATE_1}"
    "fixed-interval:${FI_CONNECTION_COUNT_2}:${FI_REQUESTS_PER_CON_2}:${FI_REQUEST_INTERVAL_2}:${FI_MIN_REPLY_RATE_2}"
)

DNS_PROBE="A,www.example.com"

PROTOS=(icmp tcp-80 udp-dns-53)

declare -A ZMAP

zmap_flags() {
    case "$1" in
        icmp)       echo "--payload icmp" ;;
        tcp-80)     echo "--payload tcp --port 80" ;;
        udp-dns-53) echo "--payload udp-dns --port 53 --probe-args ${DNS_PROBE}" ;;
        *) echo "unknown proto: $1" >&2; return 1 ;;
    esac
}

# --- Phase 1: zmap + os per protocol -----------------------------------------
for proto in "${PROTOS[@]}"; do
    echo "=== [$proto] zmap ==="
    # shellcheck disable=SC2046
    id=$(./bin/measure-zmap $(zmap_flags "$proto") --print-id | tail -n1)
    ZMAP[$proto]=$id
    SUMMARY+=("zmap  $proto  $id")
    echo "=== [$proto] zmap id = $id ==="

    echo "=== [$proto] os ==="
    ./bin/measure-os --zmap "$id"
    SUMMARY+=("os    $proto  $(latest_id os)")
done

# --- Phase 2: ipid parameter sweep -------------------------------------------
for proto in "${PROTOS[@]}"; do
    id=${ZMAP[$proto]}

    # establish_connection only varies for tcp/80
    if [[ "$proto" == "tcp-80" ]]; then
        tcp_establish_con_values=(false true)
    else
        tcp_establish_con_values=(false)
    fi

    for tcp_establish_con in "${tcp_establish_con_values[@]}"; do
        for spec in "${MODES[@]}"; do
            IFS=: read -r mode con_count reqs_per_con fi_request_interval fi_minimum_reply_rate <<< "$spec"

            args=(--config "config/ipid.yaml"
                  --zmap "$id"
                  --connection_count "$con_count"
                  --requests_per_connection "$reqs_per_con"
                  --measurement_mode "$mode"
                  --tcp.establish_connection "$tcp_establish_con")

            if [[ "$mode" == "fixed-interval" ]]; then
                args+=(--fixed_interval.request_interval "$fi_request_interval"
                       --fixed_interval.minimum_reply_rate "$fi_minimum_reply_rate")
            fi

            echo "=== [$proto] ipid: mode=$mode con=$con_count reqs=$reqs_per_con establish=$tcp_establish_con ${fi_request_interval:+interval=$fi_request_interval rate=$fi_minimum_reply_rate} ==="
            ./bin/measure-ipid "${args[@]}"
            SUMMARY+=("ipid  $proto  est=$tcp_establish_con mode=$mode con=$con_count reqs=$reqs_per_con  $(latest_id ipid)")
        done
    done
done

echo "=== sweep complete ==="