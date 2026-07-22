#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")/.."

# Optional protocol filter: run the full sweep for a single protocol only.
#   run-all.sh              -> icmp + tcp + udp
#   run-all.sh icmp|tcp|udp -> just that protocol
if [ $# -gt 1 ]; then
    echo "usage: $0 [icmp|tcp|udp]" >&2
    exit 1
fi
case "${1:-all}" in
    all) SELECTED_PROTOS=(icmp tcp-80 udp-dns-53) ;;
    icmp) SELECTED_PROTOS=(icmp) ;;
    tcp) SELECTED_PROTOS=(tcp-80) ;;
    udp) SELECTED_PROTOS=(udp-dns-53) ;;
    *) echo "usage: $0 [icmp|tcp|udp]" >&2; exit 1 ;;
esac

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

# --- swept ipid parameterisations --------------------------------------------
RT_CONNECTION_COUNT=4;   RT_REQUESTS_PER_CON=4
FI_CONNECTION_COUNT_1=4; FI_REQUESTS_PER_CON_1=4;  FI_REQUEST_INTERVAL_1=20ms; FI_MIN_REPLY_RATE_1=1.0
FI_CONNECTION_COUNT_2=4; FI_REQUESTS_PER_CON_2=25; FI_REQUEST_INTERVAL_2=20ms; FI_MIN_REPLY_RATE_2=0.8

# spec fields: mode:connection_count:requests_per_connection:request_interval:minimum_reply_rate
MODES=(
    "rt-based:${RT_CONNECTION_COUNT}:${RT_REQUESTS_PER_CON}::"
    "fixed-interval:${FI_CONNECTION_COUNT_1}:${FI_REQUESTS_PER_CON_1}:${FI_REQUEST_INTERVAL_1}:${FI_MIN_REPLY_RATE_1}"
)

# High-volume fixed-interval probing is only safe without establishing TCP
# connections. Running it against many hosts with full handshakes is unfriendly.
STATELESS_ONLY_MODES=(
    "fixed-interval:${FI_CONNECTION_COUNT_2}:${FI_REQUESTS_PER_CON_2}:${FI_REQUEST_INTERVAL_2}:${FI_MIN_REPLY_RATE_2}"
)

DNS_PROBE="A,www.example.com"

PROTOS=("${SELECTED_PROTOS[@]}")

declare -A ZMAP OS RT_BASE FIXED_MASS FIXED_BASE CONNECTION_RT CONNECTION_FIXED

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
    os_id=$(./bin/measure-os --zmap "$id" --print-id | tail -n1)
    OS[$proto]=$os_id
    SUMMARY+=("os    $proto  $os_id")
done

# --- Phase 2: ipid parameter sweep -------------------------------------------
LAST_IPID_ID=
run_ipid() {
    local proto=$1 zmap_id=$2 tcp_establish_con=$3 spec=$4
    local target_file=${5:-} analysis_workflow=${6:-false}
    local mode con_count reqs_per_con fi_request_interval fi_minimum_reply_rate
    IFS=: read -r mode con_count reqs_per_con fi_request_interval fi_minimum_reply_rate <<< "$spec"

    args=(--config "config/ipid.yaml"
          --zmap "$zmap_id"
          --connection_count "$con_count"
          --requests_per_connection "$reqs_per_con"
          --measurement_mode "$mode"
          --tcp.establish_connection "$tcp_establish_con"
          --analysis_workflow.enable "$analysis_workflow")

    if [[ "$mode" == "fixed-interval" ]]; then
        args+=(--fixed_interval.request_interval "$fi_request_interval"
               --fixed_interval.minimum_reply_rate "$fi_minimum_reply_rate")
    fi
    if [[ -n "$target_file" ]]; then
        args+=(--target-file "$target_file")
    fi

    echo "=== [$proto] ipid: mode=$mode con=$con_count reqs=$reqs_per_con establish=$tcp_establish_con ${fi_request_interval:+interval=$fi_request_interval rate=$fi_minimum_reply_rate} ${target_file:+targets=$target_file} ==="
    LAST_IPID_ID=$(./bin/measure-ipid "${args[@]}" --print-id | tail -n1)
    SUMMARY+=("ipid  $proto  est=$tcp_establish_con mode=$mode con=$con_count reqs=$reqs_per_con  $LAST_IPID_ID")
}

for proto in "${PROTOS[@]}"; do
    id=${ZMAP[$proto]}

    # The stateless RT run publishes an S3 analysis request and blocks until
    # the analysis VM has returned a verified UNCLASSIFIED target parquet.
    run_ipid "$proto" "$id" false "${MODES[0]}" "" true
    rt_id=$LAST_IPID_ID
    RT_BASE[$proto]=$rt_id
    unclassified_targets="$PWD/ipid/raw/$rt_id/zmap_unclassified.pq"
    if [[ ! -f "$unclassified_targets" ]]; then
        echo "analysis result missing: $unclassified_targets" >&2
        exit 1
    fi

    # Probe only the RT-unclassified addresses at the higher sample count.
    run_ipid "$proto" "$id" false "${STATELESS_ONLY_MODES[0]}" "$unclassified_targets" false
    FIXED_MASS[$proto]=$LAST_IPID_ID

    # Base fixed-interval and TCP connection variants keep the original targets.
    run_ipid "$proto" "$id" false "${MODES[1]}" "" false
    FIXED_BASE[$proto]=$LAST_IPID_ID
    if [[ "$proto" == "tcp-80" ]]; then
        run_ipid "$proto" "$id" true  "${MODES[0]}" "" false
        CONNECTION_RT[$proto]=$LAST_IPID_ID
        run_ipid "$proto" "$id" true  "${MODES[1]}" "" false
        CONNECTION_FIXED[$proto]=$LAST_IPID_ID
    fi
done

echo "=== sweep complete ==="

# Publish one persistent analysis job per completed protocol sweep. The request
# is uploaded last, so the analysis VM never observes a partially written job.
for proto in "${PROTOS[@]}"; do
    publish_args=(--zmap "${ZMAP[$proto]}"
                  --os "${OS[$proto]}"
                  --rt-base "${RT_BASE[$proto]}"
                  --fixed-mass "${FIXED_MASS[$proto]}"
                  --fixed-base "${FIXED_BASE[$proto]}")
    if [[ "$proto" == "tcp-80" ]]; then
        publish_args+=(--connection-rt-base "${CONNECTION_RT[$proto]}"
                       --connection-fixed-base "${CONNECTION_FIXED[$proto]}")
    fi
    request_uri=$(./bin/publish-analysis-job "${publish_args[@]}")
    echo "=== [$proto] analysis job published: $request_uri ==="
done
