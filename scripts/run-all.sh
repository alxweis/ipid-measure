#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
    cat >&2 <<EOF
usage: $0 [icmp|tcp|udp] [--zmap-id ID] [--os-id ID]

Without existing ids, run the complete sweep. --zmap-id reuses a local ZMap
measurement and starts at OS; adding --os-id reuses both and starts at IPID.
--os-id requires --zmap-id, and resume options require a single protocol.
EOF
}

SELECTED_PROTOCOL=all
RESUME_ZMAP_ID=
RESUME_OS_ID=

if [[ $# -gt 0 && "$1" != --* ]]; then
    SELECTED_PROTOCOL=$1
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --zmap-id)
            [[ $# -ge 2 ]] || { echo "--zmap-id requires a value" >&2; usage; exit 1; }
            RESUME_ZMAP_ID=$2
            shift 2
            ;;
        --zmap-id=*)
            RESUME_ZMAP_ID=${1#*=}
            shift
            ;;
        --os-id)
            [[ $# -ge 2 ]] || { echo "--os-id requires a value" >&2; usage; exit 1; }
            RESUME_OS_ID=$2
            shift 2
            ;;
        --os-id=*)
            RESUME_OS_ID=${1#*=}
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

case "$SELECTED_PROTOCOL" in
    all) SELECTED_PROTOS=(icmp tcp-80 udp-dns-53) ;;
    icmp) SELECTED_PROTOS=(icmp) ;;
    tcp) SELECTED_PROTOS=(tcp-80) ;;
    udp) SELECTED_PROTOS=(udp-dns-53) ;;
    *) echo "unknown protocol: $SELECTED_PROTOCOL" >&2; usage; exit 1 ;;
esac

if [[ -n "$RESUME_OS_ID" && -z "$RESUME_ZMAP_ID" ]]; then
    echo "--os-id requires --zmap-id" >&2
    exit 1
fi
if [[ -n "$RESUME_ZMAP_ID" && ${#SELECTED_PROTOS[@]} -ne 1 ]]; then
    echo "resume options require exactly one of icmp, tcp, or udp" >&2
    exit 1
fi

validate_measurement() {
    local kind=$1 proto=$2 id=$3
    local pattern="^${proto}_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}$"
    local path snapshot

    if [[ ! "$id" =~ $pattern ]]; then
        echo "invalid $kind id for $proto: $id" >&2
        exit 1
    fi

    case "$kind" in
        zmap)
            path="zmap/raw/$id/zmap.pq"
            snapshot="zmap/raw/$id/zmap.snapshot.yaml"
            ;;
        os)
            path="os/raw/$id/os.pq"
            snapshot="os/raw/$id/os.snapshot.yaml"
            ;;
        *)
            echo "internal error: unknown measurement kind $kind" >&2
            exit 1
            ;;
    esac

    if [[ ! -s "$path" ]]; then
        echo "existing $kind measurement is missing or empty: $path" >&2
        exit 1
    fi
    if [[ ! -s "$snapshot" ]]; then
        echo "existing $kind snapshot is missing or empty: $snapshot" >&2
        exit 1
    fi
}

validate_os_zmap_reference() {
    local os_id=$1 zmap_id=$2
    local snapshot="os/raw/$os_id/os.snapshot.yaml"
    local referenced_zmap

    referenced_zmap=$(
        awk '$1 == "zmap:" { value=$2; gsub(/^"|"$/, "", value); print value; exit }' "$snapshot"
    )
    if [[ -z "$referenced_zmap" ]]; then
        echo "could not read zmap reference from $snapshot" >&2
        exit 1
    fi
    if [[ "$referenced_zmap" != "$zmap_id" ]]; then
        echo "OS measurement $os_id references $referenced_zmap, not $zmap_id" >&2
        exit 1
    fi
}

if [[ -n "$RESUME_ZMAP_ID" ]]; then
    resume_proto=${SELECTED_PROTOS[0]}
    validate_measurement zmap "$resume_proto" "$RESUME_ZMAP_ID"
    if [[ -n "$RESUME_OS_ID" ]]; then
        validate_measurement os "$resume_proto" "$RESUME_OS_ID"
        validate_os_zmap_reference "$RESUME_OS_ID" "$RESUME_ZMAP_ID"
    fi
else
    # Only a fresh ZMap scan consumes the blocklist.
    make pull-blocklist
fi

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
TCP_FIXED_BASE_SAMPLE_PERCENT=10
TCP_FIXED_BASE_SAMPLE_MINIMUM=1000000

# Internet-wide OS profile: retain high-yield SSH/SMB/HTTP/HTTPS/SNMP probes
# for every target, but sample the lower-yield application modules. These
# overrides keep run-all bounded even when a deployed os.yaml predates the
# optimized defaults.
OS_SECONDARY_SAMPLE_RATE=0.01
OS_ZGRAB2_SENDERS=5K
OS_ZDNS_THREADS=1K
OS_SNMP_WORKERS=3K
OS_CONNECT_TIMEOUT=1s
OS_READ_TIMEOUT=1s
OS_SNMP_TIMEOUT=1s

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

declare -A ZMAP OS RT_BASE FIXED_MASS FIXED_BASE FIXED_BASE_TARGET CONNECTION_RT CONNECTION_FIXED

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
    if [[ -n "$RESUME_ZMAP_ID" ]]; then
        id=$RESUME_ZMAP_ID
        echo "=== [$proto] reusing zmap id = $id ==="
    else
        echo "=== [$proto] zmap ==="
        # shellcheck disable=SC2046
        id=$(./bin/measure-zmap $(zmap_flags "$proto") --print-id | tail -n1)
        echo "=== [$proto] zmap id = $id ==="
    fi
    ZMAP[$proto]=$id
    SUMMARY+=("zmap  $proto  $id")

    if [[ -n "$RESUME_OS_ID" ]]; then
        os_id=$RESUME_OS_ID
        echo "=== [$proto] reusing os id = $os_id ==="
    else
        echo "=== [$proto] os ==="
        os_args=(--zmap "$id"
                 --secondary-sample-rate "$OS_SECONDARY_SAMPLE_RATE"
                 --zgrab2-senders "$OS_ZGRAB2_SENDERS"
                 --zdns-threads "$OS_ZDNS_THREADS"
                 --snmp-workers "$OS_SNMP_WORKERS"
                 --connect-timeout "$OS_CONNECT_TIMEOUT"
                 --read-timeout "$OS_READ_TIMEOUT"
                 --snmp-timeout "$OS_SNMP_TIMEOUT")
        os_id=$(./bin/measure-os "${os_args[@]}" --print-id | tail -n1)
    fi
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

    # TCP fixed-interval base measurements share one exact-size uniform sample:
    # min(N, max(ceil(10% * N), 1,000,000)). Other protocols keep the full
    # original ZMap target population.
    fixed_base_target=
    if [[ "$proto" == "tcp-80" ]]; then
        fixed_base_target=$(./bin/sample-zmap \
            --zmap "$id" \
            --percent "$TCP_FIXED_BASE_SAMPLE_PERCENT" \
            --minimum "$TCP_FIXED_BASE_SAMPLE_MINIMUM" | tail -n1)
    fi
    FIXED_BASE_TARGET[$proto]=$fixed_base_target

    run_ipid "$proto" "$id" false "${MODES[1]}" "$fixed_base_target" false
    FIXED_BASE[$proto]=$LAST_IPID_ID
    if [[ "$proto" == "tcp-80" ]]; then
        run_ipid "$proto" "$id" true  "${MODES[0]}" "" false
        CONNECTION_RT[$proto]=$LAST_IPID_ID
        run_ipid "$proto" "$id" true  "${MODES[1]}" "$fixed_base_target" false
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
        publish_args+=(--fixed-base-target "${FIXED_BASE_TARGET[$proto]}"
                       --connection-rt-base "${CONNECTION_RT[$proto]}"
                       --connection-fixed-base "${CONNECTION_FIXED[$proto]}")
    fi
    request_uri=$(./bin/publish-analysis-job "${publish_args[@]}")
    echo "=== [$proto] analysis job published: $request_uri ==="
done
