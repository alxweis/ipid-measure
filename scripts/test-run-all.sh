#!/usr/bin/env bash
set -euo pipefail

source_script=$(cd "$(dirname "$0")" && pwd)/run-all.sh
test_parent=$(cd "${TMPDIR:-/tmp}" && pwd)
test_root=$(mktemp -d "$test_parent/ipid-run-all-test.XXXXXXXX")
[[ $test_root == "$test_parent"/ipid-run-all-test.* ]]
trap 'rm -rf -- "$test_root"' EXIT

mkdir -p "$test_root/scripts" "$test_root/bin"
cp "$source_script" "$test_root/scripts/run-all.sh"
cat > "$test_root/bin/mock" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
value() {
    local key=$1
    shift
    while [[ $# -gt 0 ]]; do
        if [[ $1 == "$key" ]]; then printf '%s\n' "$2"; return; fi
        shift
    done
}
fail() { echo "$*" >&2; exit 1; }
id=$(value --zmap "$@")
sample="$PWD/zmap/raw/$id/zmap-fixed-base-sample.pq"
connection="$PWD/zmap/raw/$id/zmap-connection-sample.pq"
case "$(basename "$0")" in
    measure-zmap)
        printf '%s\n' "$*" >> zmap-calls
        payload=$(value --payload "$@")
        case "$payload" in icmp) prefix=icmp ;; tcp) prefix=tcp-80 ;; udp-dns) prefix=udp-dns-53 ;; *) fail "invalid discovery payload" ;; esac
        run="${prefix}_${TEST_STAMP:?}"
        mkdir -p "zmap/raw/$run"
        printf 'fixture\n' > "zmap/raw/$run/zmap.pq"
        printf 'fixture\n' > "zmap/raw/$run/zmap.snapshot.yaml"
        printf '%s\n' "$run"
        ;;
    measure-os)
        [[ $(value --config "$@") == config/os.yaml ]] || fail "OS config not selected"
        for arg in "$@"; do
            case "$arg" in
                --zgrab2-senders|--dns-chaos-workers|--snmp-workers|--connect-timeout|--read-timeout|--dns-chaos-timeout|--snmp-timeout)
                    fail "OS configuration silently overridden: $arg" ;;
            esac
        done
        run="${id%_*}_11-00-00"
        mkdir -p "os/raw/$run"
        printf 'fixture\n' > "os/raw/$run/os.pq"
        printf 'zmap: %s\n' "$id" > "os/raw/$run/os.snapshot.yaml"
        printf '{}\n' > "os/raw/$run/os-coverage.json"
        printf '%s\n' "$run" >> os-calls
        printf '%s\n' "$run"
        ;;
    sample-zmap)
        [[ $(value --percent "$@") == 10 && $(value --minimum "$@") == 1000000 ]] || fail "wrong sampling rule"
        if [[ -n $(value --reply-type "$@") ]]; then
            [[ $id == tcp-80_* && $(value --reply-type "$@") == synack ]] || fail "wrong connection filter"
            sample=$connection
        fi
        printf 'sample\n' > "$sample"
        printf '%s\n' "$sample"
        ;;
    measure-ipid)
        count=$(cat calls-count)
        count=$((count + 1))
        printf '%s\n' "$count" > calls-count
        run="${id%_*}_$(printf '10-00-%02d' "$count")"
        target=$(value --target-file "$@")
        mode=$(value --measurement_mode "$@")
        requests=$(value --requests_per_connection "$@")
        establish=$(value --tcp.establish_connection "$@")
        expected_workers=
        if [[ $establish == true && $mode == rt-based ]]; then
            expected_workers=${TEST_CONNECTION_RT_WORKERS:-}
        elif [[ $establish == true ]]; then
            expected_workers=${TEST_CONNECTION_FI_WORKERS:-}
        elif [[ $mode == rt-based ]]; then
            expected_workers=${TEST_RT_WORKERS:-}
        else
            expected_workers=${TEST_FI_WORKERS:-}
        fi
        [[ $(value --number_of_inflight_probes "$@") == "$expected_workers" ]] || fail "wrong phase concurrency"
        if [[ $establish == true ]]; then
            [[ $id == tcp-80_* && $target == "$connection" && $requests == 4 ]] || fail "wrong connection targets"
        elif [[ $mode == rt-based ]]; then
            [[ -z $target && $requests == 4 ]] || fail "RT must use all ZMap targets"
            [[ $(value --analysis_workflow.enable "$@") == true ]] || fail "missing RT analysis"
            mkdir -p "ipid/raw/$run"
            touch "ipid/raw/$run/zmap_unclassified.pq"
            printf '%s\n' "$PWD/ipid/raw/$run/zmap_unclassified.pq" > mass-target
        elif [[ $requests == 25 ]]; then
            [[ $(value --fixed_interval.minimum_reply_rate "$@") == 0.8 ]] || fail "wrong Mass reply rate"
            if [[ $(value --analysis_workflow.enable "$@") == true ]]; then
                [[ $target == "$(cat mass-target)" ]] || fail "wrong initial Mass targets"
                [[ $(value --analysis_workflow.maximum_targets "$@") == 10000 ]] || fail "wrong reproducibility cap"
                [[ $(value --analysis_workflow.selection_seed "$@") == 42 ]] || fail "wrong reproducibility seed"
                mkdir -p "ipid/raw/$run"
                touch "ipid/raw/$run/random-reproducibility-targets.pq"
                printf '%s\n' "$PWD/ipid/raw/$run/random-reproducibility-targets.pq" > reproducibility-target
            else
                [[ $target == "$(cat reproducibility-target)" ]] || fail "wrong reproducibility targets"
            fi
        else
            [[ $target == "$sample" && -f $sample && $requests == 4 ]] || fail "FI Base must use its sample"
        fi
        if [[ $mode == fixed-interval && $requests == 4 ]]; then
            [[ $(value --fixed_interval.minimum_reply_rate "$@") == 1.0 ]] || fail "Base must require all replies"
        fi
        printf '%s\n' "$run"
        ;;
    publish-analysis-job)
        if [[ " $* " == *" --record-os-policy "* ]]; then
            mode=requested
            [[ " $* " != *" --skip-os "* ]] || mode=not_requested
            policy="analysis-jobs/$id/test-os-policy"
            if [[ -f $policy ]]; then
                [[ $(cat "$policy") == "$mode" ]] || fail "OS mode changed on restart"
            else
                mkdir -p "$(dirname "$policy")"
                printf '%s\n' "$mode" > "$policy"
            fi
            printf '%s\n' "$*" >> policy-calls
            exit 0
        fi
        if [[ " $* " == *" --skip-os "* ]]; then
            [[ -z $(value --os "$@") ]] || fail "disabled OS has a fabricated measurement ID"
        else
            [[ -n $(value --os "$@") ]] || fail "default OS measurement missing"
        fi
        [[ $(value --fixed-base-target "$@") == "$sample" ]] || fail "sample missing from analysis job"
        if [[ $id == tcp-80_* ]]; then
            [[ $(value --connection-target "$@") == "$connection" ]] || fail "connection sample missing"
        else
            [[ -z $(value --connection-target "$@") ]] || fail "unexpected connection sample"
        fi
        repeats=$(value --random-reproducibility-repeats "$@")
        [[ $(awk -F, '{print NF}' <<< "$repeats") == 5 ]] || fail "expected five reproducibility repeats"
        [[ $(value --random-reproducibility-maximum-targets "$@") == 10000 ]] || fail "missing reproducibility cap"
        [[ $(value --random-reproducibility-selection-seed "$@") == 42 ]] || fail "missing reproducibility seed"
        printf 'published\n' > published
        printf 's3://test/request.json\n'
        ;;
esac
MOCK
for tool in sample-zmap measure-ipid publish-analysis-job measure-zmap measure-os; do
    cp "$test_root/bin/mock" "$test_root/bin/$tool"
    chmod +x "$test_root/bin/$tool"
done

for protocol in icmp tcp udp; do
    case "$protocol" in icmp) prefix=icmp ;; tcp) prefix=tcp-80 ;; udp) prefix=udp-dns-53 ;; esac
    id="${prefix}_2026-09-22_09-00-00"
    mkdir -p "$test_root/zmap/raw/$id" "$test_root/os/raw/$id"
    printf 'fixture\n' > "$test_root/zmap/raw/$id/zmap.pq"
    printf 'fixture\n' > "$test_root/zmap/raw/$id/zmap.snapshot.yaml"
    printf 'fixture\n' > "$test_root/os/raw/$id/os.pq"
    printf 'zmap: %s\n' "$id" > "$test_root/os/raw/$id/os.snapshot.yaml"
    printf '{}\n' > "$test_root/os/raw/$id/os-coverage.json"
    printf '0\n' > "$test_root/calls-count"
    rm -f "$test_root/published"
    bash "$test_root/scripts/run-all.sh" "$protocol" --zmap-id "$id" --os-id "$id" > "$test_root/output"
    expected=8
    [[ $protocol != tcp ]] || expected=10
    [[ $(cat "$test_root/calls-count") == "$expected" && -f "$test_root/published" ]]
    printf '%s sweep passed\n' "$protocol"
done

# Fresh starts exercise the actual default and explicit opt-out, not only resume.
mkdir -p "$test_root/mock-path"
printf '#!/usr/bin/env bash\nexit 0\n' > "$test_root/mock-path/make"
chmod +x "$test_root/mock-path/make"
index=0
for protocol in icmp tcp udp; do
    case "$protocol" in icmp) prefix=icmp ;; tcp) prefix=tcp-80 ;; udp) prefix=udp-dns-53 ;; esac
    for mode in requested not_requested; do
        index=$((index+1))
        stamp="2026-09-23_09-00-0$index"
        args=()
        [[ $mode != not_requested ]] || args+=(--skip-os)
        printf '0\n' > "$test_root/calls-count"
        rm -f "$test_root/published" "$test_root/os-calls"
        TEST_STAMP="$stamp" PATH="$test_root/mock-path:$PATH" bash "$test_root/scripts/run-all.sh" "$protocol" "${args[@]}" > "$test_root/output"
        expected=8
        [[ $protocol != tcp ]] || expected=10
        [[ $(cat "$test_root/calls-count") == "$expected" && -f "$test_root/published" ]]
        if [[ $mode == not_requested ]]; then
            [[ ! -f "$test_root/os-calls" ]]
            grep -q 'not_requested' "$test_root/output"
            # Same mode can resume; accidental mode changes must fail before OS/IPID.
            printf '0\n' > "$test_root/calls-count"
            bash "$test_root/scripts/run-all.sh" "$protocol" --zmap-id "${prefix}_$stamp" --skip-os > "$test_root/output"
            [[ $(cat "$test_root/calls-count") == "$expected" ]]
            printf '0\n' > "$test_root/calls-count"
            if bash "$test_root/scripts/run-all.sh" "$protocol" --zmap-id "${prefix}_$stamp" > "$test_root/output" 2>&1; then
                echo 'mode change unexpectedly succeeded' >&2; exit 1
            fi
            [[ $(cat "$test_root/calls-count") == 0 && ! -f "$test_root/os-calls" ]]
        else
            [[ $(wc -l < "$test_root/os-calls") == 1 ]]
        fi
        printf '%s OS=%s fresh sweep passed\n' "$protocol" "$mode"
    done
done
if bash "$test_root/scripts/run-all.sh" icmp --skip-os --zmap-id icmp_2026-09-22_09-00-00 --os-id icmp_2026-09-22_09-00-00 > "$test_root/output" 2>&1; then
    echo '--skip-os/--os-id conflict unexpectedly succeeded' >&2; exit 1
fi

# A complete TCP sweep must independently route all four resource settings.
printf '0\n' > "$test_root/calls-count"
TEST_STAMP=2026-09-24_09-00-00 TEST_RT_WORKERS=5000 TEST_FI_WORKERS=2000 \
TEST_CONNECTION_RT_WORKERS=3000 TEST_CONNECTION_FI_WORKERS=1000 \
PATH="$test_root/mock-path:$PATH" bash "$test_root/scripts/run-all.sh" tcp \
    --rt-inflight-probes 5K --fi-inflight-probes 2000 \
    --connection-rt-inflight-probes 3k --connection-fi-inflight-probes 1000 \
    > "$test_root/output"
[[ $(cat "$test_root/calls-count") == 10 ]]

# Omitted FI/connection settings keep config rather than inheriting RT tuning.
printf '0\n' > "$test_root/calls-count"
TEST_STAMP=2026-09-24_09-00-01 TEST_RT_WORKERS=4000 \
PATH="$test_root/mock-path:$PATH" bash "$test_root/scripts/run-all.sh" tcp \
    --rt-inflight-probes 4K > "$test_root/output"
[[ $(cat "$test_root/calls-count") == 10 ]]

# All phases are validated before discovery, even when not selected for ICMP.
for invalid in 0 -1 1000001 10000000 2M NaN 9999999K ''; do
    printf '0\n' > "$test_root/calls-count"
    rm -f "$test_root/zmap-calls"
    if PATH="$test_root/mock-path:$PATH" bash "$test_root/scripts/run-all.sh" icmp \
        --connection-fi-inflight-probes "$invalid" > "$test_root/output" 2>&1; then
        echo "accepted invalid worker count: $invalid" >&2; exit 1
    fi
    [[ ! -f "$test_root/zmap-calls" && $(cat "$test_root/calls-count") == 0 ]]
done
if bash "$test_root/scripts/run-all.sh" icmp --rt-inflight-probes > "$test_root/output" 2>&1; then
    echo 'accepted missing worker count' >&2; exit 1
fi
printf 'phase-specific concurrency and OS config preservation passed\n'
