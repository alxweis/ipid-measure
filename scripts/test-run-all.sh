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
        if [[ $establish == true ]]; then
            [[ $id == tcp-80_* && $target == "$connection" && $requests == 4 ]] || fail "wrong connection targets"
        elif [[ $mode == rt-based ]]; then
            [[ -z $target && $requests == 4 ]] || fail "RT must use all ZMap targets"
            [[ $(value --analysis_workflow.enable "$@") == true ]] || fail "missing RT analysis"
            mkdir -p "ipid/raw/$run"
            touch "ipid/raw/$run/zmap_unclassified.pq"
            printf '%s\n' "$PWD/ipid/raw/$run/zmap_unclassified.pq" > mass-target
        elif [[ $requests == 25 ]]; then
            [[ $target == "$(cat mass-target)" ]] || fail "wrong Mass targets"
            [[ $(value --fixed_interval.minimum_reply_rate "$@") == 0.8 ]] || fail "wrong Mass reply rate"
        else
            [[ $target == "$sample" && -f $sample && $requests == 4 ]] || fail "FI Base must use its sample"
        fi
        if [[ $mode == fixed-interval && $requests == 4 ]]; then
            [[ $(value --fixed_interval.minimum_reply_rate "$@") == 1.0 ]] || fail "Base must require all replies"
        fi
        printf '%s\n' "$run"
        ;;
    publish-analysis-job)
        [[ $(value --fixed-base-target "$@") == "$sample" ]] || fail "sample missing from analysis job"
        if [[ $id == tcp-80_* ]]; then
            [[ $(value --connection-target "$@") == "$connection" ]] || fail "connection sample missing"
        else
            [[ -z $(value --connection-target "$@") ]] || fail "unexpected connection sample"
        fi
        printf 'published\n' > published
        printf 's3://test/request.json\n'
        ;;
esac
MOCK
for tool in sample-zmap measure-ipid publish-analysis-job; do
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
    expected=3
    [[ $protocol != tcp ]] || expected=5
    [[ $(cat "$test_root/calls-count") == "$expected" && -f "$test_root/published" ]]
    printf '%s sweep passed\n' "$protocol"
done
