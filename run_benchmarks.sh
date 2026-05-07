#!/bin/bash
# Comprehensive benchmark suite: raw loopback, Floo plaintext/encrypted (all ciphers), frp, rathole
set -euo pipefail

usage() {
    echo "Usage: $0 [-t duration_seconds] [-P streams]" >&2
    exit 1
}

fatal() {
    echo "fatal: $*" >&2
    exit 1
}

require_cmd() {
    local cmd=$1
    command -v "${cmd}" >/dev/null 2>&1 || fatal "Required command '${cmd}' not found in PATH"
}

STREAMS=${FLOO_STREAMS:-4}
DURATION=${FLOO_DURATION:-3}
# Auto-detect parallel tunnels if not provided
CPU_COUNT=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
NUM_TUNNELS=${FLOO_TUNNELS:-$CPU_COUNT}
if (( NUM_TUNNELS > 64 )); then
    NUM_TUNNELS=64
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLOO_BIN_DIR=${FLOO_BIN_DIR:-"${ROOT_DIR}/zig-out/bin"}

if [[ -n "${FLOO_BENCH_DIR:-}" ]]; then
    WORKDIR="${FLOO_BENCH_DIR}"
    CLEAN_WORKDIR=0
else
    WORKDIR="$(mktemp -d /tmp/floo-bench.XXXXXX)"
    CLEAN_WORKDIR=1
fi
LOG_DIR="${WORKDIR}/logs"
mkdir -p "${LOG_DIR}"
SUMMARY_FILE="${WORKDIR}/summary.tsv"
RESULT_FILE="${WORKDIR}/results.tsv"
: > "${RESULT_FILE}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--time)
            shift || usage
            DURATION=$1
            ;;
        -P|--streams)
            shift || usage
            STREAMS=$1
            ;;
        -h|--help)
            usage
            ;;
        *)
            usage
            ;;
    esac
    shift
done

if ! [[ "${DURATION}" =~ ^[0-9]+$ ]] || ! [[ "${STREAMS}" =~ ^[0-9]+$ ]]; then
    echo "Duration and streams must be positive integers." >&2
    exit 1
fi

require_cmd iperf3
require_cmd awk
require_cmd pkill
require_cmd zig

build_floo() {
    local floos_path="${FLOO_BIN_DIR}/floos"
    local flooc_path="${FLOO_BIN_DIR}/flooc"
    if [[ "${FLOO_SKIP_BUILD:-0}" == "1" && -x "${floos_path}" && -x "${flooc_path}" ]]; then
        return
    fi
    if [[ ! -x "${floos_path}" || ! -x "${flooc_path}" ]]; then
        echo "[build] Compiling Floo binaries (ReleaseFast)"
        (cd "${ROOT_DIR}" && zig build -Doptimize=ReleaseFast) >/dev/null
        return
    fi
    if [[ "${FLOO_SKIP_BUILD:-0}" != "1" ]]; then
        echo "[build] Refreshing Floo binaries (ReleaseFast)"
        (cd "${ROOT_DIR}" && zig build -Doptimize=ReleaseFast) >/dev/null
    fi
}

PSK="benchmark-test-key"
TOKEN="floo-bench-token"
build_floo

cleanup() {
    pkill -f "floos|flooc|rathole|frps|frpc|iperf3" 2>/dev/null || true
    if [[ ${CLEAN_WORKDIR} -eq 1 ]]; then
        rm -rf "${WORKDIR}"
    fi
}

ensure_idle() {
    pkill -f "floos|flooc|rathole|frps|frpc|iperf3" 2>/dev/null || true
    sleep 1
}

wait_for_port() {
    local host=$1
    local port=$2
    local attempts=${3:-50}
    local delay=${4:-0.2}

    if ! command -v nc >/dev/null 2>&1; then
        # Fallback: rely on fixed wait if nc is unavailable
        sleep 1
        return 0
    fi

    local i
    for ((i = 0; i < attempts; i++)); do
        if nc -z "${host}" "${port}" 2>/dev/null; then
            return 0
        fi
        sleep "${delay}"
    done
    return 1
}

record_result() {
    local key=$1
    local value=$2
    printf "%s\t%s\n" "${key}" "${value}" >> "${RESULT_FILE}"
}

run_iperf() {
    local name=$1
    local port=$2
    local streams=${3:-${STREAMS}}
    local outfile="${LOG_DIR}/iperf_${name}.log"

    set +e
    iperf3 -c 127.0.0.1 -p "${port}" -P "${streams}" -t "${DURATION}" > "${outfile}" 2>&1
    local status=$?
    set -e

    if [[ $status -ne 0 ]]; then
        record_result "$name" "error (iperf)"
        echo "[${name}] iperf3 failed (see ${outfile})"
        return 1
    fi

    local line
    if [[ "${streams}" -eq 1 ]]; then
        line=$(grep -E "Gbits/sec" "${outfile}" | tail -1 || true)
    else
        line=$(grep "SUM" "${outfile}" | tail -1 || true)
        if [[ -z "${line}" ]]; then
            line=$(grep -E "Gbits/sec" "${outfile}" | tail -1 || true)
        fi
    fi
    if [[ -z "${line}" ]]; then
        # Single-stream runs omit the SUM row; fall back to the last throughput line.
        line=$(grep -E "Gbits/sec" "${outfile}" | tail -1 || true)
    fi
    if [[ -z "${line}" ]]; then
        record_result "$name" "error (parse)"
        echo "[${name}] unable to parse iperf result (see ${outfile})"
        return 1
    fi

    local rate unit role
    rate=$(echo "${line}" | awk '{print $(NF-2)}')
    unit=$(echo "${line}" | awk '{print $(NF-1)}')
    role=$(echo "${line}" | awk '{print $NF}')
    record_result "$name" "${rate} ${unit} (${role})"
    echo "[${name}] ${rate} ${unit} (${role})"
}

start_iperf_server() {
    local port=$1
    iperf3 -s -p "${port}" > "${LOG_DIR}/iperf_server_${port}.log" 2>&1 &
    echo $!
}

stop_iperf_server() {
    local pid=$1
    if [[ -n "${pid}" ]]; then
        kill "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    fi
}

run_raw() {
    local name="raw-loopback"
    ensure_idle
    local iperf_pid
    iperf_pid=$(start_iperf_server 9000)
    sleep 1
    run_iperf "${name}" 9000 1 || true
    stop_iperf_server "${iperf_pid}"
}

write_floo_configs() {
    local cipher=$1
    local floo_mode=$2 # plaintext or ciphered
    local server_cfg=$3
    local client_cfg=$4

    local cipher_value="${cipher}"
    local psk_value="${PSK}"
    if [[ "${floo_mode}" == "plaintext" ]]; then
        cipher_value="none"
        # cipher=none still requires a PSK post-S-1 (mutual-auth proof-of-knowledge
        # runs in plaintext mode too).  Reuse the same PSK as the encrypted runs.
    fi

    # New config format for server
    cat > "${server_cfg}" <<EOF
bind = "0.0.0.0"
port = 8000
cipher = "${cipher_value}"
psk = "${psk_value}"
token = "${TOKEN}"

[services]
benchmark = "127.0.0.1:9000"

[advanced]
tcp_nodelay = true
socket_buffer_size = 8388608  # 8MB buffer for high throughput
heartbeat_interval_seconds = 30
EOF

    # New config format for client
    cat > "${client_cfg}" <<EOF
server = "127.0.0.1:8000"
cipher = "${cipher_value}"
psk = "${psk_value}"
token = "${TOKEN}"

[services]
benchmark = "127.0.0.1:9001"

[advanced]
num_tunnels = ${NUM_TUNNELS}
tcp_nodelay = true
socket_buffer_size = 8388608  # 8MB buffer for high throughput
heartbeat_timeout_seconds = 60
reconnect_enabled = false
EOF
}

write_floo_reverse_configs() {
    local cipher=$1
    local floo_mode=$2 # plaintext or ciphered
    local server_cfg=$3
    local client_cfg=$4

    local cipher_value="${cipher}"
    local psk_value="${PSK}"
    if [[ "${floo_mode}" == "plaintext" ]]; then
        cipher_value="none"
        # cipher=none still requires a PSK post-S-1 (mutual-auth proof-of-knowledge
        # runs in plaintext mode too).  Reuse the same PSK as the encrypted runs.
    fi

    # Server config for reverse mode
    cat > "${server_cfg}" <<EOF
bind = "0.0.0.0"
port = 8000
cipher = "${cipher_value}"
psk = "${psk_value}"
token = "${TOKEN}"

[reverse_services]
benchmark = "0.0.0.0:9002"

[advanced]
tcp_nodelay = true
socket_buffer_size = 8388608  # 8MB buffer for high throughput
heartbeat_interval_seconds = 30
EOF

    # Client config for reverse mode
    cat > "${client_cfg}" <<EOF
server = "127.0.0.1:8000"
cipher = "${cipher_value}"
psk = "${psk_value}"
token = "${TOKEN}"

[reverse_services]
benchmark = "127.0.0.1:9000"

[advanced]
num_tunnels = ${NUM_TUNNELS}
tcp_nodelay = true
socket_buffer_size = 8388608  # 8MB buffer for high throughput
heartbeat_timeout_seconds = 60
reconnect_enabled = false
EOF
}

run_floo() {
    local cipher=$1
    local mode=$2
    local label=$3

    ensure_idle
    local iperf_pid
    iperf_pid=$(start_iperf_server 9000)

    local server_cfg="${WORKDIR}/floos_${label}.toml"
    local client_cfg="${WORKDIR}/flooc_${label}.toml"
    write_floo_configs "${cipher}" "${mode}" "${server_cfg}" "${client_cfg}"

    "${FLOO_BIN_DIR}/floos" "${server_cfg}" > "${LOG_DIR}/floos_${label}.log" 2>&1 &
    local floos_pid=$!
    sleep 1

    "${FLOO_BIN_DIR}/flooc" "${client_cfg}" > "${LOG_DIR}/flooc_${label}.log" 2>&1 &
    local flooc_pid=$!
    if ! wait_for_port 127.0.0.1 9001 100 0.2; then
        record_result "floo-${label}" "error (tunnel init)"
        echo "[floo-${label}] tunnel failed to open port 9001"
        stop_iperf_server "${iperf_pid}"
        kill "${flooc_pid}" "${floos_pid}" 2>/dev/null || true
        wait "${flooc_pid}" 2>/dev/null || true
        wait "${floos_pid}" 2>/dev/null || true
        return
    fi

    run_iperf "floo-${label}" 9001 || true

    stop_iperf_server "${iperf_pid}"
    kill "${flooc_pid}" "${floos_pid}" 2>/dev/null || true
    wait "${flooc_pid}" 2>/dev/null || true
    wait "${floos_pid}" 2>/dev/null || true
}

run_floo_reverse() {
    local cipher=$1
    local mode=$2
    local label=$3

    ensure_idle
    local iperf_pid
    iperf_pid=$(start_iperf_server 9000)

    local server_cfg="${WORKDIR}/floos_reverse_${label}.toml"
    local client_cfg="${WORKDIR}/flooc_reverse_${label}.toml"
    write_floo_reverse_configs "${cipher}" "${mode}" "${server_cfg}" "${client_cfg}"

    "${FLOO_BIN_DIR}/floos" "${server_cfg}" > "${LOG_DIR}/floos_reverse_${label}.log" 2>&1 &
    local floos_pid=$!
    sleep 1

    "${FLOO_BIN_DIR}/flooc" "${client_cfg}" > "${LOG_DIR}/flooc_reverse_${label}.log" 2>&1 &
    local flooc_pid=$!
    if ! wait_for_port 127.0.0.1 9002 100 0.2; then
        record_result "floo-reverse-${label}" "error (tunnel init)"
        echo "[floo-reverse-${label}] tunnel failed to expose port 9002"
        stop_iperf_server "${iperf_pid}"
        kill "${flooc_pid}" "${floos_pid}" 2>/dev/null || true
        wait "${flooc_pid}" 2>/dev/null || true
        wait "${floos_pid}" 2>/dev/null || true
        return
    fi

    run_iperf "floo-reverse-${label}" 9002 || true

    stop_iperf_server "${iperf_pid}"
    kill "${flooc_pid}" "${floos_pid}" 2>/dev/null || true
    wait "${flooc_pid}" 2>/dev/null || true
    wait "${floos_pid}" 2>/dev/null || true
}

run_rathole() {
    local name="rathole"
    if ! command -v rathole >/dev/null 2>&1; then
        record_result "${name}" "missing (rathole)"
        echo "[${name}] skipped: rathole binary not found in PATH"
        return
    fi
    ensure_idle
    local iperf_pid
    iperf_pid=$(start_iperf_server 9000)

    local server_cfg="${WORKDIR}/rathole_server.toml"
    local client_cfg="${WORKDIR}/rathole_client.toml"

    cat > "${server_cfg}" <<EOF
[server]
bind_addr = "127.0.0.1:7200"

[server.services.iperf]
bind_addr = "127.0.0.1:9100"
token = "${TOKEN}"
EOF

    cat > "${client_cfg}" <<EOF
[client]
remote_addr = "127.0.0.1:7200"

[client.services.iperf]
local_addr = "127.0.0.1:9000"
token = "${TOKEN}"
EOF

    rathole --server "${server_cfg}" > "${LOG_DIR}/rathole_server.log" 2>&1 &
    local rathole_server_pid=$!
    sleep 1

    rathole --client "${client_cfg}" > "${LOG_DIR}/rathole_client.log" 2>&1 &
    local rathole_client_pid=$!
    sleep 2

    run_iperf "${name}" 9100 || true

    stop_iperf_server "${iperf_pid}"
    kill "${rathole_client_pid}" "${rathole_server_pid}" 2>/dev/null || true
    wait "${rathole_client_pid}" 2>/dev/null || true
    wait "${rathole_server_pid}" 2>/dev/null || true
}

run_frp() {
    local name="frp"

    if ! command -v frps >/dev/null 2>&1; then
        record_result "${name}" "missing (frps)"
        echo "[${name}] skipped: frps not found in PATH"
        return
    fi
    if ! command -v frpc >/dev/null 2>&1; then
        record_result "${name}" "missing (frpc)"
        echo "[${name}] skipped: frpc not found in PATH"
        return
    fi

    ensure_idle
    local iperf_pid
    iperf_pid=$(start_iperf_server 9000)

    local frps_cfg="${WORKDIR}/frps.ini"
    local frpc_cfg="${WORKDIR}/frpc.ini"

    cat > "${frps_cfg}" <<EOF
[common]
bind_port = 7200
token = ${TOKEN}
log_file = /tmp/frps.log
log_level = warn
EOF

    cat > "${frpc_cfg}" <<EOF
[common]
server_addr = 127.0.0.1
server_port = 7200
token = ${TOKEN}

[iperf]
type = tcp
local_ip = 127.0.0.1
local_port = 9000
remote_port = 9100
EOF

    frps -c "${frps_cfg}" > "${LOG_DIR}/frps_benchmark.log" 2>&1 &
    local frps_pid=$!
    if ! wait_for_port 127.0.0.1 7200; then
        record_result "${name}" "error (frps)"
        echo "[${name}] frps failed to open port 7200"
        stop_iperf_server "${iperf_pid}"
        kill "${frps_pid}" 2>/dev/null || true
        wait "${frps_pid}" 2>/dev/null || true
        return
    fi

    frpc -c "${frpc_cfg}" > "${LOG_DIR}/frpc_benchmark.log" 2>&1 &
    local frpc_pid=$!
    if ! wait_for_port 127.0.0.1 9100; then
        record_result "${name}" "error (frpc)"
        echo "[${name}] frpc failed to expose port 9100"
        stop_iperf_server "${iperf_pid}"
        kill "${frpc_pid}" "${frps_pid}" 2>/dev/null || true
        wait "${frpc_pid}" 2>/dev/null || true
        wait "${frps_pid}" 2>/dev/null || true
        return
    fi

    run_iperf "${name}" 9100 || true

    stop_iperf_server "${iperf_pid}"
    kill "${frpc_pid}" "${frps_pid}" 2>/dev/null || true
    wait "${frpc_pid}" 2>/dev/null || true
    wait "${frps_pid}" 2>/dev/null || true
}

trap cleanup EXIT

echo "Running benchmarks (duration=${DURATION}s, streams=${STREAMS})..."
echo ""

# Raw loopback baseline
echo "=== Testing raw loopback ==="
run_raw

# Forward mode benchmarks
echo ""
echo "=== Testing forward mode ==="
declare -a FLOO_TEST_MATRIX=(
    "none:plaintext:plaintext"
    "chacha20poly1305:encrypted:chacha20"
    "aes256gcm:encrypted:aes256gcm"
    "aes128gcm:encrypted:aes128gcm"
    "aegis128l:encrypted:aegis128l"
    "aegis256:encrypted:aegis256"
)

for spec in "${FLOO_TEST_MATRIX[@]}"; do
    IFS=":" read -r cipher mode label <<< "${spec}"
    run_floo "${cipher}" "${mode}" "${label}"
done

# Reverse mode benchmarks
echo ""
echo "=== Testing reverse mode ==="
for spec in "${FLOO_TEST_MATRIX[@]}"; do
    IFS=":" read -r cipher mode label <<< "${spec}"
    run_floo_reverse "${cipher}" "${mode}" "${label}"
done

# Competing solutions
echo ""
echo "=== Testing competing solutions ==="
run_frp
run_rathole

: > "${SUMMARY_FILE}"
printf "%-25s\t%s\n" "Benchmark" "Throughput" | tee -a "${SUMMARY_FILE}"
printf "%-25s\t%s\n" "---------" "----------" | tee -a "${SUMMARY_FILE}"

lookup_result() {
    local key=$1
    local value
    value=$(awk -F'\t' -v k="$key" '$1==k {print $2}' "${RESULT_FILE}" | tail -1)
    if [[ -z "${value}" ]]; then
        echo "n/a"
    else
        echo "${value}"
    fi
}

# Print results grouped by category
echo "Forward Mode:" | tee -a "${SUMMARY_FILE}"
for key in raw-loopback floo-plaintext floo-chacha20 floo-aes256gcm floo-aes128gcm floo-aegis128l floo-aegis256; do
    printf "  %-23s\t%s\n" "${key}" "$(lookup_result "${key}")" | tee -a "${SUMMARY_FILE}"
done

echo "" | tee -a "${SUMMARY_FILE}"
echo "Reverse Mode:" | tee -a "${SUMMARY_FILE}"
for key in floo-reverse-plaintext floo-reverse-chacha20 floo-reverse-aes256gcm floo-reverse-aes128gcm floo-reverse-aegis128l floo-reverse-aegis256; do
    printf "  %-23s\t%s\n" "${key}" "$(lookup_result "${key}")" | tee -a "${SUMMARY_FILE}"
done

echo "" | tee -a "${SUMMARY_FILE}"
echo "Other Solutions:" | tee -a "${SUMMARY_FILE}"
for key in frp rathole; do
    printf "  %-23s\t%s\n" "${key}" "$(lookup_result "${key}")" | tee -a "${SUMMARY_FILE}"
done

echo ""
echo "Artifacts saved under ${WORKDIR}"
echo "  - iperf logs: ${LOG_DIR}"
echo "  - summary: ${SUMMARY_FILE}"
