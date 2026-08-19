#!/usr/bin/env bash
# WP-03 correctness gate: spawn ReleaseFast floos/flooc on ephemeral ports and
# check TCP forward/reverse, UDP /udp, rapid connect/close, and bad-PSK fail-closed.
# Tracks only PIDs this script started — never pkill by name.
set -euo pipefail

fatal() {
    echo "fatal: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fatal "Required command '$1' not found in PATH"
}

# Prefer an explicit ZIG, then a 0.16 install (this repo's minimum), then PATH zig.
resolve_zig() {
    if [[ -n "${ZIG:-}" && -x "${ZIG}" ]]; then
        echo "${ZIG}"
        return
    fi
    local candidate
    for candidate in \
        "${HOME}/.zvm/0.16.0/zig" \
        "${HOME}/.zvm/bin/zig" \
        "$(command -v zig 2>/dev/null || true)"; do
        if [[ -n "${candidate}" && -x "${candidate}" ]]; then
            echo "${candidate}"
            return
        fi
    done
    return 1
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FLOO_BIN_DIR="${FLOO_BIN_DIR:-${ROOT_DIR}/zig-out/bin}"
WORKDIR="$(mktemp -d /tmp/floo-e2e.XXXXXX)"
LOG_DIR="${WORKDIR}/logs"
mkdir -p "${LOG_DIR}"

# Must pass config.validateSecurity (>=16 chars, >=8 distinct, not placeholders).
PSK="floo-e2e-psk-7kQm2nVx"
TOKEN="floo-e2e-token-9pLr"
BAD_PSK="floo-e2e-psk-WRONG-4bHt"
PAYLOAD_BYTES="${FLOO_E2E_BYTES:-4194304}" # 4 MiB
UDP_COUNT=8
RAPID_STREAMS=32

PIDS=()

track() {
    PIDS+=("$1")
}

alive() {
    kill -0 "$1" 2>/dev/null
}

assert_alive() {
    local name=$1
    local pid=$2
    if ! alive "${pid}"; then
        echo "---- ${name} died early (see ${LOG_DIR}) ----" >&2
        tail -n 80 "${LOG_DIR}/${name}.log" 2>/dev/null || true
        fatal "${name} (pid ${pid}) exited unexpectedly"
    fi
}

stop_pid() {
    local pid=$1
    if [[ -n "${pid}" ]] && alive "${pid}"; then
        kill "${pid}" 2>/dev/null || true
        local i
        for ((i = 0; i < 25; i++)); do
            alive "${pid}" || break
            sleep 0.05
        done
        if alive "${pid}"; then
            kill -9 "${pid}" 2>/dev/null || true
        fi
    fi
    wait "${pid}" 2>/dev/null || true
}

cleanup() {
    local i
    for ((i = ${#PIDS[@]} - 1; i >= 0; i--)); do
        stop_pid "${PIDS[$i]}"
    done
}
trap cleanup EXIT INT TERM

pass() { echo "[ok] $*"; }

wait_for_tcp() {
    local host=$1
    local port=$2
    local attempts=${3:-80}
    python3 - "${host}" "${port}" "${attempts}" <<'PY'
import socket, sys, time
host, port, attempts = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for _ in range(attempts):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.25)
    try:
        s.connect((host, port))
        sys.exit(0)
    except OSError:
        time.sleep(0.1)
    finally:
        s.close()
sys.exit(1)
PY
}

wait_for_log() {
    local file=$1
    local pattern=$2
    local attempts=${3:-80}
    local i
    for ((i = 0; i < attempts; i++)); do
        if [[ -f "${file}" ]] && grep -E -q "${pattern}" "${file}"; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

alloc_ports() {
    python3 - <<'PY'
import socket
ports = []
socks = []
for _ in range(8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    ports.append(s.getsockname()[1])
    socks.append(s)
for s in socks:
    s.close()
print(" ".join(str(p) for p in ports))
PY
}

# Floo maps local EOF to a full stream CLOSE (no TCP half-close). Backends
# therefore use a 4-byte big-endian length prefix, read the whole payload,
# then write it back — clients must not SHUT_WR until the echo is done.
start_tcp_echo() {
    local port=$1
    local log=$2
    python3 -u - "${port}" >"${log}" 2>&1 <<'PY' &
import socket, sys, threading

def recvall(conn, n):
    got = bytearray()
    while len(got) < n:
        chunk = conn.recv(min(65536, n - len(got)))
        if not chunk:
            return None
        got.extend(chunk)
    return bytes(got)

port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(128)
srv.settimeout(0.5)
print("ready", flush=True)

def handle(conn):
    try:
        hdr = recvall(conn, 4)
        if not hdr:
            return
        n = int.from_bytes(hdr, "big")
        data = recvall(conn, n)
        if data is None:
            return
        conn.sendall(data)
        # Wait for the client ACK so CLOSE is not sent until the echo
        # has been read (Floo maps EOF to a full stream teardown).
        recvall(conn, 1)
    finally:
        conn.close()

try:
    while True:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
except KeyboardInterrupt:
    pass
finally:
    srv.close()
PY
    track $!
}

start_udp_echo() {
    local port=$1
    local log=$2
    python3 -u - "${port}" >"${log}" 2>&1 <<'PY' &
import socket, sys
port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.settimeout(0.5)
print("ready", flush=True)
try:
    while True:
        try:
            data, addr = srv.recvfrom(65536)
        except socket.timeout:
            continue
        srv.sendto(data, addr)
except KeyboardInterrupt:
    pass
finally:
    srv.close()
PY
    track $!
}

tcp_echo_roundtrip() {
    local host=$1
    local port=$2
    local nbytes=$3
    local label=$4
    python3 - "${host}" "${port}" "${nbytes}" "${WORKDIR}/${label}" <<'PY'
import os, socket, sys
host, port, nbytes, prefix = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
send_path = prefix + ".send"
recv_path = prefix + ".recv"
payload = os.urandom(nbytes)
open(send_path, "wb").write(payload)
s = socket.create_connection((host, port), timeout=15)
s.settimeout(15)

def recvall(n):
    got = bytearray()
    while len(got) < n:
        chunk = s.recv(min(65536, n - len(got)))
        if not chunk:
            break
        got.extend(chunk)
    return bytes(got)

try:
    s.sendall(nbytes.to_bytes(4, "big"))
    view = memoryview(payload)
    sent = 0
    while sent < nbytes:
        sent += s.send(view[sent:])
    got = recvall(nbytes)
    if len(got) == nbytes:
        s.sendall(b"x")
finally:
    s.close()
open(recv_path, "wb").write(got)
if got != payload:
    raise SystemExit(f"byte mismatch: sent {nbytes} recv {len(got)}")
PY
}

tcp_rapid_connects() {
    local host=$1
    local port=$2
    local count=$3
    python3 - "${host}" "${port}" "${count}" <<'PY'
import socket, sys
host, port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for i in range(count):
    msg = f"rapid-{i:03d}\n".encode()
    s = socket.create_connection((host, port), timeout=5)
    s.settimeout(5)
    try:
        s.sendall(len(msg).to_bytes(4, "big") + msg)
        got = bytearray()
        while len(got) < len(msg):
            chunk = s.recv(64)
            if not chunk:
                break
            got.extend(chunk)
        if got == msg:
            s.sendall(b"x")
    finally:
        s.close()
    if got != msg:
        raise SystemExit(f"rapid stream {i} mismatch: {got!r} != {msg!r}")
PY
}

udp_smoke() {
    local host=$1
    local port=$2
    local count=$3
    python3 - "${host}" "${port}" "${count}" <<'PY'
import socket, sys, time
host, port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.5)
try:
    for i in range(count):
        msg = f"udp-e2e-{i}".encode()
        last_err = None
        for _ in range(40):
            s.sendto(msg, (host, port))
            try:
                data, _ = s.recvfrom(4096)
            except socket.timeout as err:
                last_err = err
                time.sleep(0.05)
                continue
            if data != msg:
                raise SystemExit(f"udp datagram {i} mismatch: {data!r} != {msg!r}")
            break
        else:
            raise SystemExit(f"udp datagram {i} timed out: {last_err}")
finally:
    s.close()
PY
}

tcp_should_not_transfer() {
    local host=$1
    local port=$2
    python3 - "${host}" "${port}" <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
payload = b"should-not-pass"
try:
    s = socket.create_connection((host, port), timeout=3)
except OSError:
    sys.exit(0)
s.settimeout(2)
try:
    try:
        s.sendall(payload)
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        got = s.recv(64)
    except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
        sys.exit(0)
finally:
    s.close()
if got:
    raise SystemExit(f"bad-PSK path leaked {len(got)} bytes")
PY
}

write_configs() {
    local server_cfg=$1
    local client_cfg=$2
    local client_listen=$3
    local client_psk=$4
    cat >"${server_cfg}" <<EOF
bind = "127.0.0.1"
port = ${TUNNEL_PORT}
cipher = "aegis128l"
psk = "${PSK}"
token = "${TOKEN}"

[services]
echo = "127.0.0.1:${TCP_FWD_BACKEND}/tcp"
udp_echo = "127.0.0.1:${UDP_BACKEND}/udp"

[reverse_services]
rev_echo = "127.0.0.1:${TCP_REV_PUBLISH}"

[advanced]
pin_threads = false
tcp_nodelay = true
heartbeat_interval_seconds = 30
heartbeat_timeout_seconds = 60
EOF

    cat >"${client_cfg}" <<EOF
server = "127.0.0.1:${TUNNEL_PORT}"
cipher = "aegis128l"
psk = "${client_psk}"
token = "${TOKEN}"

[services]
echo = "127.0.0.1:${client_listen}"
udp_echo = "127.0.0.1:${UDP_LISTEN}/udp"

[reverse_services]
rev_echo = "127.0.0.1:${TCP_REV_BACKEND}"

[advanced]
num_tunnels = 1
pin_threads = false
tcp_nodelay = true
reconnect_enabled = false
heartbeat_timeout_seconds = 60
EOF
}

build_floo() {
    local floos_path="${FLOO_BIN_DIR}/floos"
    local flooc_path="${FLOO_BIN_DIR}/flooc"
    if [[ "${FLOO_SKIP_BUILD:-0}" == "1" && -x "${floos_path}" && -x "${flooc_path}" ]]; then
        return
    fi
    echo "[build] ${ZIG} build -Doptimize=ReleaseFast"
    (cd "${ROOT_DIR}" && "${ZIG}" build -Doptimize=ReleaseFast)
}

ZIG="$(resolve_zig)" || fatal "zig not found (need 0.16.x; set ZIG=...)"
require_cmd python3
build_floo

FLOOS="${FLOO_BIN_DIR}/floos"
FLOOC="${FLOO_BIN_DIR}/flooc"
[[ -x "${FLOOS}" && -x "${FLOOC}" ]] || fatal "ReleaseFast binaries missing under ${FLOO_BIN_DIR}"

read -r TUNNEL_PORT TCP_FWD_LISTEN TCP_FWD_BACKEND TCP_REV_PUBLISH TCP_REV_BACKEND UDP_LISTEN UDP_BACKEND BAD_LISTEN < <(alloc_ports)

echo "[e2e] workdir ${WORKDIR}"
echo "[e2e] tunnel=${TUNNEL_PORT} fwd ${TCP_FWD_LISTEN}->${TCP_FWD_BACKEND} rev ${TCP_REV_PUBLISH}->${TCP_REV_BACKEND} udp ${UDP_LISTEN}->${UDP_BACKEND}"

start_tcp_echo "${TCP_FWD_BACKEND}" "${LOG_DIR}/tcp-echo-fwd.log"
start_tcp_echo "${TCP_REV_BACKEND}" "${LOG_DIR}/tcp-echo-rev.log"
start_udp_echo "${UDP_BACKEND}" "${LOG_DIR}/udp-echo.log"
wait_for_log "${LOG_DIR}/tcp-echo-fwd.log" "^ready$" 40 || fatal "forward TCP echo backend did not bind"
wait_for_log "${LOG_DIR}/tcp-echo-rev.log" "^ready$" 40 || fatal "reverse TCP echo backend did not bind"
wait_for_log "${LOG_DIR}/udp-echo.log" "^ready$" 40 || fatal "UDP echo backend did not bind"

SERVER_CFG="${WORKDIR}/floos.toml"
CLIENT_CFG="${WORKDIR}/flooc.toml"
BAD_CFG="${WORKDIR}/flooc-badpsk.toml"
write_configs "${SERVER_CFG}" "${CLIENT_CFG}" "${TCP_FWD_LISTEN}" "${PSK}"
write_configs "${WORKDIR}/floos-unused.toml" "${BAD_CFG}" "${BAD_LISTEN}" "${BAD_PSK}"

"${FLOOS}" "${SERVER_CFG}" >"${LOG_DIR}/floos.log" 2>&1 &
FLOOS_PID=$!
track "${FLOOS_PID}"
if ! wait_for_log "${LOG_DIR}/floos.log" "\\[SERVER\\] Listening|\\[READY\\] Server ready" 50; then
    tail -n 80 "${LOG_DIR}/floos.log" >&2 || true
    fatal "floos did not listen on ${TUNNEL_PORT}"
fi
assert_alive floos "${FLOOS_PID}"

"${FLOOC}" "${CLIENT_CFG}" >"${LOG_DIR}/flooc.log" 2>&1 &
FLOOC_PID=$!
track "${FLOOC_PID}"

if ! wait_for_log "${LOG_DIR}/flooc.log" "Authentication enabled|Heartbeat timeout enabled" 80; then
    tail -n 80 "${LOG_DIR}/flooc.log" >&2 || true
    tail -n 80 "${LOG_DIR}/floos.log" >&2 || true
    fatal "flooc handshake did not complete"
fi
assert_alive flooc "${FLOOC_PID}"

if ! wait_for_log "${LOG_DIR}/flooc.log" "TCP-SERVICE.*Listening" 50; then
    tail -n 80 "${LOG_DIR}/flooc.log" >&2 || true
    fatal "flooc forward listener ${TCP_FWD_LISTEN} did not open"
fi
if ! wait_for_log "${LOG_DIR}/floos.log" "REVERSE.*Listening" 80; then
    tail -n 80 "${LOG_DIR}/floos.log" >&2 || true
    fatal "floos reverse listener ${TCP_REV_PUBLISH} did not open"
fi
if ! wait_for_log "${LOG_DIR}/flooc.log" "UDP-CLIENT.*Listening|UDP-SERVICE.*ready" 80; then
    tail -n 80 "${LOG_DIR}/flooc.log" >&2 || true
    fatal "flooc UDP /udp listener did not start"
fi

echo "[e2e] TCP forward push/pull ${PAYLOAD_BYTES} bytes"
tcp_echo_roundtrip 127.0.0.1 "${TCP_FWD_LISTEN}" "${PAYLOAD_BYTES}" "fwd" \
    || fatal "TCP forward payload mismatch"
pass "TCP forward byte-identical"

echo "[e2e] TCP reverse push/pull ${PAYLOAD_BYTES} bytes"
tcp_echo_roundtrip 127.0.0.1 "${TCP_REV_PUBLISH}" "${PAYLOAD_BYTES}" "rev" \
    || fatal "TCP reverse payload mismatch"
pass "TCP reverse byte-identical"

echo "[e2e] UDP /udp smoke (${UDP_COUNT} datagrams)"
udp_smoke 127.0.0.1 "${UDP_LISTEN}" "${UDP_COUNT}" \
    || fatal "UDP smoke failed"
pass "UDP datagrams echoed"

echo "[e2e] rapid connect/close (${RAPID_STREAMS} streams)"
tcp_rapid_connects 127.0.0.1 "${TCP_FWD_LISTEN}" "${RAPID_STREAMS}" \
    || fatal "rapid connect/close failed"
pass "rapid connect/close"

echo "[e2e] bad-PSK --ping must fail closed"
set +e
"${FLOOC}" --ping "${BAD_CFG}" >"${LOG_DIR}/flooc-ping-bad.log" 2>&1
PING_STATUS=$?
set -e
if [[ "${PING_STATUS}" -eq 0 ]]; then
    cat "${LOG_DIR}/flooc-ping-bad.log" >&2
    fatal "flooc --ping succeeded with the wrong PSK"
fi
if ! grep -E -q "fail|AuthenticationFailed|HandshakeFailed|Connection attempt failed" "${LOG_DIR}/flooc-ping-bad.log"; then
    cat "${LOG_DIR}/flooc-ping-bad.log" >&2
    fatal "flooc --ping failed but did not report a handshake/auth error"
fi
pass "bad-PSK --ping failed closed (exit ${PING_STATUS})"

echo "[e2e] bad-PSK client must not transfer"
"${FLOOC}" "${BAD_CFG}" >"${LOG_DIR}/flooc-badpsk.log" 2>&1 &
BAD_PID=$!
track "${BAD_PID}"
# Listener may bind before handshake; wait for either bind or a failed create.
wait_for_log "${LOG_DIR}/flooc-badpsk.log" "TCP-SERVICE.*Listening|Failed to create client|AuthenticationFailed|HandshakeFailed" 50 || true
sleep 0.2
if wait_for_tcp 127.0.0.1 "${BAD_LISTEN}" 10; then
    tcp_should_not_transfer 127.0.0.1 "${BAD_LISTEN}" \
        || fatal "bad-PSK client forwarded traffic"
fi
if grep -E -q "Authentication enabled" "${LOG_DIR}/flooc-badpsk.log"; then
    cat "${LOG_DIR}/flooc-badpsk.log" >&2
    fatal "bad-PSK client completed handshake"
fi
pass "bad-PSK client did not complete handshake or leak bytes"

assert_alive floos "${FLOOS_PID}"
assert_alive flooc "${FLOOC_PID}"

echo
echo "[e2e] all checks passed"
echo "[e2e] artifacts: ${WORKDIR}"
