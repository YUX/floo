#!/bin/bash
# Isolation bench matrix for the Floo 0.3 data path.
#
# Defaults: ReleaseFast, 5s trials, 2 repeats, receiver-side SUM.
# Artifacts: $FLOO_BENCH_DIR (default /tmp/floo-bench-0.3) as TSV + JSON.
# Baseline:  --write-baseline (after a run) or --export-baseline (from existing results).
#
# PID policy: this script records every process it starts and signals only those
# PIDs. It never runs pkill / killall / pgrep against iperf3, floos, or flooc.
#
# Config writers follow run_benchmarks.sh (TOML shape, PSK-required cipher=none,
# /udp service suffix). SIGUSR1 dumps use diagnostics.flushEncryptStats lines.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/perf_matrix.sh [options]

  Isolation matrix (ReleaseFast, receiver-side SUM). Writes TSV + JSON under
  FLOO_BENCH_DIR (default /tmp/floo-bench-0.3). Tracks only its own PIDs.

Options:
  -t, --time SEC          Trial duration in seconds (default: 5)
  -r, --repeats N         Repeats per cell (default: 2)
  --ciphers LIST          Comma-separated ciphers
  --lengths LIST          Comma-separated iperf3 -l values (default: 8K,128K,1M)
  --streams LIST          Comma-separated iperf3 -P values (default: 1,4,16)
  --tunnels LIST          Comma-separated tunnel counts; "auto" = CPU count
                          (default: 1,auto)
  --narrow-ciphers LIST   Reverse-mode cipher set (default: none,aes128gcm)
  --skip-build            Do not rebuild (use existing zig-out/bin)
  --smoke                 Tiny subset: 1s, 1 repeat, one cipher / -l / -P / tunnel
  --skip-reverse          Do not run reverse-mode cells
  --skip-udp              Do not run the UDP cell
  --skip-profile          Do not run FLOO_PROFILE_ENCRYPT dumps
  --list                  Print planned cells and exit
  --write-baseline        After a successful run, write bench/baseline.json
  --export-baseline [JSON]
                          Do not run. Build bench/baseline.json from results.json
                          (default: $FLOO_BENCH_DIR/results.json)
  --baseline-path PATH    Destination for baseline.json (default: bench/baseline.json)
  -h, --help              Show this help

Environment:
  FLOO_BENCH_DIR          Artifact directory (default: /tmp/floo-bench-0.3)
  FLOO_BIN_DIR            Binary directory (default: <repo>/zig-out/bin)
  FLOO_SKIP_BUILD=1       Same as --skip-build
  FLOO_DURATION / FLOO_REPEATS
  FLOO_WRITE_BASELINE=1   Same as --write-baseline
  FLOO_BASELINE_PATH      Same as --baseline-path
  FLOO_UDP_BANDWIDTH      iperf3 -b for the UDP cell (default: 2G)

  After a completed run:
  ./scripts/perf_matrix.sh --export-baseline
  ./scripts/perf_matrix.sh --export-baseline /tmp/floo-bench-0.3/results.json
  FLOO_WRITE_BASELINE=1 ./scripts/perf_matrix.sh

Examples:
  ./scripts/perf_matrix.sh
  ./scripts/perf_matrix.sh --write-baseline
  ./scripts/perf_matrix.sh --export-baseline
  ./scripts/perf_matrix.sh --export-baseline /tmp/floo-bench-0.3/results.json
  ./scripts/perf_matrix.sh --list
  ./scripts/perf_matrix.sh --smoke --list
EOF
    exit "${1:-0}"
}

fatal() {
    echo "fatal: $*" >&2
    exit 1
}

require_cmd() {
    local cmd=$1
    command -v "${cmd}" >/dev/null 2>&1 || fatal "Required command '${cmd}' not found in PATH"
}

# --- defaults (plan Phase 2) -------------------------------------------------
DURATION=${FLOO_DURATION:-5}
REPEATS=${FLOO_REPEATS:-2}
OPTIMIZE=ReleaseFast
UDP_BANDWIDTH=${FLOO_UDP_BANDWIDTH:-2G}
UDP_LENGTH=8K
UDP_STREAMS=1
UDP_CIPHER=aes128gcm

CIPHERS_SPEC="none,aes128gcm,aes256gcm,aegis128l,chacha20poly1305"
LENGTHS_SPEC="8K,128K,1M"
STREAMS_SPEC="1,4,16"
TUNNELS_SPEC="1,auto"
NARROW_SPEC="none,aes128gcm"

SKIP_BUILD=${FLOO_SKIP_BUILD:-0}
SKIP_REVERSE=${FLOO_SKIP_REVERSE:-0}
SKIP_UDP=${FLOO_SKIP_UDP:-0}
SKIP_PROFILE=${FLOO_SKIP_PROFILE:-0}
SMOKE=0
LIST_ONLY=0
WRITE_BASELINE=${FLOO_WRITE_BASELINE:-0}
EXPORT_BASELINE=0
EXPORT_SRC=""
DO_RUN=1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FLOO_BIN_DIR=${FLOO_BIN_DIR:-"${ROOT_DIR}/zig-out/bin"}
WORKDIR=${FLOO_BENCH_DIR:-/tmp/floo-bench-0.3}
BASELINE_PATH=${FLOO_BASELINE_PATH:-"${ROOT_DIR}/bench/baseline.json"}

CPU_COUNT=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
if ! [[ "${CPU_COUNT}" =~ ^[0-9]+$ ]] || [[ "${CPU_COUNT}" -lt 1 ]]; then
    CPU_COUNT=4
fi
if (( CPU_COUNT > 64 )); then
    CPU_COUNT=64
fi

PSK="benchmark-test-key"
TOKEN="floo-bench-token"

# --- argv --------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--time)
            shift || usage 1
            DURATION=$1
            ;;
        -r|--repeats)
            shift || usage 1
            REPEATS=$1
            ;;
        --ciphers)
            shift || usage 1
            CIPHERS_SPEC=$1
            ;;
        --lengths)
            shift || usage 1
            LENGTHS_SPEC=$1
            ;;
        --streams)
            shift || usage 1
            STREAMS_SPEC=$1
            ;;
        --tunnels)
            shift || usage 1
            TUNNELS_SPEC=$1
            ;;
        --narrow-ciphers)
            shift || usage 1
            NARROW_SPEC=$1
            ;;
        --skip-build)
            SKIP_BUILD=1
            ;;
        --smoke)
            SMOKE=1
            ;;
        --skip-reverse)
            SKIP_REVERSE=1
            ;;
        --skip-udp)
            SKIP_UDP=1
            ;;
        --skip-profile)
            SKIP_PROFILE=1
            ;;
        --list)
            LIST_ONLY=1
            DO_RUN=0
            ;;
        --write-baseline)
            WRITE_BASELINE=1
            ;;
        --export-baseline)
            EXPORT_BASELINE=1
            DO_RUN=0
            if [[ "${2:-}" != "" && "${2:-}" != -* ]]; then
                shift
                EXPORT_SRC=$1
            fi
            ;;
        --baseline-path)
            shift || usage 1
            BASELINE_PATH=$1
            ;;
        -h|--help)
            usage 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage 1
            ;;
    esac
    shift
done

if ! [[ "${DURATION}" =~ ^[0-9]+$ ]] || [[ "${DURATION}" -lt 1 ]]; then
    fatal "duration must be a positive integer"
fi
if ! [[ "${REPEATS}" =~ ^[0-9]+$ ]] || [[ "${REPEATS}" -lt 1 ]]; then
    fatal "repeats must be a positive integer"
fi

split_csv() {
    # $1 = dest-name via nameless echo; caller assigns array from newline list
    local spec=$1
    local IFS=','
    # shellcheck disable=SC2086
    printf '%s\n' ${spec}
}

CIPHERS=()
LENGTHS=()
STREAMS=()
TUNNELS=()
NARROW_CIPHERS=()

while IFS= read -r item; do
    [[ -n "${item}" ]] && CIPHERS[${#CIPHERS[@]}]="${item}"
done < <(split_csv "${CIPHERS_SPEC}")
while IFS= read -r item; do
    [[ -n "${item}" ]] && LENGTHS[${#LENGTHS[@]}]="${item}"
done < <(split_csv "${LENGTHS_SPEC}")
while IFS= read -r item; do
    [[ -n "${item}" ]] && STREAMS[${#STREAMS[@]}]="${item}"
done < <(split_csv "${STREAMS_SPEC}")
while IFS= read -r item; do
    [[ -n "${item}" ]] && NARROW_CIPHERS[${#NARROW_CIPHERS[@]}]="${item}"
done < <(split_csv "${NARROW_SPEC}")

while IFS= read -r item; do
    [[ -z "${item}" ]] && continue
    if [[ "${item}" == "auto" || "${item}" == "cpu" ]]; then
        item=${CPU_COUNT}
    fi
    if ! [[ "${item}" =~ ^[0-9]+$ ]] || [[ "${item}" -lt 1 ]]; then
        fatal "invalid tunnel count: ${item}"
    fi
    TUNNELS[${#TUNNELS[@]}]="${item}"
done < <(split_csv "${TUNNELS_SPEC}")

# Dedup tunnels while preserving order (bash 3.2: no associative arrays).
dedup_tunnels() {
    local out=()
    local t u seen
    for t in "${TUNNELS[@]}"; do
        seen=0
        for u in "${out[@]+"${out[@]}"}"; do
            if [[ "${u}" == "${t}" ]]; then
                seen=1
                break
            fi
        done
        if [[ "${seen}" -eq 0 ]]; then
            out[${#out[@]}]="${t}"
        fi
    done
    TUNNELS=("${out[@]}")
}
dedup_tunnels

if [[ "${SMOKE}" -eq 1 ]]; then
    DURATION=1
    REPEATS=1
    CIPHERS=(aes128gcm)
    LENGTHS=(128K)
    STREAMS=(4)
    TUNNELS=(1)
    NARROW_CIPHERS=(aes128gcm)
    UDP_CIPHER=aes128gcm
fi

PROFILE_LENGTH=128K
PROFILE_STREAMS=4
PROFILE_TUNNELS=${CPU_COUNT}
if [[ "${SMOKE}" -eq 1 ]]; then
    PROFILE_TUNNELS=1
fi

# --- python helpers (JSON, ports, iperf parse, baseline) ---------------------
perf_py() {
    python3 - "$@" <<'PY'
from __future__ import print_function

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone


INT_KEYS = {
    "streams",
    "tunnels",
    "repeat",
    "calls",
    "client_encrypt_calls",
    "server_encrypt_calls",
    "client_encrypt_total_ns",
    "server_encrypt_total_ns",
    "client_encrypt_avg_ns",
    "server_encrypt_avg_ns",
}
FLOAT_KEYS = {"gbps", "bits_per_second", "lost_percent"}
NULL_TOKENS = {"", "-", "null", "None"}


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def coerce(key, value):
    if value in NULL_TOKENS:
        return None
    if key in INT_KEYS:
        return int(value)
    if key in FLOAT_KEYS:
        return float(value)
    return value


def cmd_ports():
    socks = []
    ports = []
    try:
        for _ in range(3):
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            ports.append(s.getsockname()[1])
            socks.append(s)
        print("%d %d %d" % (ports[0], ports[1], ports[2]))
    finally:
        for s in socks:
            s.close()


def cmd_wait_port(host, port, attempts):
    port = int(port)
    attempts = int(attempts)
    for _ in range(attempts):
        s = socket.socket()
        s.settimeout(0.2)
        try:
            s.connect((host, port))
            s.close()
            sys.exit(0)
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            time.sleep(0.2)
    sys.exit(1)


def cmd_parse_iperf(path):
    with open(path) as f:
        try:
            data = json.load(f)
        except ValueError as exc:
            json.dump({"status": "error", "error": "json: %s" % exc}, sys.stdout)
            return
    iperf_err = data.get("error") if isinstance(data, dict) else None
    if isinstance(data, dict) and iperf_err and not data.get("end"):
        json.dump({"status": "error", "error": iperf_err, "bps": None}, sys.stdout)
        return
    end = (data or {}).get("end") or {}
    bps = None
    role = "receiver"
    lost = None
    rec = end.get("sum_received") or {}
    if rec.get("bits_per_second") is not None:
        bps = rec["bits_per_second"]
        lost = rec.get("lost_percent")
    else:
        block = end.get("sum") or {}
        if block.get("bits_per_second") is not None:
            bps = block["bits_per_second"]
            role = "sum"
            lost = block.get("lost_percent")
        else:
            sent = end.get("sum_sent") or {}
            if sent.get("bits_per_second") is not None:
                bps = sent["bits_per_second"]
                role = "sender"
    if iperf_err:
        json.dump(
            {
                "status": "error",
                "error": iperf_err,
                "bps": bps,
                "role": role,
                "lost_percent": lost,
            },
            sys.stdout,
        )
        return
    if bps is None:
        json.dump({"status": "error", "error": "parse", "bps": None}, sys.stdout)
        return
    # Loopback receiver-side 0 bps is a dead control/data path, not a real result.
    if role == "receiver" and float(bps) == 0.0:
        json.dump(
            {
                "status": "error",
                "error": "receiver 0 bps",
                "bps": bps,
                "role": role,
                "lost_percent": lost,
            },
            sys.stdout,
        )
        return
    json.dump(
        {"status": "ok", "bps": bps, "role": role, "lost_percent": lost},
        sys.stdout,
    )


def cmd_iperf_fields(path):
    """One-line TSV: status, bps, role, lost, error — for bash (no JSON-in-argv)."""
    import io

    buf = io.StringIO()
    # Reuse parse-iperf JSON on stdout, then flatten.
    orig = sys.stdout
    sys.stdout = buf
    try:
        cmd_parse_iperf(path)
    finally:
        sys.stdout = orig
    data = json.loads(buf.getvalue() or "{}")
    status = data.get("status") or "error"
    bps = data.get("bps")
    role = data.get("role") or "-"
    lost = data.get("lost_percent")
    err = data.get("error") or "-"
    bps_s = "-" if bps is None else str(bps)
    lost_s = "-" if lost is None else str(lost)
    print("%s\t%s\t%s\t%s\t%s" % (status, bps_s, role, lost_s, err))


def cmd_append_jsonl(path, pairs):
    obj = {}
    for item in pairs:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        obj[key] = coerce(key, value)
    with open(path, "a") as f:
        f.write(json.dumps(obj, separators=(",", ":")))
        f.write("\n")


def load_jsonl(path):
    cells = []
    profiles = []
    if not os.path.exists(path):
        return cells, profiles
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("kind") == "profile":
                profiles.append(obj)
            else:
                cells.append(obj)
    return cells, profiles


def cmd_assemble(jsonl, meta_path, out_path):
    cells, profiles = load_jsonl(jsonl)
    with open(meta_path) as f:
        meta = json.load(f)
    meta["finished_at"] = utcnow()
    with open(out_path, "w") as f:
        json.dump({"meta": meta, "cells": cells, "profiles": profiles}, f, indent=2)
        f.write("\n")


def cell_key(cell):
    return "%s/%s/%s/%s/l=%s/P=%s/tunnels=%s" % (
        cell.get("kind") or "-",
        cell.get("mode") or "-",
        cell.get("protocol") or "-",
        cell.get("cipher") or "-",
        cell.get("length") or "-",
        cell.get("streams") if cell.get("streams") is not None else "-",
        cell.get("tunnels") if cell.get("tunnels") is not None else "-",
    )


def aggregate_cells(cells):
    groups = []
    index = {}
    for cell in cells:
        key = cell_key(cell)
        if key not in index:
            index[key] = len(groups)
            groups.append({"key": key, "rows": []})
        groups[index[key]]["rows"].append(cell)
    out = []
    for group in groups:
        rows = group["rows"]
        oks = [
            r
            for r in rows
            if r.get("status") == "ok" and r.get("bits_per_second") is not None
        ]
        gbps_values = [float(r["gbps"]) for r in oks if r.get("gbps") is not None]
        bps_values = [float(r["bits_per_second"]) for r in oks]
        first = rows[0]
        mean_gbps = (sum(gbps_values) / len(gbps_values)) if gbps_values else None
        mean_bps = (sum(bps_values) / len(bps_values)) if bps_values else None
        out.append(
            {
                "key": group["key"],
                "kind": first.get("kind"),
                "mode": first.get("mode"),
                "protocol": first.get("protocol"),
                "cipher": first.get("cipher"),
                "length": first.get("length"),
                "streams": first.get("streams"),
                "tunnels": first.get("tunnels"),
                "repeats": len(rows),
                "ok_repeats": len(oks),
                "gbps_mean": mean_gbps,
                "gbps_values": gbps_values,
                "bits_per_second_mean": mean_bps,
            }
        )
    return out


def cmd_export_baseline(results_path, dest):
    with open(results_path) as f:
        data = json.load(f)
    payload = {
        "version": (data.get("meta") or {}).get("version", "0.3.0"),
        "metric": "receiver_sum",
        "source": os.path.abspath(results_path),
        "created_at": utcnow(),
        "meta": data.get("meta") or {},
        "cells": aggregate_cells(data.get("cells") or []),
        "profiles": data.get("profiles") or [],
    }
    dest_dir = os.path.dirname(os.path.abspath(dest))
    if dest_dir and not os.path.isdir(dest_dir):
        os.makedirs(dest_dir)
    with open(dest, "w") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def cmd_summary(results_path, dest):
    with open(results_path) as f:
        data = json.load(f)
    rows = aggregate_cells(data.get("cells") or [])
    with open(dest, "w") as f:
        f.write("key\tok_repeats\trepeats\tgbps_mean\tgbps_values\n")
        for row in rows:
            values = ",".join("%.4f" % v for v in row["gbps_values"])
            mean = "" if row["gbps_mean"] is None else "%.4f" % row["gbps_mean"]
            f.write(
                "%s\t%s\t%s\t%s\t%s\n"
                % (row["key"], row["ok_repeats"], row["repeats"], mean, values)
            )


def cmd_parse_profile(path):
    out = {
        "client_encrypt_total_ns": None,
        "client_encrypt_calls": None,
        "client_encrypt_avg_ns": None,
        "server_encrypt_total_ns": None,
        "server_encrypt_calls": None,
        "server_encrypt_avg_ns": None,
        "lines": [],
    }
    if not os.path.exists(path):
        json.dump(out, sys.stdout)
        return
    with open(path) as f:
        text = f.read()
    for line in text.splitlines():
        if "[PROFILE]" not in line:
            continue
        out["lines"].append(line)
        # [PROFILE] client encryption total=123 ns calls=4 avg=5 ns
        if " encryption " in line and "total=" in line:
            side = "client" if "client encryption" in line else "server"
            parts = {}
            for token in line.replace(",", " ").split():
                if "=" in token:
                    k, v = token.split("=", 1)
                    if v.isdigit():
                        parts[k] = int(v)
            if "total" in parts:
                out["%s_encrypt_total_ns" % side] = parts["total"]
            if "calls" in parts:
                out["%s_encrypt_calls" % side] = parts["calls"]
            if "avg" in parts:
                out["%s_encrypt_avg_ns" % side] = parts["avg"]
    json.dump(out, sys.stdout)


def cmd_profile_fields(path):
    import io

    buf = io.StringIO()
    orig = sys.stdout
    sys.stdout = buf
    try:
        cmd_parse_profile(path)
    finally:
        sys.stdout = orig
    data = json.loads(buf.getvalue() or "{}")
    keys = (
        "client_encrypt_total_ns",
        "client_encrypt_calls",
        "client_encrypt_avg_ns",
        "server_encrypt_total_ns",
        "server_encrypt_calls",
        "server_encrypt_avg_ns",
    )
    vals = []
    for key in keys:
        v = data.get(key)
        vals.append("-" if v is None else str(v))
    print("\t".join(vals))


def main(argv):
    if not argv:
        sys.exit("missing command")
    cmd = argv[0]
    args = argv[1:]
    if cmd == "ports":
        cmd_ports()
    elif cmd == "wait-port":
        cmd_wait_port(args[0], args[1], args[2])
    elif cmd == "parse-iperf":
        cmd_parse_iperf(args[0])
    elif cmd == "iperf-fields":
        cmd_iperf_fields(args[0])
    elif cmd == "append-jsonl":
        cmd_append_jsonl(args[0], args[1:])
    elif cmd == "assemble":
        cmd_assemble(args[0], args[1], args[2])
    elif cmd == "export-baseline":
        cmd_export_baseline(args[0], args[1])
    elif cmd == "summary":
        cmd_summary(args[0], args[1])
    elif cmd == "parse-profile":
        cmd_parse_profile(args[0])
    elif cmd == "profile-fields":
        cmd_profile_fields(args[0])
    else:
        sys.exit("unknown helper command: %s" % cmd)


if __name__ == "__main__":
    main(sys.argv[1:])
PY
}

# --- coverage / list ---------------------------------------------------------
raw_cells=$(( ${#LENGTHS[@]} * ${#STREAMS[@]} ))
fwd_unique=$(( ${#CIPHERS[@]} * ${#LENGTHS[@]} * ${#STREAMS[@]} * ${#TUNNELS[@]} ))
rev_unique=$(( ${#NARROW_CIPHERS[@]} * ${#LENGTHS[@]} * ${#STREAMS[@]} * ${#TUNNELS[@]} ))
udp_unique=1
profile_unique=${#CIPHERS[@]}
if [[ "${SKIP_REVERSE}" -eq 1 ]]; then
    rev_unique=0
fi
if [[ "${SKIP_UDP}" -eq 1 ]]; then
    udp_unique=0
fi
if [[ "${SKIP_PROFILE}" -eq 1 ]]; then
    profile_unique=0
fi
tcp_trials=$(( (fwd_unique + rev_unique) * REPEATS ))
raw_trials=$(( raw_cells * REPEATS ))
udp_trials=$(( udp_unique * REPEATS ))

print_coverage() {
    echo "Matrix coverage (optimize=${OPTIMIZE}, ${DURATION}s x ${REPEATS} repeats, receiver-side SUM)"
    echo "  CPU count:          ${CPU_COUNT}"
    echo "  Ciphers:            ${CIPHERS[*]}"
    echo "  Reverse ciphers:    ${NARROW_CIPHERS[*]}"
    echo "  iperf3 -l:          ${LENGTHS[*]}"
    echo "  iperf3 -P:          ${STREAMS[*]}"
    echo "  Tunnels:            ${TUNNELS[*]}"
    echo "  Raw loopback:       ${raw_cells} configs x ${REPEATS} = ${raw_trials} trials"
    echo "  Forward TCP:        ${fwd_unique} configs x ${REPEATS} = $((fwd_unique * REPEATS)) trials"
    if [[ "${SKIP_REVERSE}" -eq 1 ]]; then
        echo "  Reverse TCP:        skipped"
    else
        echo "  Reverse TCP:        ${rev_unique} configs x ${REPEATS} = $((rev_unique * REPEATS)) trials"
    fi
    if [[ "${SKIP_UDP}" -eq 1 ]]; then
        echo "  UDP (one cell):     skipped"
    else
        echo "  UDP (one cell):     ${UDP_CIPHER} forward TCP+/udp (iperf3 control+data), -u -b ${UDP_BANDWIDTH} -l ${UDP_LENGTH} -P ${UDP_STREAMS}, tunnels=1 x ${REPEATS}"
    fi
    if [[ "${SKIP_PROFILE}" -eq 1 ]]; then
        echo "  Encrypt profiles:   skipped"
    else
        echo "  Encrypt profiles:   ${profile_unique} (FLOO_PROFILE_ENCRYPT=1 + SIGUSR1, one per cipher)"
    fi
    echo "  Artifacts:          ${WORKDIR}"
}

print_cell_plan() {
    local length streams cipher tunnels repeat
    echo "# raw"
    for length in "${LENGTHS[@]}"; do
        for streams in "${STREAMS[@]}"; do
            for ((repeat = 1; repeat <= REPEATS; repeat++)); do
                echo "raw	loopback	tcp	-	${length}	${streams}	-	${repeat}"
            done
        done
    done
    echo "# forward"
    for cipher in "${CIPHERS[@]}"; do
        for tunnels in "${TUNNELS[@]}"; do
            for length in "${LENGTHS[@]}"; do
                for streams in "${STREAMS[@]}"; do
                    for ((repeat = 1; repeat <= REPEATS; repeat++)); do
                        echo "forward	forward	tcp	${cipher}	${length}	${streams}	${tunnels}	${repeat}"
                    done
                done
            done
        done
    done
    if [[ "${SKIP_REVERSE}" -eq 0 ]]; then
        echo "# reverse (narrow ciphers)"
        for cipher in "${NARROW_CIPHERS[@]}"; do
            for tunnels in "${TUNNELS[@]}"; do
                for length in "${LENGTHS[@]}"; do
                    for streams in "${STREAMS[@]}"; do
                        for ((repeat = 1; repeat <= REPEATS; repeat++)); do
                            echo "reverse	reverse	tcp	${cipher}	${length}	${streams}	${tunnels}	${repeat}"
                        done
                    done
                done
            done
        done
    fi
    if [[ "${SKIP_UDP}" -eq 0 ]]; then
        echo "# udp"
        for ((repeat = 1; repeat <= REPEATS; repeat++)); do
            echo "udp	forward	udp	${UDP_CIPHER}	${UDP_LENGTH}	${UDP_STREAMS}	1	${repeat}"
        done
    fi
    if [[ "${SKIP_PROFILE}" -eq 0 ]]; then
        echo "# profile"
        for cipher in "${CIPHERS[@]}"; do
            echo "profile	forward	tcp	${cipher}	${PROFILE_LENGTH}	${PROFILE_STREAMS}	${PROFILE_TUNNELS}	1"
        done
    fi
}

if [[ "${LIST_ONLY}" -eq 1 ]]; then
    print_coverage
    echo ""
    print_cell_plan
    exit 0
fi

# --- export-only path --------------------------------------------------------
require_cmd python3

if [[ "${EXPORT_BASELINE}" -eq 1 ]]; then
    if [[ -z "${EXPORT_SRC}" ]]; then
        EXPORT_SRC="${WORKDIR}/results.json"
    fi
    [[ -f "${EXPORT_SRC}" ]] || fatal "results file not found: ${EXPORT_SRC}"
    perf_py export-baseline "${EXPORT_SRC}" "${BASELINE_PATH}"
    echo "Wrote baseline ${BASELINE_PATH} from ${EXPORT_SRC}"
    exit 0
fi

if [[ "${DO_RUN}" -ne 1 ]]; then
    fatal "nothing to do"
fi

require_cmd iperf3
require_cmd awk
require_cmd zig

# --- workdir / PID table -----------------------------------------------------
LOG_DIR="${WORKDIR}/logs"
IPERF_DIR="${WORKDIR}/iperf"
CFG_DIR="${WORKDIR}/configs"
PROF_DIR="${WORKDIR}/profiles"
PID_FILE="${WORKDIR}/.tracked.pids"
TSV_FILE="${WORKDIR}/results.tsv"
JSONL_FILE="${WORKDIR}/results.jsonl"
RESULT_JSON="${WORKDIR}/results.json"
SUMMARY_FILE="${WORKDIR}/summary.tsv"
META_FILE="${WORKDIR}/meta.json"

mkdir -p "${LOG_DIR}" "${IPERF_DIR}" "${CFG_DIR}" "${PROF_DIR}"
: > "${PID_FILE}"
: > "${JSONL_FILE}"
printf 'cell\tkind\tmode\tprotocol\tcipher\tlength\tstreams\ttunnels\trepeat\tstatus\tgbps\tbits_per_second\trole\tlost_percent\tlog\n' > "${TSV_FILE}"

ASSEMBLED=0
FAILED_CELLS=0
LAST_PID=""
IPERF_PID=""
SESSION_RESTART=0

stop_one_pid() {
    local pid=$1
    [[ -n "${pid}" ]] || return 0
    if kill -0 "${pid}" 2>/dev/null; then
        kill -TERM "${pid}" 2>/dev/null || true
        local i
        for ((i = 0; i < 30; i++)); do
            kill -0 "${pid}" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "${pid}" 2>/dev/null; then
            kill -KILL "${pid}" 2>/dev/null || true
        fi
    fi
    wait "${pid}" 2>/dev/null || true
}

untrack_pid() {
    local target=$1
    local tmp p
    [[ -f "${PID_FILE}" ]] || return 0
    tmp=$(mktemp "${WORKDIR}/.pids.XXXXXX")
    while IFS= read -r p; do
        [[ -z "${p}" || "${p}" == "${target}" ]] && continue
        printf '%s\n' "${p}"
    done < "${PID_FILE}" > "${tmp}"
    mv "${tmp}" "${PID_FILE}"
}

track_pid() {
    printf '%s\n' "$1" >> "${PID_FILE}"
}

stop_pid() {
    local pid=$1
    stop_one_pid "${pid}"
    untrack_pid "${pid}"
}

stop_all_tracked() {
    local pids pid
    [[ -f "${PID_FILE}" ]] || return 0
    pids=$(cat "${PID_FILE}" 2>/dev/null || true)
    : > "${PID_FILE}"
    # Stop newest first (client before server before iperf).
    if [[ -n "${pids}" ]]; then
        local rev="" pid
        for pid in ${pids}; do
            rev="${pid} ${rev}"
        done
        for pid in ${rev}; do
            stop_one_pid "${pid}"
        done
    fi
}

assemble_artifacts() {
    if [[ ! -f "${META_FILE}" ]]; then
        return 0
    fi
    perf_py assemble "${JSONL_FILE}" "${META_FILE}" "${RESULT_JSON}"
    if [[ -f "${RESULT_JSON}" ]]; then
        perf_py summary "${RESULT_JSON}" "${SUMMARY_FILE}"
    fi
    ASSEMBLED=1
}

cleanup() {
    stop_all_tracked
    if [[ "${ASSEMBLED}" -ne 1 ]]; then
        assemble_artifacts || true
    fi
}

trap cleanup EXIT

wait_for_port() {
    local host=$1
    local port=$2
    local attempts=${3:-50}
    perf_py wait-port "${host}" "${port}" "${attempts}"
}

wait_for_log() {
    local file=$1
    local pattern=$2
    local attempts=${3:-50}
    local i
    for ((i = 0; i < attempts; i++)); do
        if [[ -f "${file}" ]] && grep -q "${pattern}" "${file}" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

allocate_ports() {
    local out
    out=$(perf_py ports)
    PORT_TUNNEL=${out%% *}
    local rest=${out#* }
    PORT_IPERF=${rest%% *}
    PORT_LISTEN=${rest#* }
}

# Config writers mirror run_benchmarks.sh (same keys / advanced block / PSK note).
write_floo_configs() {
    local cipher=$1
    local server_cfg=$2
    local client_cfg=$3
    local tunnel_port=$4
    local target_port=$5
    local listen_port=$6
    local num_tunnels=$7
    local transport_suffix=${8:-}

    cat > "${server_cfg}" <<EOF
bind = "0.0.0.0"
port = ${tunnel_port}
cipher = "${cipher}"
psk = "${PSK}"
token = "${TOKEN}"

[services]
benchmark = "127.0.0.1:${target_port}${transport_suffix}"

[advanced]
tcp_nodelay = true
socket_buffer_size = 8388608  # 8MB buffer for high throughput
heartbeat_interval_seconds = 30
EOF

    cat > "${client_cfg}" <<EOF
server = "127.0.0.1:${tunnel_port}"
cipher = "${cipher}"
psk = "${PSK}"
token = "${TOKEN}"

[services]
benchmark = "127.0.0.1:${listen_port}${transport_suffix}"

[advanced]
num_tunnels = ${num_tunnels}
tcp_nodelay = true
socket_buffer_size = 8388608  # 8MB buffer for high throughput
heartbeat_timeout_seconds = 60
reconnect_enabled = false
EOF
}

write_floo_reverse_configs() {
    local cipher=$1
    local server_cfg=$2
    local client_cfg=$3
    local tunnel_port=$4
    local target_port=$5
    local listen_port=$6
    local num_tunnels=$7
    local transport_suffix=${8:-}

    cat > "${server_cfg}" <<EOF
bind = "0.0.0.0"
port = ${tunnel_port}
cipher = "${cipher}"
psk = "${PSK}"
token = "${TOKEN}"

[reverse_services]
benchmark = "0.0.0.0:${listen_port}${transport_suffix}"

[advanced]
tcp_nodelay = true
socket_buffer_size = 8388608  # 8MB buffer for high throughput
heartbeat_interval_seconds = 30
EOF

    cat > "${client_cfg}" <<EOF
server = "127.0.0.1:${tunnel_port}"
cipher = "${cipher}"
psk = "${PSK}"
token = "${TOKEN}"

[reverse_services]
benchmark = "127.0.0.1:${target_port}${transport_suffix}"

[advanced]
num_tunnels = ${num_tunnels}
tcp_nodelay = true
socket_buffer_size = 8388608  # 8MB buffer for high throughput
heartbeat_timeout_seconds = 60
reconnect_enabled = false
EOF
}

# iperf3 -u still opens a TCP control channel on the same port as the UDP
# data. Pair a TCP service with a /udp service so both land on one port.
write_floo_udp_configs() {
    local cipher=$1
    local server_cfg=$2
    local client_cfg=$3
    local tunnel_port=$4
    local target_port=$5
    local listen_port=$6
    local num_tunnels=$7

    cat > "${server_cfg}" <<EOF
bind = "0.0.0.0"
port = ${tunnel_port}
cipher = "${cipher}"
psk = "${PSK}"
token = "${TOKEN}"

[services]
benchmark = "127.0.0.1:${target_port}"
benchmark_udp = "127.0.0.1:${target_port}/udp"

[advanced]
tcp_nodelay = true
socket_buffer_size = 8388608  # 8MB buffer for high throughput
heartbeat_interval_seconds = 30
udp_timeout_seconds = 60
EOF

    cat > "${client_cfg}" <<EOF
server = "127.0.0.1:${tunnel_port}"
cipher = "${cipher}"
psk = "${PSK}"
token = "${TOKEN}"

[services]
benchmark = "127.0.0.1:${listen_port}"
benchmark_udp = "127.0.0.1:${listen_port}/udp"

[advanced]
num_tunnels = ${num_tunnels}
tcp_nodelay = true
socket_buffer_size = 8388608  # 8MB buffer for high throughput
heartbeat_timeout_seconds = 60
reconnect_enabled = false
udp_timeout_seconds = 60
EOF
}

build_floo() {
    local floos_path="${FLOO_BIN_DIR}/floos"
    local flooc_path="${FLOO_BIN_DIR}/flooc"
    if [[ "${SKIP_BUILD}" == "1" && -x "${floos_path}" && -x "${flooc_path}" ]]; then
        return
    fi
    if [[ ! -x "${floos_path}" || ! -x "${flooc_path}" ]]; then
        echo "[build] Compiling Floo binaries (${OPTIMIZE})"
        (cd "${ROOT_DIR}" && zig build -Doptimize="${OPTIMIZE}") >/dev/null
        return
    fi
    if [[ "${SKIP_BUILD}" != "1" ]]; then
        echo "[build] Refreshing Floo binaries (${OPTIMIZE})"
        (cd "${ROOT_DIR}" && zig build -Doptimize="${OPTIMIZE}") >/dev/null
    fi
}

start_iperf_server() {
    local port=$1
    local logfile="${LOG_DIR}/iperf_server_${port}.log"
    iperf3 -s -p "${port}" > "${logfile}" 2>&1 &
    LAST_PID=$!
    track_pid "${LAST_PID}"
}

start_floos() {
    local cfg=$1
    local logfile=$2
    local profile=${3:-0}
    if [[ "${profile}" -eq 1 ]]; then
        FLOO_PROFILE_ENCRYPT=1 "${FLOO_BIN_DIR}/floos" "${cfg}" > "${logfile}" 2>&1 &
    else
        "${FLOO_BIN_DIR}/floos" "${cfg}" > "${logfile}" 2>&1 &
    fi
    LAST_PID=$!
    track_pid "${LAST_PID}"
}

start_flooc() {
    local cfg=$1
    local logfile=$2
    local profile=${3:-0}
    if [[ "${profile}" -eq 1 ]]; then
        FLOO_PROFILE_ENCRYPT=1 "${FLOO_BIN_DIR}/flooc" "${cfg}" > "${logfile}" 2>&1 &
    else
        "${FLOO_BIN_DIR}/flooc" "${cfg}" > "${logfile}" 2>&1 &
    fi
    LAST_PID=$!
    track_pid "${LAST_PID}"
}

alive() {
    local pid=$1
    [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null
}

record_cell() {
    local cell=$1
    local kind=$2
    local mode=$3
    local protocol=$4
    local cipher=$5
    local length=$6
    local streams=$7
    local tunnels=$8
    local repeat=$9
    local status=${10}
    local gbps=${11:--}
    local bps=${12:--}
    local role=${13:--}
    local lost=${14:--}
    local logpath=${15:--}

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${cell}" "${kind}" "${mode}" "${protocol}" "${cipher}" "${length}" \
        "${streams}" "${tunnels}" "${repeat}" "${status}" "${gbps}" "${bps}" \
        "${role}" "${lost}" "${logpath}" >> "${TSV_FILE}"

    perf_py append-jsonl "${JSONL_FILE}" \
        cell="${cell}" \
        kind="${kind}" \
        mode="${mode}" \
        protocol="${protocol}" \
        cipher="${cipher}" \
        length="${length}" \
        streams="${streams}" \
        tunnels="${tunnels}" \
        repeat="${repeat}" \
        status="${status}" \
        gbps="${gbps}" \
        bits_per_second="${bps}" \
        role="${role}" \
        lost_percent="${lost}" \
        log="${logpath}"

    if [[ "${status}" != "ok" ]]; then
        FAILED_CELLS=$((FAILED_CELLS + 1))
        echo "[${cell}] ${status}"
    else
        echo "[${cell}] ${gbps} Gbits/sec (${role})"
    fi
}

run_iperf_client() {
    # Sets PARSE_STATUS PARSE_GBPS PARSE_BPS PARSE_ROLE PARSE_LOST
    local outfile=$1
    local port=$2
    local streams=$3
    local length=$4
    local udp=${5:-0}

    local extra=()
    extra=(-c 127.0.0.1 -p "${port}" -P "${streams}" -t "${DURATION}" -l "${length}" -J --connect-timeout 3000)
    if [[ "${udp}" -eq 1 ]]; then
        extra+=(-u -b "${UDP_BANDWIDTH}")
    fi

    set +e
    # 5s trials can hang forever if the iperf3 control socket dies mid-test
    # (HOL writev). Cap the client so one cell cannot stall the matrix.
    perl -e 'alarm shift; exec @ARGV' $((DURATION + 15)) iperf3 "${extra[@]}" > "${outfile}" 2>&1
    set -e

    PARSE_STATUS=error
    PARSE_GBPS=-
    PARSE_BPS=-
    PARSE_ROLE=-
    PARSE_LOST=-

    if [[ ! -s "${outfile}" ]]; then
        PARSE_STATUS="error (iperf empty)"
        return 1
    fi

    local fields status bps role lost err
    fields=$(perf_py iperf-fields "${outfile}" || true)
    if [[ -z "${fields}" ]]; then
        PARSE_STATUS="error (parse)"
        return 1
    fi
    IFS=$'\t' read -r status bps role lost err <<< "${fields}"
    if [[ "${status}" != "ok" ]]; then
        PARSE_STATUS="error (${err})"
        return 1
    fi
    PARSE_STATUS=ok
    PARSE_BPS=${bps}
    PARSE_ROLE=${role}
    PARSE_LOST=${lost}
    PARSE_GBPS=$(python3 -c 'import sys; print("%.6f" % (float(sys.argv[1]) / 1e9))' "${PARSE_BPS}")
    return 0
}

start_floo_pair() {
    # Uses PORT_* and writes logs; sets FLOOS_PID FLOOC_PID
    local mode=$1
    local cipher=$2
    local tunnels=$3
    local suffix=$4
    local profile=${5:-0}
    local transport_suffix=${6:-}

    local server_cfg="${CFG_DIR}/floos_${suffix}.toml"
    local client_cfg="${CFG_DIR}/flooc_${suffix}.toml"
    local floos_log="${LOG_DIR}/floos_${suffix}.log"
    local flooc_log="${LOG_DIR}/flooc_${suffix}.log"
    FLOOS_PID=""
    FLOOC_PID=""
    FLOOS_LOG="${floos_log}"
    FLOOC_LOG="${flooc_log}"

    if [[ "${transport_suffix}" == "/udp" ]]; then
        write_floo_udp_configs "${cipher}" "${server_cfg}" "${client_cfg}" \
            "${PORT_TUNNEL}" "${PORT_IPERF}" "${PORT_LISTEN}" "${tunnels}"
    elif [[ "${mode}" == "reverse" ]]; then
        write_floo_reverse_configs "${cipher}" "${server_cfg}" "${client_cfg}" \
            "${PORT_TUNNEL}" "${PORT_IPERF}" "${PORT_LISTEN}" "${tunnels}" "${transport_suffix}"
    else
        write_floo_configs "${cipher}" "${server_cfg}" "${client_cfg}" \
            "${PORT_TUNNEL}" "${PORT_IPERF}" "${PORT_LISTEN}" "${tunnels}" "${transport_suffix}"
    fi

    start_floos "${server_cfg}" "${floos_log}" "${profile}"
    FLOOS_PID=${LAST_PID}
    if ! wait_for_port 127.0.0.1 "${PORT_TUNNEL}" 50; then
        echo "floos failed to listen on ${PORT_TUNNEL} (see ${floos_log})" >&2
        return 1
    fi
    if ! wait_for_log "${floos_log}" "\\[READY\\]" 50; then
        echo "floos did not become ready (see ${floos_log})" >&2
        return 1
    fi

    start_flooc "${client_cfg}" "${flooc_log}" "${profile}"
    FLOOC_PID=${LAST_PID}

    if [[ "${mode}" == "reverse" ]]; then
        if ! wait_for_port 127.0.0.1 "${PORT_LISTEN}" 100; then
            echo "reverse listener ${PORT_LISTEN} did not open (see ${floos_log} ${flooc_log})" >&2
            return 1
        fi
    else
        # TCP listen (forward) or TCP control sibling of the /udp iperf3 cell.
        if ! wait_for_port 127.0.0.1 "${PORT_LISTEN}" 100; then
            echo "client listener ${PORT_LISTEN} did not open (see ${flooc_log})" >&2
            return 1
        fi
        if [[ "${transport_suffix}" == "/udp" ]]; then
            if ! wait_for_log "${flooc_log}" "\\[READY\\]" 50; then
                echo "flooc UDP did not become ready (see ${flooc_log})" >&2
                return 1
            fi
        fi
    fi
    return 0
}

stop_floo_pair() {
    local flooc_pid=${1:-}
    local floos_pid=${2:-}
    [[ -n "${flooc_pid}" ]] && stop_pid "${flooc_pid}"
    [[ -n "${floos_pid}" ]] && stop_pid "${floos_pid}"
}

# Bring up iperf3 + floo on fresh ephemeral ports. Retries bind races
# (Darwin TIME_WAIT vs allocate_ports). Sets IPERF_PID / PORT_LISTEN.
bring_up_tcp() {
    local mode=$1
    local cipher=$2
    local tunnels=$3
    local transport_suffix=${4:-}
    local profile=${5:-0}
    SESSION_RESTART=$((SESSION_RESTART + 1))
    local suffix="${mode}_${cipher}_t${tunnels}_n${SESSION_RESTART}"
    local attempt
    IPERF_PID=""
    for ((attempt = 1; attempt <= 5; attempt++)); do
        allocate_ports
        start_iperf_server "${PORT_IPERF}"
        local iperf_try=${LAST_PID}
        if ! wait_for_port 127.0.0.1 "${PORT_IPERF}" 50; then
            echo "[${suffix}] iperf3 bind retry ${attempt} port=${PORT_IPERF}"
            stop_pid "${iperf_try}"
            sleep 0.2
            continue
        fi
        if start_floo_pair "${mode}" "${cipher}" "${tunnels}" "${suffix}" "${profile}" "${transport_suffix}"; then
            IPERF_PID=${iperf_try}
            return 0
        fi
        echo "[${suffix}] tunnel init retry ${attempt}"
        stop_floo_pair "${FLOOC_PID:-}" "${FLOOS_PID:-}"
        stop_pid "${iperf_try}"
        sleep 0.3
    done
    return 1
}

tear_down_tcp() {
    stop_floo_pair "${FLOOC_PID:-}" "${FLOOS_PID:-}"
    if [[ -n "${IPERF_PID:-}" ]]; then
        stop_pid "${IPERF_PID}"
    fi
    IPERF_PID=""
    FLOOC_PID=""
    FLOOS_PID=""
}

run_tcp_session() {
    local mode=$1
    local cipher=$2
    local tunnels=$3
    local length streams repeat
    local suffix="${mode}_${cipher}_t${tunnels}"
    SESSION_RESTART=0

    if ! bring_up_tcp "${mode}" "${cipher}" "${tunnels}" "" 0; then
        echo "[${suffix}] failed to start iperf3/floo after retries"
        local r
        for length in "${LENGTHS[@]}"; do
            for streams in "${STREAMS[@]}"; do
                for ((r = 1; r <= REPEATS; r++)); do
                    record_cell "${mode}_${cipher}_l${length}_P${streams}_t${tunnels}_r${r}" \
                        "${mode}" "${mode}" tcp "${cipher}" "${length}" "${streams}" \
                        "${tunnels}" "${r}" "error (tunnel init)" - - - - \
                        "${FLOOC_LOG:-}"
                done
            done
        done
        tear_down_tcp
        return
    fi

    local client_port=${PORT_LISTEN}

    for length in "${LENGTHS[@]}"; do
        for streams in "${STREAMS[@]}"; do
            for ((repeat = 1; repeat <= REPEATS; repeat++)); do
                local cell="${mode}_${cipher}_l${length}_P${streams}_t${tunnels}_r${repeat}"
                if ! alive "${FLOOS_PID}" || ! alive "${FLOOC_PID}" || ! alive "${IPERF_PID}"; then
                    echo "[${cell}] restacking (process died)"
                    tear_down_tcp
                    if ! bring_up_tcp "${mode}" "${cipher}" "${tunnels}" "" 0; then
                        record_cell "${cell}" "${mode}" "${mode}" tcp "${cipher}" \
                            "${length}" "${streams}" "${tunnels}" "${repeat}" \
                            "error (floo died)" - - - - "${FLOOC_LOG:-}"
                        continue
                    fi
                    client_port=${PORT_LISTEN}
                fi
                local outfile="${IPERF_DIR}/${cell}.json"
                if run_iperf_client "${outfile}" "${client_port}" "${streams}" "${length}" 0; then
                    record_cell "${cell}" "${mode}" "${mode}" tcp "${cipher}" \
                        "${length}" "${streams}" "${tunnels}" "${repeat}" \
                        ok "${PARSE_GBPS}" "${PARSE_BPS}" "${PARSE_ROLE}" "${PARSE_LOST}" \
                        "${outfile}"
                else
                    record_cell "${cell}" "${mode}" "${mode}" tcp "${cipher}" \
                        "${length}" "${streams}" "${tunnels}" "${repeat}" \
                        "${PARSE_STATUS}" - - - - "${outfile}"
                    # Full restack: iperf3-through-proxy often kills the control
                    # socket and leaves tunnels dead (reconnect_enabled=false).
                    tear_down_tcp
                    if bring_up_tcp "${mode}" "${cipher}" "${tunnels}" "" 0; then
                        client_port=${PORT_LISTEN}
                    fi
                fi
            done
        done
    done

    tear_down_tcp
}

run_raw() {
    echo ""
    echo "=== raw loopback ==="
    local attempt iperf_pid=""
    for ((attempt = 1; attempt <= 5; attempt++)); do
        allocate_ports
        start_iperf_server "${PORT_IPERF}"
        iperf_pid=${LAST_PID}
        if wait_for_port 127.0.0.1 "${PORT_IPERF}" 50; then
            break
        fi
        echo "raw: iperf3 bind retry ${attempt} port=${PORT_IPERF}"
        stop_pid "${iperf_pid}"
        iperf_pid=""
        sleep 0.2
    done
    if [[ -z "${iperf_pid}" ]] || ! wait_for_port 127.0.0.1 "${PORT_IPERF}" 5; then
        echo "raw: iperf3 server failed after retries"
        [[ -n "${iperf_pid}" ]] && stop_pid "${iperf_pid}"
        return
    fi
    local length streams repeat
    for length in "${LENGTHS[@]}"; do
        for streams in "${STREAMS[@]}"; do
            for ((repeat = 1; repeat <= REPEATS; repeat++)); do
                local cell="raw_l${length}_P${streams}_r${repeat}"
                local outfile="${IPERF_DIR}/${cell}.json"
                if run_iperf_client "${outfile}" "${PORT_IPERF}" "${streams}" "${length}" 0; then
                    record_cell "${cell}" raw loopback tcp - "${length}" "${streams}" \
                        - "${repeat}" ok "${PARSE_GBPS}" "${PARSE_BPS}" "${PARSE_ROLE}" \
                        "${PARSE_LOST}" "${outfile}"
                else
                    record_cell "${cell}" raw loopback tcp - "${length}" "${streams}" \
                        - "${repeat}" "${PARSE_STATUS}" - - - - "${outfile}"
                    stop_pid "${iperf_pid}"
                    allocate_ports
                    start_iperf_server "${PORT_IPERF}"
                    iperf_pid=${LAST_PID}
                    wait_for_port 127.0.0.1 "${PORT_IPERF}" 50 || true
                fi
            done
        done
    done
    stop_pid "${iperf_pid}"
}

run_udp_cell() {
    echo ""
    echo "=== UDP (one cell) ==="
    local tunnels=1
    local cipher=${UDP_CIPHER}
    SESSION_RESTART=0
    if ! bring_up_tcp forward "${cipher}" "${tunnels}" "/udp" 0; then
        record_cell "udp_${cipher}_l${UDP_LENGTH}_P${UDP_STREAMS}_t${tunnels}_r1" \
            udp forward udp "${cipher}" "${UDP_LENGTH}" "${UDP_STREAMS}" \
            "${tunnels}" 1 "error (tunnel init)" - - - - "${FLOOC_LOG:-}"
        tear_down_tcp
        return
    fi
    local repeat
    local client_port=${PORT_LISTEN}
    for ((repeat = 1; repeat <= REPEATS; repeat++)); do
        local cell="udp_${cipher}_l${UDP_LENGTH}_P${UDP_STREAMS}_t${tunnels}_r${repeat}"
        local outfile="${IPERF_DIR}/${cell}.json"
        if run_iperf_client "${outfile}" "${client_port}" "${UDP_STREAMS}" "${UDP_LENGTH}" 1; then
            record_cell "${cell}" udp forward udp "${cipher}" "${UDP_LENGTH}" \
                "${UDP_STREAMS}" "${tunnels}" "${repeat}" ok \
                "${PARSE_GBPS}" "${PARSE_BPS}" "${PARSE_ROLE}" "${PARSE_LOST}" "${outfile}"
        else
            record_cell "${cell}" udp forward udp "${cipher}" "${UDP_LENGTH}" \
                "${UDP_STREAMS}" "${tunnels}" "${repeat}" "${PARSE_STATUS}" \
                - - - - "${outfile}"
            tear_down_tcp
            if bring_up_tcp forward "${cipher}" "${tunnels}" "/udp" 0; then
                client_port=${PORT_LISTEN}
            fi
        fi
    done
    tear_down_tcp
}

dump_sigusr1() {
    # SIGUSR1 is supposed to set flush_stats. On this Darwin/Zig 0.16 host
    # it terminates floo (default action), which skips defer flushEncryptStats.
    # Leave the processes running; tear_down_tcp SIGTERM prints the profile.
    :
}

run_profile_dumps() {
    echo ""
    echo "=== FLOO_PROFILE_ENCRYPT + SIGUSR1 (one per cipher) ==="
    local cipher
    local tunnels=${PROFILE_TUNNELS}
    for cipher in "${CIPHERS[@]}"; do
        local dump="${PROF_DIR}/${cipher}.dump.txt"
        SESSION_RESTART=0
        if ! bring_up_tcp forward "${cipher}" "${tunnels}" "" 1; then
            echo "[profile ${cipher}] tunnel init failed"
            {
                echo "# floos"
                [[ -f "${FLOOS_LOG:-}" ]] && cat "${FLOOS_LOG}"
                echo "# flooc"
                [[ -f "${FLOOC_LOG:-}" ]] && cat "${FLOOC_LOG}"
            } > "${dump}"
            perf_py append-jsonl "${JSONL_FILE}" \
                cell="profile_${cipher}" kind=profile mode=forward protocol=tcp \
                cipher="${cipher}" length="${PROFILE_LENGTH}" streams="${PROFILE_STREAMS}" \
                tunnels="${tunnels}" repeat=1 status="error (tunnel init)" dump="${dump}"
            FAILED_CELLS=$((FAILED_CELLS + 1))
            tear_down_tcp
            continue
        fi
        local outfile="${IPERF_DIR}/profile_${cipher}.json"
        run_iperf_client "${outfile}" "${PORT_LISTEN}" "${PROFILE_STREAMS}" "${PROFILE_LENGTH}" 0 || true
        dump_sigusr1 "${FLOOS_PID}" "${FLOOC_PID}"
        {
            echo "# SIGUSR1 dump  cipher=${cipher}  floos=${FLOOS_PID} flooc=${FLOOC_PID}"
            echo "# floos ${FLOOS_LOG}"
            grep '\[PROFILE\]' "${FLOOS_LOG}" 2>/dev/null || true
            echo "# flooc ${FLOOC_LOG}"
            grep '\[PROFILE\]' "${FLOOC_LOG}" 2>/dev/null || true
        } > "${dump}"
        # Graceful stop so defer diagnostics.flush* also lands in the logs.
        local saved_floos_log="${FLOOS_LOG}"
        local saved_flooc_log="${FLOOC_LOG}"
        tear_down_tcp
        {
            echo ""
            echo "# after SIGTERM (defer flush)"
            echo "# floos"
            grep '\[PROFILE\]' "${saved_floos_log}" 2>/dev/null || true
            echo "# flooc"
            grep '\[PROFILE\]' "${saved_flooc_log}" 2>/dev/null || true
        } >> "${dump}"

        local c_total c_calls c_avg s_total s_calls s_avg
        IFS=$'\t' read -r c_total c_calls c_avg s_total s_calls s_avg <<< "$(perf_py profile-fields "${dump}")"
        perf_py append-jsonl "${JSONL_FILE}" \
            cell="profile_${cipher}" \
            kind=profile \
            mode=forward \
            protocol=tcp \
            cipher="${cipher}" \
            length="${PROFILE_LENGTH}" \
            streams="${PROFILE_STREAMS}" \
            tunnels="${tunnels}" \
            repeat=1 \
            status=ok \
            dump="${dump}" \
            client_encrypt_total_ns="${c_total}" \
            client_encrypt_calls="${c_calls}" \
            client_encrypt_avg_ns="${c_avg}" \
            server_encrypt_total_ns="${s_total}" \
            server_encrypt_calls="${s_calls}" \
            server_encrypt_avg_ns="${s_avg}"
        echo "[profile ${cipher}] wrote ${dump}"
        if grep -q 'avg=' "${dump}" 2>/dev/null; then
            grep 'avg=' "${dump}" | sed 's/^/  /'
        fi
    done
}

# --- meta + run --------------------------------------------------------------
build_floo
[[ -x "${FLOO_BIN_DIR}/floos" && -x "${FLOO_BIN_DIR}/flooc" ]] || fatal "floos/flooc missing under ${FLOO_BIN_DIR}"

HOST=$(hostname 2>/dev/null || echo unknown)
UNAME=$(uname -srm 2>/dev/null || echo unknown)
FLOO_VER=$("${FLOO_BIN_DIR}/floos" --version 2>/dev/null | awk '{print $NF; exit}' || true)
STARTED=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

python3 - "${META_FILE}" <<PY
import json, sys
json.dump({
    "version": "0.3.0",
    "floo_version": """${FLOO_VER}""",
    "optimize": """${OPTIMIZE}""",
    "duration_s": int("""${DURATION}"""),
    "repeats": int("""${REPEATS}"""),
    "metric": "receiver_sum",
    "cpu_count": int("""${CPU_COUNT}"""),
    "ciphers": """${CIPHERS[*]}""".split(),
    "narrow_ciphers": """${NARROW_CIPHERS[*]}""".split(),
    "lengths": """${LENGTHS[*]}""".split(),
    "streams": [int(x) for x in """${STREAMS[*]}""".split()],
    "tunnels": [int(x) for x in """${TUNNELS[*]}""".split()],
    "udp": {
        "cipher": """${UDP_CIPHER}""",
        "length": """${UDP_LENGTH}""",
        "streams": int("""${UDP_STREAMS}"""),
        "tunnels": 1,
        "bandwidth": """${UDP_BANDWIDTH}""",
    },
    "host": """${HOST}""",
    "uname": """${UNAME}""",
    "started_at": """${STARTED}""",
    "bench_dir": """${WORKDIR}""",
}, open(sys.argv[1], "w"), indent=2)
open(sys.argv[1], "a").write("\\n")
PY

print_coverage
echo ""

run_raw

echo ""
echo "=== forward TCP ==="
for cipher in "${CIPHERS[@]}"; do
    for tunnels in "${TUNNELS[@]}"; do
        echo "--- forward ${cipher} tunnels=${tunnels} ---"
        run_tcp_session forward "${cipher}" "${tunnels}"
    done
done

if [[ "${SKIP_REVERSE}" -eq 0 ]]; then
    echo ""
    echo "=== reverse TCP (narrow cipher set) ==="
    for cipher in "${NARROW_CIPHERS[@]}"; do
        for tunnels in "${TUNNELS[@]}"; do
            echo "--- reverse ${cipher} tunnels=${tunnels} ---"
            run_tcp_session reverse "${cipher}" "${tunnels}"
        done
    done
fi

if [[ "${SKIP_UDP}" -eq 0 ]]; then
    run_udp_cell
fi
if [[ "${SKIP_PROFILE}" -eq 0 ]]; then
    run_profile_dumps
fi

assemble_artifacts

if [[ "${WRITE_BASELINE}" == "1" ]]; then
    [[ -f "${RESULT_JSON}" ]] || fatal "results.json missing; cannot write baseline"
    perf_py export-baseline "${RESULT_JSON}" "${BASELINE_PATH}"
    echo "Wrote baseline ${BASELINE_PATH}"
fi

echo ""
echo "Artifacts:"
echo "  TSV:     ${TSV_FILE}"
echo "  JSON:    ${RESULT_JSON}"
echo "  summary: ${SUMMARY_FILE}"
echo "  profiles:${PROF_DIR}"
echo "  iperf:   ${IPERF_DIR}"
if [[ -f "${BASELINE_PATH}" && "${WRITE_BASELINE}" == "1" ]]; then
    echo "  baseline:${BASELINE_PATH}"
fi
echo ""
echo "Export baseline later (no re-run):"
echo "  ./scripts/perf_matrix.sh --export-baseline ${RESULT_JSON}"

if [[ "${FAILED_CELLS}" -gt 0 ]]; then
    echo "Completed with ${FAILED_CELLS} failed cell(s)." >&2
    exit 1
fi
