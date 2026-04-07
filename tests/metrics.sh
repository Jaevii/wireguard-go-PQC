#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# wireguard-go benchmark
# PQC support (ML-KEM, HQC) is stubbed out and marked with TODO comments.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WG_GO_BIN="${WG_GO_BIN:-$REPO_ROOT/wireguard-go}"
WG_BIN="${WG_BIN:-wg}"
IF1="${IF1:-utun11}"
IF2="${IF2:-utun12}"
PORT1="${PORT1:-51820}"
PORT2="${PORT2:-51821}"
PEER1_IP="10.199.0.1"
PEER2_IP="10.199.0.2"  
ALGO="x25519"   # TODO: replace with ALGO="${ALGO:-x25519}" once PQC is integrated
HANDSHAKE_TRIALS="${HANDSHAKE_TRIALS:-10}"
RESULTS_DIR="$SCRIPT_DIR/results/$(date +%Y%m%d_%H%M%S)_${ALGO}"
TMP_DIR="$(mktemp -d)"
PID1=""
PID2=""

# =============================================================================
# TODO (Phase 2): populate these with real liboqs-go values once integrated.
# Source: https://github.com/open-quantum-safe/liboqs
# =============================================================================
declare -A PUBKEY_SIZE=(  [x25519]=32   ) # [ml-kem-768]=1184  [hqc-128]=2249
declare -A CT_SIZE=(      [x25519]=0    ) # [ml-kem-768]=1088  [hqc-128]=4481
declare -A SS_SIZE=(      [x25519]=32   ) # [ml-kem-768]=32    [hqc-128]=64

# ── Cleanup ──────────────────────────────────────────────────────────
cleanup() {
    set +e
    [[ -n "$PID1" ]] && sudo kill "$PID1" >/dev/null 2>&1
    [[ -n "$PID2" ]] && sudo kill "$PID2" >/dev/null 2>&1
    # Kill any iperf3 servers left over from this or previous runs
    pkill -f "iperf3 -s" 2>/dev/null || true
    # Destroy any utun interface carrying our test addresses
    for iface in $(ifconfig -l); do
        if ifconfig "$iface" 2>/dev/null | grep -qE "${PEER1_IP}|${PEER2_IP}"; then
            echo "  Destroying stale interface: $iface"
            sudo ifconfig "$iface" destroy >/dev/null 2>&1 || true
        fi
    done
    sudo route -q delete -host "$PEER1_IP" 2>/dev/null || true
    sudo route -q delete -host "$PEER2_IP" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# ── Pre-checks ──────────────────────────────────────────────────────────
echo "=== Preflight checks ==="
command -v "$WG_BIN" >/dev/null 2>&1 || { echo "Error: '$WG_BIN' not found"; exit 1; }
command -v iperf3    >/dev/null 2>&1 || { echo "Error: 'iperf3' not found (brew install iperf3)"; exit 1; }
command -v python3   >/dev/null 2>&1 || { echo "Error: 'python3' not found"; exit 1; }
[[ -x "$WG_GO_BIN" ]] || {
    echo "Error: wireguard-go binary not found: $WG_GO_BIN"
    echo "Tip: run 'make' in repo root, or set WG_GO_BIN=/path/to/binary"
    exit 1
}

mkdir -p "$RESULTS_DIR"
echo "Binary  : $WG_GO_BIN"
echo "Results : $RESULTS_DIR"
echo "Algo    : $ALGO (baseline — classic only)"
echo ""

sudo -v  # prime sudo credentials upfront

# ── Key generation ────────────────────────────────────────────────────────────
echo "=== Generating keypairs ==="
P1_PRIV="$($WG_BIN genkey)"
P2_PRIV="$($WG_BIN genkey)"
P1_PUB="$(printf '%s' "$P1_PRIV" | $WG_BIN pubkey)"
P2_PUB="$(printf '%s' "$P2_PRIV" | $WG_BIN pubkey)"
echo "Done."
echo ""

# ── Write configs ─────────────────────────────────────────────────────────────
cat > "$TMP_DIR/$IF1.conf" <<EOF
[Interface]
PrivateKey = $P1_PRIV
ListenPort = $PORT1
[Peer]
PublicKey = $P2_PUB
AllowedIPs = $PEER2_IP/32
Endpoint = 127.0.0.1:$PORT2
PersistentKeepalive = 2
EOF

cat > "$TMP_DIR/$IF2.conf" <<EOF
[Interface]
PrivateKey = $P2_PRIV
ListenPort = $PORT2
[Peer]
PublicKey = $P1_PUB
AllowedIPs = $PEER1_IP/32
Endpoint = 127.0.0.1:$PORT1
PersistentKeepalive = 2
EOF

# ── Start interfaces ──────────────────────────────────────────────────────────
echo "=== Starting interfaces ==="

sudo "$WG_GO_BIN" --foreground "$IF1" >"/tmp/${IF1}.log" 2>&1 & PID1=$!
sudo "$WG_GO_BIN" --foreground "$IF2" >"/tmp/${IF2}.log" 2>&1 & PID2=$!

# Poll until both interfaces appear (max 10s each)
wait_for_iface() {
    local iface="$1"
    local log="$2"
    for _ in $(seq 1 20); do
        if ifconfig "$iface" >/dev/null 2>&1; then
            echo "  $iface interface is up."
            break
        fi
        sleep 0.5
    done

    if ! ifconfig "$iface" >/dev/null 2>&1; then
        echo "Error: $iface did not appear within 10s."
        echo "--- log tail ---"
        tail -n 20 "$log" || true
        exit 1
    fi

    # Wait for the wireguard-go control socket to be ready
    echo "  Waiting for $iface control socket..."
    for _ in $(seq 1 20); do
        if [[ -S "/var/run/wireguard/${iface}.sock" ]]; then
            echo "  $iface socket ready."
            return 0
        fi
        sleep 0.5
    done

    echo "Error: /var/run/wireguard/${iface}.sock did not appear within 10s."
    echo "--- log tail ---"
    tail -n 20 "$log" || true
    exit 1
}

wait_for_iface "$IF1" "/tmp/${IF1}.log"
wait_for_iface "$IF2" "/tmp/${IF2}.log"

# On macOS utun (POINTOPOINT), specify both local and destination address.
sudo ifconfig "$IF1" inet "$PEER1_IP" "$PEER2_IP" up
sudo ifconfig "$IF2" inet "$PEER2_IP" "$PEER1_IP" up

# ── Flush any stale routes for our address range ──────────────────────────
echo "  Flushing stale routes..."
sudo route -q delete "$PEER1_IP" 2>/dev/null || true
sudo route -q delete "$PEER2_IP" 2>/dev/null || true

# ── Add explicit host routes through the correct interfaces ───────────────
sudo route -q add -host "$PEER2_IP" -interface "$IF1"
sudo route -q add -host "$PEER1_IP" -interface "$IF2"

sudo "$WG_BIN" setconf "$IF1" "$TMP_DIR/$IF1.conf"
sudo "$WG_BIN" setconf "$IF2" "$TMP_DIR/$IF2.conf"
echo "Interfaces up."
echo ""

# ── 1. Static sizes ───────────────────────────────────────────────────────────
echo "=== [1/4] Key and ciphertext sizes ==="
{
    echo "algorithm=$ALGO"
    echo "pubkey_bytes=${PUBKEY_SIZE[$ALGO]}"
    echo "ciphertext_bytes=${CT_SIZE[$ALGO]}"
    echo "shared_secret_bytes=${SS_SIZE[$ALGO]}"
    # TODO (Phase 2): these will be read dynamically from liboqs-go once
    # PQC is integrated, rather than hardcoded here.
} | tee "$RESULTS_DIR/sizes.txt"
echo ""

# ── 2. Handshake latency ──────────────────────────────────────────────────────
echo "=== [2/4] Handshake latency ($HANDSHAKE_TRIALS trials) ==="
LATENCIES=()

for i in $(seq 1 "$HANDSHAKE_TRIALS"); do
    # Remove and re-add peer to force a completely fresh handshake each trial
    sudo "$WG_BIN" set "$IF1" peer "$P2_PUB" remove
    sudo "$WG_BIN" set "$IF1" peer "$P2_PUB" \
        allowed-ips "$PEER2_IP/32" \
        endpoint "127.0.0.1:$PORT2" \
        persistent-keepalive 2
    sleep 0.2

    T_START=$(python3 -c "import time; print(int(time.time_ns()))")

    # Poll until handshake timestamp is non-zero (100ms polling, 5s timeout)
    HANDSHAKE_SEEN=0
    for _ in $(seq 1 50); do
        TS="$(sudo "$WG_BIN" show "$IF1" latest-handshakes | awk 'NR==1 {print $2}')"
        if [[ "${TS:-0}" -gt 0 ]]; then HANDSHAKE_SEEN=1; break; fi
        sleep 0.1
    done

    if [[ "$HANDSHAKE_SEEN" -eq 0 ]]; then
        echo "  Trial $i: TIMEOUT — handshake not seen within 5s"
        echo "  --- $IF1 log tail ---"
        tail -n 20 "/tmp/${IF1}.log" || true
        exit 2
    fi

    T_END=$(python3 -c "import time; print(int(time.time_ns()))")
    LATENCY_MS=$(python3 -c "print(f'{($T_END - $T_START) / 1e6:.2f}')")
    LATENCIES+=("$LATENCY_MS")
    echo "  Trial $i: ${LATENCY_MS} ms"
done

{
    echo "algorithm=$ALGO"
    echo "trials=$HANDSHAKE_TRIALS"
    printf '%s\n' "${LATENCIES[@]}" | awk '
        BEGIN { sum=0; min=9999999; max=0; n=0 }
        { sum+=$1; n++
          if($1<min) min=$1
          if($1>max) max=$1 }
        END {
            printf "latency_mean_ms=%.2f\n", sum/n
            printf "latency_min_ms=%.2f\n",  min
            printf "latency_max_ms=%.2f\n",  max
        }'
} | tee "$RESULTS_DIR/latency.txt"
echo ""

# ── Restore clean peer state ────────────────────────
echo "Restoring peer state before bandwidth test..."

# Re-add both peers cleanly after the handshake trials
sudo "$WG_BIN" set "$IF1" peer "$P2_PUB" remove 2>/dev/null || true
sudo "$WG_BIN" set "$IF2" peer "$P1_PUB" remove 2>/dev/null || true
sleep 0.3

sudo "$WG_BIN" set "$IF1" peer "$P2_PUB" \
    allowed-ips "$PEER2_IP/32" \
    endpoint "127.0.0.1:$PORT2" \
    persistent-keepalive 2

sudo "$WG_BIN" set "$IF2" peer "$P1_PUB" \
    allowed-ips "$PEER1_IP/32" \
    endpoint "127.0.0.1:$PORT1" \
    persistent-keepalive 2

# Wait for handshake to re-establish
echo "Waiting for tunnel to re-establish..."
for _ in $(seq 1 30); do
    TS1="$(sudo "$WG_BIN" show "$IF1" latest-handshakes | awk 'NR==1 {print $2}')"
    TS2="$(sudo "$WG_BIN" show "$IF2" latest-handshakes | awk 'NR==1 {print $2}')"
    if [[ "${TS1:-0}" -gt 0 && "${TS2:-0}" -gt 0 ]]; then
        echo "Tunnel re-established."
        break
    fi
    sleep 0.5
done

# Verify ping before proceeding
if ! ping -c 1 -W 1000 "$PEER2_IP" >/dev/null 2>&1; then
    echo "Error: tunnel is up but ping to $PEER2_IP fails."
    echo "WireGuard state:"
    sudo "$WG_BIN" show "$IF1"
    sudo "$WG_BIN" show "$IF2"
    echo "Routing table:"
    netstat -rn | grep -E "$PEER1_IP|$PEER2_IP" || true
    exit 1
fi
echo "Tunnel verified — ping OK."
echo ""

# ── 3. Bandwidth ──────────────────────────────────────────────────────────────
echo "=== [3/4] Bandwidth ==="

# Kill any iperf3 server left over from a previous run
pkill -f "iperf3 -s" 2>/dev/null || true
sleep 0.5

# Start iperf3 server in background as a tracked process (--daemon is
# unreliable on macOS — keep it as a normal background job instead)
iperf3 -s -B "$PEER1_IP" --json \
    --logfile "$RESULTS_DIR/iperf_server.log" &
IPERF_SERVER_PID=$!

# Give the server time to bind
sleep 1

# Verify the server actually started before attempting client connections
if ! kill -0 "$IPERF_SERVER_PID" 2>/dev/null; then
    echo "Error: iperf3 server failed to start. Server log:"
    cat "$RESULTS_DIR/iperf_server.log" || true
    exit 1
fi

echo "  TCP throughput (20s)..."
if ! iperf3 -c "$PEER1_IP" -t 20 --json \
        > "$RESULTS_DIR/tcp_throughput.json" 2>&1; then
    echo "  TCP test failed. Server log:"
    cat "$RESULTS_DIR/iperf_server.log" || true
    exit 1
fi

# iperf3 server exits after one client by default (-1 flag).
# Restart it for the UDP run.
iperf3 -s -B "$PEER1_IP" --json \
    --logfile "$RESULTS_DIR/iperf_server.log" &
IPERF_SERVER_PID=$!
sleep 1

echo "  UDP throughput (20s)..."
if ! iperf3 -c "$PEER1_IP" -u -b 0 -t 20 --json \
        > "$RESULTS_DIR/udp_throughput.json" 2>&1; then
    echo "  UDP test failed. Server log:"
    cat "$RESULTS_DIR/iperf_server.log" || true
    exit 1
fi

kill "$IPERF_SERVER_PID" 2>/dev/null || true

python3 - "$RESULTS_DIR/tcp_throughput.json" "$RESULTS_DIR/udp_throughput.json" <<'PYEOF'
import json, sys
for path, label in zip(sys.argv[1:], ["TCP", "UDP"]):
    try:
        d = json.load(open(path))
        bps = d["end"]["sum_received"]["bits_per_second"]
        print(f"  {label} throughput: {bps/1e6:.1f} Mbps")
    except Exception as e:
        print(f"  {label}: could not parse ({e})")
PYEOF
echo ""

# ── 4. CPU overhead ───────────────────────────────────────────────────────────
echo "=== [4/4] CPU and memory overhead ==="

# Sample memory usage before the transfer
echo "  Memory usage (before transfer):"
ps -o pid,rss,vsz,command -p "$PID1" "$PID2" | tee -a "$RESULTS_DIR/memory.txt"
echo "" >> "$RESULTS_DIR/memory.txt"

# Run iperf3 in background while sampling CPU
iperf3 -c "$PEER1_IP" -t 20 > /dev/null 2>&1 &
IPERF_BG=$!

top -l 20 -s 1 -stats pid,cpu,command \
    | grep -E "wireguard|iperf" > "$RESULTS_DIR/cpu_usage.txt" 2>&1 || true

wait "$IPERF_BG" 2>/dev/null || true

# Sample memory usage after the transfer
echo "  Memory usage (after transfer):"
ps -o pid,rss,vsz,command -p "$PID1" "$PID2" | tee -a "$RESULTS_DIR/memory.txt"

echo "  CPU samples saved to cpu_usage.txt"
echo "  Memory samples saved to memory.txt"
echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo "============================================"
echo " Baseline benchmark complete"
echo " Algorithm : $ALGO"
echo " Results   : $RESULTS_DIR"
echo "============================================"
echo ""
echo "Files written:"
ls -lh "$RESULTS_DIR"