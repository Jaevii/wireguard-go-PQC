#!/usr/bin/env bash
# =============================================================================
# wireguard-go KEM handshake benchmark
#
# Measures handshake establishment latency.
# Bandwidth is deliberately excluded — symmetric encryption performance
# is independent of the KEM algorithm used for key establishment.
#
# Usage:
#   KEM_MODE=classic          bash benchmark.sh   # baseline
#   KEM_MODE=mlkem512         bash benchmark.sh
#   KEM_MODE=mlkem768         bash benchmark.sh
#   KEM_MODE=mlkem1024        bash benchmark.sh
#   KEM_MODE=hqc128           bash benchmark.sh
#   KEM_MODE=hqc192           bash benchmark.sh
#   KEM_MODE=hqc256           bash benchmark.sh
#   KEM_MODE=hybrid-mlkem512  bash benchmark.sh
#   KEM_MODE=hybrid-mlkem768  bash benchmark.sh
#   KEM_MODE=hybrid-mlkem1024 bash benchmark.sh
#   KEM_MODE=hybrid-hqc128    bash benchmark.sh
#   KEM_MODE=hybrid-hqc192    bash benchmark.sh
#   KEM_MODE=hybrid-hqc256    bash benchmark.sh
#
# Environment overrides:
#   WG_GO_BIN          path to wireguard-go binary  (default: ../wireguard-go)
#   WG_BIN             path to wg tool              (default: wg)
#   IF1 / IF2          interface names              (default: utun11 / utun12)
#   PORT1 / PORT2      listen ports                 (default: 51820 / 51821)
#   KEM_MODE           algorithm                    (default: classic)
#   HANDSHAKE_TRIALS   number of handshake trials   (default: 500)
# =============================================================================
set -euo pipefail

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
KEM_MODE="${KEM_MODE:-classic}"
HANDSHAKE_TRIALS="${HANDSHAKE_TRIALS:-100}"
RESULTS_DIR="$SCRIPT_DIR/results/$(date +%Y%m%d_%H%M%S)_${KEM_MODE}"
TMP_DIR="$(mktemp -d)"
PID1=""
PID2=""

# Standard Ethernet UDP payload limit (1500 - 20 IPv4 - 8 UDP)
MTU_LIMIT=1472

# =============================================================================
# Cleanup
# =============================================================================
cleanup() {
    set +e
    echo ""
    echo "--- Cleaning up ---"
    [[ -n "$PID1" ]] && sudo kill "$PID1" 2>/dev/null || true
    [[ -n "$PID2" ]] && sudo kill "$PID2" 2>/dev/null || true
    for iface in $(ifconfig -l 2>/dev/null || true); do
        if ifconfig "$iface" 2>/dev/null | grep -qE "${PEER1_IP}|${PEER2_IP}"; then
            sudo ifconfig "$iface" destroy 2>/dev/null || true
        fi
    done
    sudo route -q delete -host "$PEER1_IP" 2>/dev/null || true
    sudo route -q delete -host "$PEER2_IP" 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# =============================================================================
# Helpers
# =============================================================================
log()    { echo "[$(date +%H:%M:%S)] $*"; }
fail()   { echo "ERROR: $*" >&2; exit 1; }
ns_now() { python3 -c "import time; print(int(time.time_ns()))"; }

wait_for_iface() {
    local iface="$1" logfile="$2"
    for _ in $(seq 1 20); do
        ifconfig "$iface" >/dev/null 2>&1 && { log "$iface is up."; return 0; }
        sleep 0.5
    done
    echo "Error: $iface did not appear within 10s."
    tail -n 30 "$logfile" || true
    exit 1
}

wait_for_socket() {
    local iface="$1" logfile="$2"
    local sock="/var/run/wireguard/${iface}.sock"
    for _ in $(seq 1 20); do
        [[ -S "$sock" ]] && { log "$iface socket ready."; return 0; }
        sleep 0.5
    done
    echo "Error: $sock did not appear within 10s."
    tail -n 30 "$logfile" || true
    exit 1
}

# Force a fresh handshake on both peers.
# Both peers are removed and re-added so neither side retains any prior
# session state, handshake state, or cached index table entries.
reset_peers() {
    local p1_pub="$1"
    local p2_pub="$2"
    local p1_kem_pub="$3"
    local p2_kem_pub="$4"

    local p1_pub_hex p2_pub_hex
    p1_pub_hex=$(printf '%s' "$p1_pub" | base64 -d | xxd -p | tr -d '\n')
    p2_pub_hex=$(printf '%s' "$p2_pub" | base64 -d | xxd -p | tr -d '\n')

    local sock1="/var/run/wireguard/${IF1}.sock"
    local sock2="/var/run/wireguard/${IF2}.sock"

    # Remove peers first (separate transactions)
    printf 'set=1\npublic_key=%s\nremove=true\n\n' "$p2_pub_hex" \
        | sudo socat - "UNIX-CONNECT:$sock1" > /dev/null
    printf 'set=1\npublic_key=%s\nremove=true\n\n' "$p1_pub_hex" \
        | sudo socat - "UNIX-CONNECT:$sock2" > /dev/null

    sleep 0.3

    # Re-add peer + KEM key atomically in ONE UAPI transaction each.
    # This prevents Start() from firing before kemPublicKey is populated.
    {
        printf 'set=1\n'
        printf 'public_key=%s\n' "$p2_pub_hex"
        [[ -n "$p2_kem_pub" ]] && printf 'kem_public_key=%s\n' "$p2_kem_pub"
        printf 'allowed_ip=%s/32\n' "$PEER2_IP"
        printf 'endpoint=127.0.0.1:%s\n' "$PORT2"
        printf 'persistent_keepalive_interval=25\n'
        printf '\n'
    } | sudo socat - "UNIX-CONNECT:$sock1" > /tmp/uapi_sock1.txt

    {
        printf 'set=1\n'
        printf 'public_key=%s\n' "$p1_pub_hex"
        [[ -n "$p1_kem_pub" ]] && printf 'kem_public_key=%s\n' "$p1_kem_pub"
        printf 'allowed_ip=%s/32\n' "$PEER1_IP"
        printf 'endpoint=127.0.0.1:%s\n' "$PORT1"
        printf 'persistent_keepalive_interval=25\n'
        printf '\n'
    } | sudo socat - "UNIX-CONNECT:$sock2" > /tmp/uapi_sock2.txt

    sleep 0.1
}

# =============================================================================
# Preflight
# =============================================================================
echo "============================================"
echo " wireguard-go KEM handshake benchmark"
echo " Mode    : $KEM_MODE"
echo " Trials  : $HANDSHAKE_TRIALS"
echo "============================================"
echo ""
echo "=== Preflight checks ==="

case "$KEM_MODE" in
    classic|mlkem512|mlkem768|mlkem1024|hqc128|hqc192|hqc256|hybrid-mlkem512|hybrid-mlkem768|hybrid-mlkem1024|hybrid-hqc128|hybrid-hqc192|hybrid-hqc256) ;;
    *) fail "Unknown KEM_MODE '$KEM_MODE'. Valid: classic mlkem512 mlkem768 mlkem1024 hqc128 hybrid-mlkem512 hybrid-mlkem768 hybrid-mlkem1024 hybrid-hqc128" ;;
esac

command -v "$WG_BIN" >/dev/null 2>&1 || fail "'$WG_BIN' not found"
command -v python3   >/dev/null 2>&1 || fail "'python3' not found"
[[ -x "$WG_GO_BIN" ]]                || fail "wireguard-go binary not found: $WG_GO_BIN"

mkdir -p "$RESULTS_DIR"
echo "Binary  : $WG_GO_BIN"
echo "Results : $RESULTS_DIR"
echo ""
sudo -v

# =============================================================================
# Query sizes from binary — kem-types.go is the single source of truth.
# Requires --kem-info support in main.go (see implementation notes).
# =============================================================================
echo "=== Querying algorithm parameters from binary ==="
KEM_INFO="$(WIREGUARD_KEM="$KEM_MODE" "$WG_GO_BIN" --kem-info 2>&1)" \
    || fail "--kem-info flag not supported. Add it to main.go before benchmarking."

get_info() { echo "$KEM_INFO" | grep "^$1=" | cut -d= -f2; }

PUBKEY_BYTES=$(get_info pubkey_bytes)
CT_BYTES=$(get_info ciphertext_bytes)
SS_BYTES=$(get_info shared_secret_bytes)
MSG_INIT_BYTES=$(get_info msg_initiation_bytes)
MSG_RESP_BYTES=$(get_info msg_response_bytes)

echo "  pubkey_bytes        = $PUBKEY_BYTES"
echo "  ciphertext_bytes    = $CT_BYTES"
echo "  shared_secret_bytes = $SS_BYTES"
echo "  msg_initiation      = $MSG_INIT_BYTES bytes"
echo "  msg_response        = $MSG_RESP_BYTES bytes"

EXCEEDS_MTU=false
if [[ "$MSG_INIT_BYTES" -gt "$MTU_LIMIT" || "$MSG_RESP_BYTES" -gt "$MTU_LIMIT" ]]; then
    EXCEEDS_MTU=true
    echo ""
    echo "  WARNING: $KEM_MODE handshake messages exceed the standard MTU ($MTU_LIMIT bytes)."
    echo "  Initiation: ${MSG_INIT_BYTES}b  Response: ${MSG_RESP_BYTES}b"
    echo "  This benchmark runs on loopback (no MTU limit) so latency results are"
    echo "  not affected here, but note that HQC would require IP fragmentation or"
    echo "  WireGuard-layer segmentation on standard Ethernet paths."
fi
echo ""

# =============================================================================
# Key generation
# =============================================================================
echo "=== Generating keypairs ==="
P1_PRIV="$("$WG_BIN" genkey)"
P2_PRIV="$("$WG_BIN" genkey)"
P1_PUB="$(printf '%s' "$P1_PRIV" | "$WG_BIN" pubkey)"
P2_PUB="$(printf '%s' "$P2_PRIV" | "$WG_BIN" pubkey)"
log "Done."
echo ""

# =============================================================================
# Write configs
# =============================================================================
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

# =============================================================================
# Start interfaces
# WIREGUARD_KEM is passed via `env` so sudo does not strip it.
# =============================================================================
echo "=== Starting interfaces ==="

sudo env WIREGUARD_KEM="$KEM_MODE" "$WG_GO_BIN" --foreground "$IF1" \
    >"/tmp/${IF1}.log" 2>&1 & PID1=$!

sudo env WIREGUARD_KEM="$KEM_MODE" "$WG_GO_BIN" --foreground "$IF2" \
    >"/tmp/${IF2}.log" 2>&1 & PID2=$!

wait_for_iface  "$IF1" "/tmp/${IF1}.log"
wait_for_iface  "$IF2" "/tmp/${IF2}.log"
wait_for_socket "$IF1" "/tmp/${IF1}.log"
wait_for_socket "$IF2" "/tmp/${IF2}.log"

# macOS POINTOPOINT: ifconfig requires both local and destination address
sudo ifconfig "$IF1" inet "$PEER1_IP" "$PEER2_IP" up
sudo ifconfig "$IF2" inet "$PEER2_IP" "$PEER1_IP" up

sudo route -q delete "$PEER1_IP" 2>/dev/null || true
sudo route -q delete "$PEER2_IP" 2>/dev/null || true
sudo route -q add -host "$PEER2_IP" -interface "$IF1"
sudo route -q add -host "$PEER1_IP" -interface "$IF2"

log "Interfaces up."
echo ""

# =============================================================================
# Fetch each device's KEM public key via UAPI get.
# Must happen before any peer config so no handshake can fire with empty key.
# =============================================================================
# =============================================================================
# Fetch KEM public keys and configure peers.
# Classic mode has no KEM keypair, so we use setconf directly.
# Pure-KEM and hybrid modes must include the KEM key atomically with the peer
# config so no handshake fires before kemPublicKey is populated.
# =============================================================================
get_kem_pubkey() {
    local iface="$1"
    local sock="/var/run/wireguard/${iface}.sock"
    local kem_key
    kem_key=$(printf 'get=1\n\n' | sudo socat - "UNIX-CONNECT:$sock" 2>&1 \
        | sed -n '/^kem_public_key=/p' | sed 's/^kem_public_key=//' | tr -d '\r\n ')
    printf '%s' "$kem_key"
}

P1_KEM_PUB=$(get_kem_pubkey "$IF1")
P2_KEM_PUB=$(get_kem_pubkey "$IF2")

P1_PRIV_HEX=$(printf '%s' "$P1_PRIV" | base64 -d | xxd -p | tr -d '\n')
P2_PRIV_HEX=$(printf '%s' "$P2_PRIV" | base64 -d | xxd -p | tr -d '\n')
P1_PUB_HEX=$(printf '%s' "$P1_PUB" | base64 -d | xxd -p | tr -d '\n')
P2_PUB_HEX=$(printf '%s' "$P2_PUB" | base64 -d | xxd -p | tr -d '\n')

SOCK1="/var/run/wireguard/${IF1}.sock"
SOCK2="/var/run/wireguard/${IF2}.sock"

if [[ "$KEM_MODE" == "classic" ]]; then
    # Classic mode: no KEM key, standard setconf is fine
    sudo "$WG_BIN" setconf "$IF1" "$TMP_DIR/$IF1.conf"
    sudo "$WG_BIN" setconf "$IF2" "$TMP_DIR/$IF2.conf"
else
    # PQC modes: include KEM key atomically so Start() never fires with empty kemPublicKey
    if [[ -z "$P1_KEM_PUB" || -z "$P2_KEM_PUB" ]]; then
        fail "Failed to retrieve KEM public keys. Is WIREGUARD_KEM set correctly?"
    fi

    {
        printf 'set=1\n'
        printf 'private_key=%s\n' "$P1_PRIV_HEX"
        printf 'listen_port=%s\n' "$PORT1"
        printf 'public_key=%s\n'  "$P2_PUB_HEX"
        printf 'kem_public_key=%s\n' "$P2_KEM_PUB"
        printf 'allowed_ip=%s/32\n' "$PEER2_IP"
        printf 'endpoint=127.0.0.1:%s\n' "$PORT2"
        printf 'persistent_keepalive_interval=25\n'
        printf '\n'
    } | sudo socat - "UNIX-CONNECT:$SOCK1" > /dev/null

    {
        printf 'set=1\n'
        printf 'private_key=%s\n' "$P2_PRIV_HEX"
        printf 'listen_port=%s\n' "$PORT2"
        printf 'public_key=%s\n'  "$P1_PUB_HEX"
        printf 'kem_public_key=%s\n' "$P1_KEM_PUB"
        printf 'allowed_ip=%s/32\n' "$PEER1_IP"
        printf 'endpoint=127.0.0.1:%s\n' "$PORT1"
        printf 'persistent_keepalive_interval=25\n'
        printf '\n'
    } | sudo socat - "UNIX-CONNECT:$SOCK2" > /dev/null
fi

# =============================================================================
# 1. Algorithm metadata
# =============================================================================
echo "=== [1/2] Algorithm parameters ==="
{
    echo "algorithm=$KEM_MODE"
    echo "pubkey_bytes=$PUBKEY_BYTES"
    echo "ciphertext_bytes=$CT_BYTES"
    echo "shared_secret_bytes=$SS_BYTES"
    echo "msg_initiation_bytes=$MSG_INIT_BYTES"
    echo "msg_response_bytes=$MSG_RESP_BYTES"
    echo "exceeds_mtu=$EXCEEDS_MTU"
    echo "mtu_limit=$MTU_LIMIT"
} | tee "$RESULTS_DIR/sizes.txt"
echo ""

# =============================================================================
# Baseline tunnel RTT measurement
#
# Measures the cost of ping process startup + userspace TUN round trip +
# Go goroutine wakeup with an already-established session — i.e. everything
# in the timed window that is NOT the handshake itself.
#
# This is gives a closer approximation of true handshake crypto cost. 
#
# Must run while a session is established (after setconf, before any
# reset_peers call) so no handshake is triggered during measurement.
# =============================================================================
echo "=== Baseline tunnel RTT (established session, no handshake) ==="

reset_peers "$P1_PUB" "$P2_PUB" "$P1_KEM_PUB" "$P2_KEM_PUB"

# Wait for session to establish by pinging rather than checking timestamps,
# since lastHandshakeNano may not update reliably after raw UAPI peer re-add.
log "Waiting for tunnel to pass traffic..."
for _ in $(seq 1 20); do
    if ping -c 1 -W 500 -s 8 "$PEER2_IP" >/dev/null 2>&1; then
        log "Tunnel is up."
        break
    fi
    sleep 0.5
done

RTT_SAMPLES=()
RTT_COUNT=${HANDSHAKE_TRIALS}
RTT_DISCARD=25
for ((i = 1; i <= RTT_COUNT + RTT_DISCARD; i++)); do
    T0=$(ns_now)
    ping -c 1 -W 1000 -s 8 "$PEER2_IP" >/dev/null 2>&1
    T1=$(ns_now)

    # Only record after the discard window
    if [[ "$i" -gt "$RTT_DISCARD" ]]; then
        RTT_SAMPLES+=("$(python3 -c "print(f'{($T1-$T0)/1e6:.3f}')")")
    fi
done

BASELINE_RTT=$(printf '%s\n' "${RTT_SAMPLES[@]}" | awk '
    BEGIN { sum=0; n=0 }
    { sum += $1; n++ }
    END { printf "%.3f", sum/n }')

echo "  Baseline tunnel RTT: ${BASELINE_RTT}ms (avg of $RTT_COUNT pings, session already established)"
echo "  This represents ping overhead + userspace TUN cost with no handshake."
echo "  True handshake crypto cost ≈ measured latency − ${BASELINE_RTT}ms"
echo ""

# Append to sizes.txt
echo "baseline_tunnel_rtt_ms=$BASELINE_RTT" >> "$RESULTS_DIR/sizes.txt"

# =============================================================================
# 2. Handshake establishment latency
#
# What is measured:
#   T_START  immediately before ping is sent
#   T_END    immediately after ping reply is received
#
#   Interval covers:
#     - CreateMessageInitiation  (keygen + KEM keypair generation on initiator)
#     - Msg1 loopback transit
#     - ConsumeMessageInitiation + CreateMessageResponse  (encapsulation on responder)
#     - Msg2 loopback transit
#     - ConsumeMessageResponse   (decapsulation on initiator)
#     - BeginSymmetricSession    (session key derivation on both sides)
#     - First encrypted ping packet RTT (~0.1ms on loopback, negligible)
#
#   A failed ping means either a handshake timeout or a session key
#   mismatch — both indicate a broken KEM integration.
#
# Warmup:
#   25 unrecorded handshakes before the main loop allow liboqs shared
#   library initialisation and the Go runtime to reach steady state.
#   Without warmup, the first few trials are inflated by dlopen() cost.
# =============================================================================
echo "=== [2/2] Handshake latency ($HANDSHAKE_TRIALS trials) ==="

WARMUP_COUNT=25
echo "  Warming up ($WARMUP_COUNT unrecorded handshakes)..."
for _ in $(seq 1 "$WARMUP_COUNT"); do
    reset_peers "$P1_PUB" "$P2_PUB" "$P1_KEM_PUB" "$P2_KEM_PUB"
    ping -c 1 -W 2000 -s 8 "$PEER2_IP" >/dev/null 2>&1 || true
done
log "Warmup complete. Starting recorded trials."
echo ""

LATENCIES=()
FAILED_TRIALS=0

for i in $(seq 1 "$HANDSHAKE_TRIALS"); do
    reset_peers "$P1_PUB" "$P2_PUB" "$P1_KEM_PUB" "$P2_KEM_PUB"

    T_START=$(ns_now)

    if ! ping -c 1 -W 2000 -s 8 "$PEER2_IP" >/dev/null 2>&1; then
        echo "  Trial $i: FAILED — ping did not return."
        echo "  Likely causes: handshake timeout, or session key mismatch"
        echo "  (wrong session keys silently drop the encrypted ping)."
        echo "  $IF1 log:"
        tail -n 15 "/tmp/${IF1}.log" || true
        FAILED_TRIALS=$((FAILED_TRIALS + 1))
        if [[ "$FAILED_TRIALS" -gt $((HANDSHAKE_TRIALS / 20)) ]]; then
            echo ""
            echo "ERROR: >5% of trials failed. Aborting."
            echo "Check mixKey insertion point in noise-protocol.go — the KEM"
            echo "shared secret must be mixed at the same transcript position"
            echo "on both the initiator and responder."
            exit 3
        fi
        continue
    fi

    T_END=$(ns_now)
    LATENCY_MS=$(python3 -c "print(f'{($T_END - $T_START) / 1e6:.3f}')")
    LATENCIES+=("$LATENCY_MS")

    # Print first 10 trials individually, then every 50 as progress marker
    if [[ "$i" -le 10 ]] || [[ $(( i % 50 )) -eq 0 ]]; then
        echo "  Trial $i/$HANDSHAKE_TRIALS: ${LATENCY_MS} ms"
    fi
done

SUCCESSFUL_TRIALS=${#LATENCIES[@]}
echo ""
log "Trials complete: $SUCCESSFUL_TRIALS successful, $FAILED_TRIALS failed."
echo ""

# Raw CSV for analyze.py and run_all_modes.sh
printf '%s\n' "${LATENCIES[@]}" > "$RESULTS_DIR/latency_raw.csv"

# Summary statistics computed in awk (no external dependencies)
{
    echo "algorithm=$KEM_MODE"
    echo "trials_requested=$HANDSHAKE_TRIALS"
    echo "trials_successful=$SUCCESSFUL_TRIALS"
    echo "trials_failed=$FAILED_TRIALS"
    printf '%s\n' "${LATENCIES[@]}" | awk '
        BEGIN { sum=0; sum2=0; min=9999999; max=0; n=0 }
        {
            a[n++] = $1
            sum   += $1
            sum2  += $1 * $1
            if ($1 < min) min = $1
            if ($1 > max) max = $1
        }
        END {
            mean   = sum / n
            stddev = sqrt(sum2/n - mean*mean)

            # Insertion sort for percentiles
            for (i = 1; i < n; i++) {
                key = a[i]; j = i - 1
                while (j >= 0 && a[j] > key) { a[j+1] = a[j]; j-- }
                a[j+1] = key
            }

            printf "latency_mean_ms=%.3f\n",   mean
            printf "latency_stddev_ms=%.3f\n", stddev
            printf "latency_min_ms=%.3f\n",    min
            printf "latency_p50_ms=%.3f\n",    a[int(n * 0.50)]
            printf "latency_p95_ms=%.3f\n",    a[int(n * 0.95)]
            printf "latency_p99_ms=%.3f\n",    a[int(n * 0.99)]
            printf "latency_max_ms=%.3f\n",    max
        }'
} | tee "$RESULTS_DIR/latency_summary.txt"

MEAN_MS=$(grep "^latency_mean_ms=" "$RESULTS_DIR/latency_summary.txt" | cut -d= -f2)
ADJUSTED_MS=$(python3 -c "print(f'{max(0.0, $MEAN_MS - $BASELINE_RTT):.3f}')")

echo ""

# =============================================================================
# Summary
# =============================================================================
echo "============================================"
echo " Benchmark complete"
echo " Algorithm : $KEM_MODE"
echo " Trials    : $SUCCESSFUL_TRIALS / $HANDSHAKE_TRIALS successful"
echo " Mean latency       : ${MEAN_MS}ms"
echo " Baseline RTT       : ${BASELINE_RTT}ms"
echo " Corrected latency  : ${ADJUSTED_MS}ms (approx. crypto cost only)"
echo " Results            : $RESULTS_DIR"
echo "============================================"
echo ""
echo "Files written:"
ls -lh "$RESULTS_DIR"