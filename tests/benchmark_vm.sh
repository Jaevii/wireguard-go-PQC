#!/usr/bin/env bash
# =============================================================================
# wireguard-go KEM handshake benchmark — two-host version
#
# Run this script on VM1 (initiator, 10.27.8.10).
# VM2 (responder, 10.27.8.11) is controlled via passwordless SSH.
#
# Both VMs must have the wireguard-go binary at ~/wireguard-go-PQC/wireguard-go
#
# Usage:
#   KEM_MODE=classic          bash benchmark_two_host.sh
#   KEM_MODE=mlkem512         bash benchmark_two_host.sh
#   KEM_MODE=mlkem768         bash benchmark_two_host.sh
#   KEM_MODE=mlkem1024        bash benchmark_two_host.sh
#   KEM_MODE=hqc128           bash benchmark_two_host.sh
#   KEM_MODE=hqc192           bash benchmark_two_host.sh
#   KEM_MODE=hqc256           bash benchmark_two_host.sh
#   KEM_MODE=hybrid-mlkem512  bash benchmark_two_host.sh
#   KEM_MODE=hybrid-mlkem768  bash benchmark_two_host.sh
#   KEM_MODE=hybrid-mlkem1024 bash benchmark_two_host.sh
#   KEM_MODE=hybrid-hqc128    bash benchmark_two_host.sh
#   KEM_MODE=hybrid-hqc192    bash benchmark_two_host.sh
#   KEM_MODE=hybrid-hqc256    bash benchmark_two_host.sh
#
# Environment overrides:
#   WG_GO_BIN        path to wireguard-go binary  (default: ~/wireguard-go-PQC/wireguard-go)
#   WG_BIN           path to wg tool              (default: wg)
#   VM2_HOST         VM2 SSH host                 (default: 10.27.8.11)
#   VM2_USER         VM2 SSH user                 (default: jaevii)
#   KEM_MODE         algorithm                    (default: classic)
#   HANDSHAKE_TRIALS number of handshake trials   (default: 1500)
# =============================================================================
set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$HOME/wireguard-go-PQC"

WG_GO_BIN="${WG_GO_BIN:-$REPO_ROOT/wireguard-go}"
WG_BIN="${WG_BIN:-wg}"

# VM1 = initiator, VM2 = responder
VM1_HOST_IP="10.27.8.10"
VM2_HOST="${VM2_HOST:-10.27.8.11}"
VM2_USER="${VM2_USER:-jaevii}"

# WireGuard tunnel IPs (separate from host IPs)
PEER1_IP="10.199.0.1"   # VM1 tunnel IP
PEER2_IP="10.199.0.2"   # VM2 tunnel IP

# WireGuard interface name (wg0 on both VMs)
IF="wg0"

# Ports
PORT1="51820"   # VM1 listens here
PORT2="51820"   # VM2 listens here

KEM_MODE="${KEM_MODE:-classic}"
HANDSHAKE_TRIALS="${HANDSHAKE_TRIALS:-1500}"

RESULTS_DIR="$SCRIPT_DIR/results/$(date +%Y%m%d_%H%M%S)_${KEM_MODE}"
TMP_DIR="$(mktemp -d)"

# Standard Ethernet UDP payload limit (1500 - 20 IPv4 - 8 UDP)
MTU_LIMIT=1472

# SSH shorthand to VM2
VM2="ssh -o StrictHostKeyChecking=no -o BatchMode=yes ${VM2_USER}@${VM2_HOST}"

# =============================================================================
# Cleanup — tears down both VMs
# =============================================================================
cleanup() {
    set +e
    echo ""
    echo "--- Cleaning up ---"

    # Local (VM1)
    sudo ip link delete "$IF" 2>/dev/null || true
    sudo pkill -f "wireguard-go.*$IF" 2>/dev/null || true

    # Remote (VM2)
    $VM2 "sudo ip link delete $IF 2>/dev/null; sudo pkill -f 'wireguard-go.*$IF' 2>/dev/null; true" 2>/dev/null || true

    rm -rf "$TMP_DIR"
    echo "--- Done ---"
}
trap cleanup EXIT INT TERM

# =============================================================================
# Helpers
# =============================================================================
log()    { echo "[$(date +%H:%M:%S)] $*"; }
fail()   { echo "ERROR: $*" >&2; exit 1; }
ns_now() { python3 -c "import time; print(int(time.time_ns()))"; }

# Wait for a local WireGuard socket to appear
wait_for_socket_local() {
    local iface="$1"
    local sock="/var/run/wireguard/${iface}.sock"
    for _ in $(seq 1 20); do
        [[ -S "$sock" ]] && { log "Local $iface socket ready."; return 0; }
        sleep 0.5
    done
    fail "Local socket $sock did not appear within 10s."
}

# Wait for remote WireGuard socket to appear on VM2
wait_for_socket_remote() {
    local iface="$1"
    local sock="/var/run/wireguard/${iface}.sock"
    for _ in $(seq 1 20); do
        $VM2 "[[ -S '$sock' ]]" 2>/dev/null && { log "Remote $iface socket ready."; return 0; }
        sleep 0.5
    done
    fail "Remote socket $sock did not appear within 10s."
}

# =============================================================================
# Reset peers on BOTH VMs between trials to force a fresh handshake.
# VM1 reset is done locally; VM2 reset is done over SSH.
# =============================================================================
reset_peers() {
    local p1_pub="$1"
    local p2_pub="$2"
    local p1_kem_pub="$3"
    local p2_kem_pub="$4"

    local p1_pub_hex p2_pub_hex
    p1_pub_hex=$(printf '%s' "$p1_pub" | base64 -d | xxd -p | tr -d '\n')
    p2_pub_hex=$(printf '%s' "$p2_pub" | base64 -d | xxd -p | tr -d '\n')

    local sock1="/var/run/wireguard/${IF}.sock"
    local sock2="/var/run/wireguard/${IF}.sock"   # same name on VM2

    # --- VM1: remove then re-add VM2 as peer ---
    printf 'set=1\npublic_key=%s\nremove=true\n\n' "$p2_pub_hex" \
        | sudo socat - "UNIX-CONNECT:$sock1" > /dev/null

    sleep 0.2

    {
        printf 'set=1\n'
        printf 'public_key=%s\n' "$p2_pub_hex"
        [[ -n "$p2_kem_pub" ]] && printf 'kem_public_key=%s\n' "$p2_kem_pub"
        printf 'allowed_ip=%s/32\n' "$PEER2_IP"
        printf 'endpoint=%s:%s\n' "$VM2_HOST" "$PORT2"
        printf 'persistent_keepalive_interval=25\n'
        printf '\n'
    } | sudo socat - "UNIX-CONNECT:$sock1" > /dev/null

    # --- VM2: remove then re-add VM1 as peer (over SSH) ---
    $VM2 "printf 'set=1\npublic_key=${p1_pub_hex}\nremove=true\n\n' \
        | sudo socat - UNIX-CONNECT:$sock2" > /dev/null

    sleep 0.2

    local kem_line=""
    [[ -n "$p1_kem_pub" ]] && kem_line="printf 'kem_public_key=%s\n' '${p1_kem_pub}';"

    $VM2 "{ \
        printf 'set=1\n'; \
        printf 'public_key=%s\n' '${p1_pub_hex}'; \
        ${kem_line} \
        printf 'allowed_ip=%s/32\n' '${PEER1_IP}'; \
        printf 'endpoint=%s:%s\n' '${VM1_HOST_IP}' '${PORT1}'; \
        printf 'persistent_keepalive_interval=25\n'; \
        printf '\n'; \
    } | sudo socat - UNIX-CONNECT:$sock2" > /dev/null

    sleep 0.1
}

# =============================================================================
# Preflight checks
# =============================================================================
echo "============================================"
echo " wireguard-go KEM handshake benchmark"
echo " Mode    : $KEM_MODE"
echo " Trials  : $HANDSHAKE_TRIALS"
echo " VM1     : $VM1_HOST_IP (initiator, local)"
echo " VM2     : $VM2_HOST (responder, SSH)"
echo "============================================"
echo ""
echo "=== Preflight checks ==="

case "$KEM_MODE" in
    classic|mlkem512|mlkem768|mlkem1024|hqc128|hqc192|hqc256|\
    hybrid-mlkem512|hybrid-mlkem768|hybrid-mlkem1024|\
    hybrid-hqc128|hybrid-hqc192|hybrid-hqc256) ;;
    *) fail "Unknown KEM_MODE '$KEM_MODE'." ;;
esac

command -v "$WG_BIN"  >/dev/null 2>&1 || fail "'$WG_BIN' not found"
command -v python3    >/dev/null 2>&1 || fail "'python3' not found"
command -v socat      >/dev/null 2>&1 || fail "'socat' not found — install with: sudo apt install socat"
[[ -x "$WG_GO_BIN" ]]                 || fail "wireguard-go binary not found: $WG_GO_BIN"

# Check SSH to VM2 works
log "Testing SSH to VM2..."
$VM2 "echo 'VM2 reachable'" || fail "Cannot SSH to ${VM2_USER}@${VM2_HOST}. Check passwordless SSH setup."

# Check remote binary exists
$VM2 "[[ -x '$REPO_ROOT/wireguard-go' ]]" \
    || fail "wireguard-go binary not found on VM2 at $REPO_ROOT/wireguard-go"

# Check socat on VM2
$VM2 "command -v socat" >/dev/null 2>&1 \
    || fail "'socat' not found on VM2 — install with: sudo apt install socat"

mkdir -p "$RESULTS_DIR"
echo "Binary  : $WG_GO_BIN"
echo "Results : $RESULTS_DIR"
echo ""
sudo -v
$VM2 "sudo -n true" 2>/dev/null || fail "VM2 user '$VM2_USER' cannot run sudo without password. Add to sudoers."

# =============================================================================
# Query algorithm parameters from binary
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
    echo "  Unlike loopback, real network paths are subject to MTU limits."
    echo "  HQC may require IP fragmentation or WireGuard-layer segmentation."
fi
echo ""

# =============================================================================
# Key generation (done on VM1, pushed to VM2 via UAPI)
# =============================================================================
echo "=== Generating keypairs ==="
P1_PRIV="$("$WG_BIN" genkey)"
P2_PRIV="$("$WG_BIN" genkey)"
P1_PUB="$(printf '%s' "$P1_PRIV" | "$WG_BIN" pubkey)"
P2_PUB="$(printf '%s' "$P2_PRIV" | "$WG_BIN" pubkey)"
log "Done."
echo ""

# =============================================================================
# Start wireguard-go on VM1 (local)
# =============================================================================
echo "=== Starting wireguard-go on VM1 (local) ==="

sudo env WIREGUARD_KEM="$KEM_MODE" "$WG_GO_BIN" --foreground "$IF" \
    >"/tmp/vm1_${IF}.log" 2>&1 &
VM1_PID=$!

wait_for_socket_local "$IF"

# Configure VM1 interface
sudo ip address add "${PEER1_IP}/32" dev "$IF"
sudo ip link set "$IF" up
sudo ip route add "${PEER2_IP}/32" dev "$IF"
log "VM1 interface up: $IF ($PEER1_IP)"
echo ""

# =============================================================================
# Start wireguard-go on VM2 (remote via SSH)
# =============================================================================
echo "=== Starting wireguard-go on VM2 (remote) ==="

$VM2 "sudo WIREGUARD_KEM='$KEM_MODE' $REPO_ROOT/wireguard-go --foreground $IF \
    >/tmp/vm2_${IF}.log 2>&1 &"

wait_for_socket_remote "$IF"

# Configure VM2 interface
$VM2 "sudo ip address add ${PEER2_IP}/32 dev $IF && \
      sudo ip link set $IF up && \
      sudo ip route add ${PEER1_IP}/32 dev $IF"
log "VM2 interface up: $IF ($PEER2_IP)"
echo ""

# =============================================================================
# Fetch KEM public keys
# =============================================================================
get_kem_pubkey_local() {
    local sock="/var/run/wireguard/${IF}.sock"
    printf 'get=1\n\n' | sudo socat - "UNIX-CONNECT:$sock" 2>&1 \
        | sed -n '/^kem_public_key=/p' | sed 's/^kem_public_key=//' | tr -d '\r\n '
}

get_kem_pubkey_remote() {
    local sock="/var/run/wireguard/${IF}.sock"
    $VM2 "printf 'get=1\n\n' | sudo socat - UNIX-CONNECT:$sock" 2>&1 \
        | sed -n '/^kem_public_key=/p' | sed 's/^kem_public_key=//' | tr -d '\r\n '
}

P1_KEM_PUB=$(get_kem_pubkey_local)
P2_KEM_PUB=$(get_kem_pubkey_remote)

# =============================================================================
# Configure peers
# =============================================================================
echo "=== Configuring peers ==="

P1_PRIV_HEX=$(printf '%s' "$P1_PRIV" | base64 -d | xxd -p | tr -d '\n')
P2_PRIV_HEX=$(printf '%s' "$P2_PRIV" | base64 -d | xxd -p | tr -d '\n')
P1_PUB_HEX=$(printf '%s' "$P1_PUB" | base64 -d | xxd -p | tr -d '\n')
P2_PUB_HEX=$(printf '%s' "$P2_PUB" | base64 -d | xxd -p | tr -d '\n')

SOCK_LOCAL="/var/run/wireguard/${IF}.sock"
SOCK_REMOTE="/var/run/wireguard/${IF}.sock"

if [[ "$KEM_MODE" == "classic" ]]; then
    # VM1 peer config
    {
        printf 'set=1\n'
        printf 'private_key=%s\n' "$P1_PRIV_HEX"
        printf 'listen_port=%s\n' "$PORT1"
        printf 'public_key=%s\n'  "$P2_PUB_HEX"
        printf 'allowed_ip=%s/32\n' "$PEER2_IP"
        printf 'endpoint=%s:%s\n' "$VM2_HOST" "$PORT2"
        printf 'persistent_keepalive_interval=25\n'
        printf '\n'
    } | sudo socat - "UNIX-CONNECT:$SOCK_LOCAL" > /dev/null

    # VM2 peer config (over SSH)
    $VM2 "{ \
        printf 'set=1\n'; \
        printf 'private_key=%s\n' '${P2_PRIV_HEX}'; \
        printf 'listen_port=%s\n' '${PORT2}'; \
        printf 'public_key=%s\n'  '${P1_PUB_HEX}'; \
        printf 'allowed_ip=%s/32\n' '${PEER1_IP}'; \
        printf 'endpoint=%s:%s\n' '${VM1_HOST_IP}' '${PORT1}'; \
        printf 'persistent_keepalive_interval=25\n'; \
        printf '\n'; \
    } | sudo socat - UNIX-CONNECT:$SOCK_REMOTE" > /dev/null

else
    [[ -z "$P1_KEM_PUB" || -z "$P2_KEM_PUB" ]] && \
        fail "Failed to retrieve KEM public keys. Is WIREGUARD_KEM set correctly?"

    # VM1 peer config (with KEM key)
    {
        printf 'set=1\n'
        printf 'private_key=%s\n' "$P1_PRIV_HEX"
        printf 'listen_port=%s\n' "$PORT1"
        printf 'public_key=%s\n'  "$P2_PUB_HEX"
        printf 'kem_public_key=%s\n' "$P2_KEM_PUB"
        printf 'allowed_ip=%s/32\n' "$PEER2_IP"
        printf 'endpoint=%s:%s\n' "$VM2_HOST" "$PORT2"
        printf 'persistent_keepalive_interval=25\n'
        printf '\n'
    } | sudo socat - "UNIX-CONNECT:$SOCK_LOCAL" > /dev/null

    # VM2 peer config with KEM key (over SSH)
    $VM2 "{ \
        printf 'set=1\n'; \
        printf 'private_key=%s\n' '${P2_PRIV_HEX}'; \
        printf 'listen_port=%s\n' '${PORT2}'; \
        printf 'public_key=%s\n'  '${P1_PUB_HEX}'; \
        printf 'kem_public_key=%s\n' '${P1_KEM_PUB}'; \
        printf 'allowed_ip=%s/32\n' '${PEER1_IP}'; \
        printf 'endpoint=%s:%s\n' '${VM1_HOST_IP}' '${PORT1}'; \
        printf 'persistent_keepalive_interval=25\n'; \
        printf '\n'; \
    } | sudo socat - UNIX-CONNECT:$SOCK_REMOTE" > /dev/null
fi

log "Peers configured."
echo ""

# =============================================================================
# Algorithm metadata
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
    echo "vm1=$VM1_HOST_IP"
    echo "vm2=$VM2_HOST"
} | tee "$RESULTS_DIR/sizes.txt"
echo ""

# =============================================================================
# Baseline tunnel RTT (established session, no handshake)
# =============================================================================
echo "=== Baseline tunnel RTT (established session, no handshake) ==="

reset_peers "$P1_PUB" "$P2_PUB" "$P1_KEM_PUB" "$P2_KEM_PUB"

log "Waiting for tunnel to pass traffic..."
for _ in $(seq 1 30); do
    if ping -c 1 -W 1 "$PEER2_IP" >/dev/null 2>&1; then
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
    ping -c 1 -W 1 "$PEER2_IP" >/dev/null 2>&1
    T1=$(ns_now)
    if [[ "$i" -gt "$RTT_DISCARD" ]]; then
        RTT_SAMPLES+=("$(python3 -c "print(f'{($T1-$T0)/1e6:.3f}')")")
    fi
done

BASELINE_RTT=$(printf '%s\n' "${RTT_SAMPLES[@]}" | awk '
    BEGIN { sum=0; n=0 }
    { sum += $1; n++ }
    END { printf "%.3f", sum/n }')

echo "  Baseline tunnel RTT : ${BASELINE_RTT}ms (avg of $RTT_COUNT pings, no handshake)"
echo "  True handshake crypto cost ≈ measured latency − ${BASELINE_RTT}ms"
echo ""
echo "baseline_tunnel_rtt_ms=$BASELINE_RTT" >> "$RESULTS_DIR/sizes.txt"

# =============================================================================
# Handshake latency trials
# =============================================================================
echo "=== [2/2] Handshake latency ($HANDSHAKE_TRIALS trials) ==="

WARMUP_COUNT=25
echo "  Warming up ($WARMUP_COUNT unrecorded handshakes)..."
for _ in $(seq 1 "$WARMUP_COUNT"); do
    reset_peers "$P1_PUB" "$P2_PUB" "$P1_KEM_PUB" "$P2_KEM_PUB"
    ping -c 1 -W 2 "$PEER2_IP" >/dev/null 2>&1 || true
done
log "Warmup complete. Starting recorded trials."
echo ""

LATENCIES=()
FAILED_TRIALS=0

for i in $(seq 1 "$HANDSHAKE_TRIALS"); do
    reset_peers "$P1_PUB" "$P2_PUB" "$P1_KEM_PUB" "$P2_KEM_PUB"

    T_START=$(ns_now)

    if ! ping -c 1 -W 2 "$PEER2_IP" >/dev/null 2>&1; then
        echo "  Trial $i: FAILED — ping did not return."
        FAILED_TRIALS=$((FAILED_TRIALS + 1))
        if [[ "$FAILED_TRIALS" -gt $((HANDSHAKE_TRIALS / 20)) ]]; then
            echo ""
            echo "ERROR: >5% of trials failed. Aborting."
            echo "VM1 log tail:"
            tail -n 15 "/tmp/vm1_${IF}.log" || true
            exit 3
        fi
        continue
    fi

    T_END=$(ns_now)
    LATENCY_MS=$(python3 -c "print(f'{($T_END - $T_START) / 1e6:.3f}')")
    LATENCIES+=("$LATENCY_MS")

    if [[ "$i" -le 10 ]] || [[ $(( i % 100 )) -eq 0 ]]; then
        echo "  Trial $i/$HANDSHAKE_TRIALS: ${LATENCY_MS} ms"
    fi
done

SUCCESSFUL_TRIALS=${#LATENCIES[@]}
echo ""
log "Trials complete: $SUCCESSFUL_TRIALS successful, $FAILED_TRIALS failed."
echo ""

printf '%s\n' "${LATENCIES[@]}" > "$RESULTS_DIR/latency_raw.csv"

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

# =============================================================================
# Summary
# =============================================================================
echo ""
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