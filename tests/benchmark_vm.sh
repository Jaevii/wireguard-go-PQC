#!/usr/bin/env bash
# =============================================================================
# wireguard-go KEM handshake benchmark (ping-RTT method)
#
# Run this script on VM1 (initiator, 10.27.8.10).
# VM2 (responder, 10.27.8.11) is controlled via passwordless SSH.
#
# Both VMs must have the wireguard-go binary built at:
#   ~/wireguard-go-PQC/wireguard-go
#
# Measurement method:
#   After expire_keys, the first ping MUST complete a full handshake before
#   it gets a response. Its RTT therefore directly captures the full
#   handshake round-trip time. No log files, no cross-VM clock sync needed.
#
#   Baseline RTT is re-sampled every BASELINE_INTERVAL trials and stored
#   alongside each handshake RTT so per-trial net latency is computed against
#   the most recent baseline rather than a single measurement taken at startup.
#
# Usage:
#   KEM_MODE=classic          bash benchmark_vm.sh
#   KEM_MODE=mlkem512         bash benchmark_vm.sh
#   KEM_MODE=mlkem768         bash benchmark_vm.sh
#   KEM_MODE=mlkem1024        bash benchmark_vm.sh
#   KEM_MODE=hqc128           bash benchmark_vm.sh
#   KEM_MODE=hqc192           bash benchmark_vm.sh
#   KEM_MODE=hqc256           bash benchmark_vm.sh
#   KEM_MODE=hybrid-mlkem512  bash benchmark_vm.sh
#   KEM_MODE=hybrid-mlkem768  bash benchmark_vm.sh
#   KEM_MODE=hybrid-mlkem1024 bash benchmark_vm.sh
#   KEM_MODE=hybrid-hqc128    bash benchmark_vm.sh
#   KEM_MODE=hybrid-hqc192    bash benchmark_vm.sh
#   KEM_MODE=hybrid-hqc256    bash benchmark_vm.sh
#
# Environment overrides:
#   WG_GO_BIN          path to wireguard-go binary  (default: ~/wireguard-go-PQC/wireguard-go)
#   WG_BIN             path to wg tool              (default: wg)
#   VM2_HOST           VM2 SSH host                 (default: 10.27.8.11)
#   VM2_USER           VM2 SSH user                 (default: jaevii)
#   KEM_MODE           algorithm                    (default: classic)
#   HANDSHAKE_TRIALS   number of handshake trials   (default: 3000)
#   BASELINE_INTERVAL  re-sample baseline every N trials (default: 100)
# =============================================================================
set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================
REPO_ROOT="$HOME/wireguard-go-PQC"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WG_GO_BIN="${WG_GO_BIN:-$REPO_ROOT/wireguard-go}"
WG_BIN="${WG_BIN:-wg}"

VM1_HOST_IP="10.27.8.10"
VM2_HOST="${VM2_HOST:-10.27.8.11}"
VM2_USER="${VM2_USER:-jaevii}"

PEER1_IP="10.199.0.1"
PEER2_IP="10.199.0.2"

IF="wg0"
PORT1="51820"
PORT2="51820"

KEM_MODE="${KEM_MODE:-classic}"
HANDSHAKE_TRIALS="${HANDSHAKE_TRIALS:-5000}"
WARMUP_TRIALS=100
TRIAL_TIMEOUT=15        # seconds to wait for a single ping/handshake
BASELINE_INTERVAL=100   # re-sample baseline every N recorded trials
BASELINE_PINGS=5        # pings per baseline sample (mean is taken)

RESULTS_DIR="$SCRIPT_DIR/results/$(date +%Y%m%d_%H%M%S)_${KEM_MODE}"
TMP_DIR="$(mktemp -d)"

MTU_LIMIT=1472

# =============================================================================
# SSH ControlMaster — one TCP connection for the entire run
# =============================================================================
SSH_CTL="$TMP_DIR/ssh_ctl"
SSH_OPTS="-o StrictHostKeyChecking=no \
          -o BatchMode=yes \
          -o ControlMaster=auto \
          -o ControlPath=$SSH_CTL \
          -o ControlPersist=300 \
          -o ServerAliveInterval=30"
VM2="ssh $SSH_OPTS ${VM2_USER}@${VM2_HOST}"

# =============================================================================
# Cleanup
# =============================================================================
cleanup() {
    set +e
    echo ""
    echo "--- Cleaning up ---"

    sudo ip link delete "$IF" 2>/dev/null || true
    sudo pkill -f "wireguard-go.*$IF" 2>/dev/null || true

    $VM2 "sudo ip link delete $IF 2>/dev/null; \
          sudo pkill -f 'wireguard-go.*$IF' 2>/dev/null; \
          true" 2>/dev/null || true

    ssh -o ControlPath="$SSH_CTL" -O exit "${VM2_USER}@${VM2_HOST}" 2>/dev/null || true

    rm -rf "$TMP_DIR"
    echo "--- Done ---"
}
trap cleanup EXIT INT TERM

# =============================================================================
# Helpers
# =============================================================================
log()  { echo "[$(date +%H:%M:%S)] $*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

uapi_set() {
    local sock="$1"
    local payload="$2"
    local response
    response=$(printf '%s\n\n' "$payload" | sudo socat - "UNIX-CONNECT:$sock" 2>&1)
    local errno
    errno=$(printf '%s' "$response" | grep '^errno=' | cut -d= -f2 | tr -d '[:space:]')
    if [[ -z "$errno" || "$errno" != "0" ]]; then
        fail "UAPI set failed (errno=${errno:-missing}) on $sock. Response: $response"
    fi
}

wait_for_socket_local() {
    local sock="/var/run/wireguard/${1}.sock"
    for _ in $(seq 1 40); do
        [[ -S "$sock" ]] && { log "Local socket ready."; return 0; }
        sleep 0.25
    done
    fail "Local socket $sock did not appear within 10s."
}

wait_for_socket_remote() {
    local sock="/var/run/wireguard/${1}.sock"
    for _ in $(seq 1 40); do
        $VM2 "[[ -S '$sock' ]]" 2>/dev/null && { log "Remote socket ready."; return 0; }
        sleep 0.25
    done
    fail "Remote socket $sock did not appear within 10s."
}

# Expire keys via local UAPI only — no SSH in the hot path
expire_keys() {
    uapi_set "$SOCK_LOCAL" \
        "$(printf 'set=1\npublic_key=%s\nexpire_keys=true' "$P2_PUB_HEX")"
}

# Sample baseline RTT over the established (non-handshake) session.
# Does NOT call expire_keys — the session stays live so we measure pure ICMP.
# Prints the mean RTT in ms, or empty string on failure.
sample_baseline() {
    local total=0
    local count=0
    local rtt
    for _ in $(seq 1 "$BASELINE_PINGS"); do
        rtt=$(ping -c 1 -W 2 "$PEER2_IP" 2>/dev/null \
            | grep -oP 'time=\K[\d.]+' || echo "")
        if [[ -n "$rtt" ]]; then
            total=$(awk "BEGIN{printf \"%.3f\", $total + $rtt}")
            count=$(( count + 1 ))
        fi
    done
    if [[ $count -gt 0 ]]; then
        awk "BEGIN{printf \"%.3f\", $total / $count}"
    fi
}

# =============================================================================
# Preflight checks
# =============================================================================
echo "============================================"
echo " wireguard-go KEM handshake benchmark"
echo " Mode     : $KEM_MODE"
echo " Trials   : $HANDSHAKE_TRIALS (+ $WARMUP_TRIALS warmup)"
echo " Baseline : re-sampled every $BASELINE_INTERVAL trials ($BASELINE_PINGS pings each)"
echo " VM1      : $VM1_HOST_IP (initiator, local)"
echo " VM2      : $VM2_HOST (responder, SSH)"
echo " Method   : ping RTT after expire_keys"
echo "============================================"
echo ""
echo "=== Preflight checks ==="

case "$KEM_MODE" in
    classic|mlkem512|mlkem768|mlkem1024|hqc128|hqc192|hqc256|\
    hybrid-mlkem512|hybrid-mlkem768|hybrid-mlkem1024|\
    hybrid-hqc128|hybrid-hqc192|hybrid-hqc256) ;;
    *) fail "Unknown KEM_MODE '$KEM_MODE'." ;;
esac

command -v "$WG_BIN" >/dev/null 2>&1 || fail "'$WG_BIN' not found."
command -v python3   >/dev/null 2>&1 || fail "'python3' not found."
command -v socat     >/dev/null 2>&1 || fail "'socat' not found — sudo apt install socat"
[[ -x "$WG_GO_BIN" ]]               || fail "wireguard-go binary not found: $WG_GO_BIN"

log "Opening SSH ControlMaster to VM2..."
ssh $SSH_OPTS -fN "${VM2_USER}@${VM2_HOST}" \
    || fail "Cannot open SSH ControlMaster to ${VM2_USER}@${VM2_HOST}."
log "SSH ControlMaster established."

$VM2 "echo 'VM2 reachable'" \
    || fail "SSH to ${VM2_USER}@${VM2_HOST} not working."
$VM2 "[[ -x '$REPO_ROOT/wireguard-go' ]]" \
    || fail "wireguard-go not found on VM2 at $REPO_ROOT/wireguard-go."
$VM2 "command -v socat" >/dev/null 2>&1 \
    || fail "'socat' not found on VM2 — sudo apt install socat"

mkdir -p "$RESULTS_DIR"
echo "Binary  : $WG_GO_BIN"
echo "Results : $RESULTS_DIR"
echo ""

sudo -v
$VM2 "sudo -n true" 2>/dev/null \
    || fail "VM2 user '$VM2_USER' cannot sudo without password."

# =============================================================================
# Query algorithm parameters
# =============================================================================
echo "=== Querying algorithm parameters ==="
KEM_INFO="$(WIREGUARD_KEM="$KEM_MODE" "$WG_GO_BIN" --kem-info 2>&1)" \
    || fail "--kem-info not supported. Add it to main.go."

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
    echo "  WARNING: $KEM_MODE messages exceed MTU ($MTU_LIMIT bytes) — IP fragmentation likely."
    echo "  Initiation: ${MSG_INIT_BYTES}b  Response: ${MSG_RESP_BYTES}b"
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

P1_PRIV_HEX=$(printf '%s' "$P1_PRIV" | base64 -d | xxd -p | tr -d '\n')
P2_PRIV_HEX=$(printf '%s' "$P2_PRIV" | base64 -d | xxd -p | tr -d '\n')
P1_PUB_HEX=$(printf '%s'  "$P1_PUB"  | base64 -d | xxd -p | tr -d '\n')
P2_PUB_HEX=$(printf '%s'  "$P2_PUB"  | base64 -d | xxd -p | tr -d '\n')
log "Done."
echo ""

# =============================================================================
# Start wireguard-go on VM1 (local)
# =============================================================================
echo "=== Starting wireguard-go on VM1 ==="
sudo env WIREGUARD_KEM="$KEM_MODE" \
         "$WG_GO_BIN" --foreground "$IF" \
    >"/tmp/vm1_${IF}.log" 2>&1 &
VM1_PID=$!

wait_for_socket_local "$IF"
SOCK_LOCAL="/var/run/wireguard/${IF}.sock"

sudo ip address add "${PEER1_IP}/32" dev "$IF"
sudo ip link set "$IF" up
sudo ip route add "${PEER2_IP}/32" dev "$IF"
log "VM1 interface up ($PEER1_IP)."
echo ""

# =============================================================================
# Start wireguard-go on VM2 (remote)
# =============================================================================
echo "=== Starting wireguard-go on VM2 ==="
$VM2 "sudo WIREGUARD_KEM='$KEM_MODE' \
           $REPO_ROOT/wireguard-go --foreground $IF \
    >/tmp/vm2_${IF}.log 2>&1 &"

wait_for_socket_remote "$IF"
SOCK_REMOTE="/var/run/wireguard/${IF}.sock"

$VM2 "sudo ip address add ${PEER2_IP}/32 dev $IF && \
      sudo ip link set $IF up && \
      sudo ip route add ${PEER1_IP}/32 dev $IF"
log "VM2 interface up ($PEER2_IP)."
echo ""

# =============================================================================
# Fetch KEM public keys
# =============================================================================
get_kem_pubkey_local() {
    printf 'get=1\n\n' | sudo socat - "UNIX-CONNECT:$SOCK_LOCAL" 2>/dev/null \
        | grep '^kem_public_key=' | sed 's/^kem_public_key=//' | tr -d '\r\n '
}

get_kem_pubkey_remote() {
    $VM2 "printf 'get=1\n\n' | sudo socat - UNIX-CONNECT:$SOCK_REMOTE" 2>/dev/null \
        | grep '^kem_public_key=' | sed 's/^kem_public_key=//' | tr -d '\r\n '
}

P1_KEM_PUB=""
P2_KEM_PUB=""
if [[ "$KEM_MODE" != "classic" ]]; then
    P1_KEM_PUB=$(get_kem_pubkey_local)
    P2_KEM_PUB=$(get_kem_pubkey_remote)
    [[ -z "$P1_KEM_PUB" || -z "$P2_KEM_PUB" ]] && \
        fail "Failed to retrieve KEM public keys. Is WIREGUARD_KEM set correctly?"
fi

# =============================================================================
# Configure peers
# =============================================================================
echo "=== Configuring peers ==="

if [[ "$KEM_MODE" == "classic" ]]; then
    uapi_set "$SOCK_LOCAL" "$(printf \
        'set=1\nprivate_key=%s\nlisten_port=%s\npublic_key=%s\nallowed_ip=%s/32\nendpoint=%s:%s\npersistent_keepalive_interval=25' \
        "$P1_PRIV_HEX" "$PORT1" "$P2_PUB_HEX" "$PEER2_IP" "$VM2_HOST" "$PORT2")"

    $VM2 "{ printf 'set=1\nprivate_key=${P2_PRIV_HEX}\nlisten_port=${PORT2}\npublic_key=${P1_PUB_HEX}\nallowed_ip=${PEER1_IP}/32\nendpoint=${VM1_HOST_IP}:${PORT1}\npersistent_keepalive_interval=25\n\n'; } \
        | sudo socat - UNIX-CONNECT:$SOCK_REMOTE"
else
    uapi_set "$SOCK_LOCAL" "$(printf \
        'set=1\nprivate_key=%s\nlisten_port=%s\npublic_key=%s\nkem_public_key=%s\nallowed_ip=%s/32\nendpoint=%s:%s\npersistent_keepalive_interval=25' \
        "$P1_PRIV_HEX" "$PORT1" "$P2_PUB_HEX" "$P2_KEM_PUB" "$PEER2_IP" "$VM2_HOST" "$PORT2")"

    $VM2 "{ printf 'set=1\nprivate_key=${P2_PRIV_HEX}\nlisten_port=${PORT2}\npublic_key=${P1_PUB_HEX}\nkem_public_key=${P1_KEM_PUB}\nallowed_ip=${PEER1_IP}/32\nendpoint=${VM1_HOST_IP}:${PORT1}\npersistent_keepalive_interval=25\n\n'; } \
        | sudo socat - UNIX-CONNECT:$SOCK_REMOTE"
fi

log "Peers configured."
echo ""

# =============================================================================
# Wait for initial handshake then take first baseline sample
# =============================================================================
echo "=== Initial baseline RTT ==="
log "Waiting for initial handshake..."
ping -c 1 -W 10 "$PEER2_IP" >/dev/null 2>&1 \
    || fail "Initial ping failed — check connectivity."
sleep 1

CURRENT_BASELINE=$(sample_baseline)
[[ -z "$CURRENT_BASELINE" ]] && fail "Could not measure initial baseline RTT."
log "Initial baseline RTT: ${CURRENT_BASELINE}ms"
echo ""

# =============================================================================
# Save algorithm metadata
# =============================================================================
{
    echo "algorithm=$KEM_MODE"
    echo "pubkey_bytes=$PUBKEY_BYTES"
    echo "ciphertext_bytes=$CT_BYTES"
    echo "shared_secret_bytes=$SS_BYTES"
    echo "msg_initiation_bytes=$MSG_INIT_BYTES"
    echo "msg_response_bytes=$MSG_RESP_BYTES"
    echo "exceeds_mtu=$EXCEEDS_MTU"
    echo "mtu_limit=$MTU_LIMIT"
    echo "initial_baseline_rtt_ms=$CURRENT_BASELINE"
    echo "baseline_interval=$BASELINE_INTERVAL"
    echo "baseline_pings=$BASELINE_PINGS"
    echo "vm1=$VM1_HOST_IP"
    echo "vm2=$VM2_HOST"
} | tee "$RESULTS_DIR/sizes.txt"
echo ""

# =============================================================================
# Warmup — unrecorded trials
# =============================================================================
echo "=== Warmup ($WARMUP_TRIALS unrecorded trials) ==="
for _ in $(seq 1 "$WARMUP_TRIALS"); do
    expire_keys
    ping -c 1 -W "$TRIAL_TIMEOUT" "$PEER2_IP" >/dev/null 2>&1 || true
    sleep 0.05
done
log "Warmup complete."

# Refresh baseline after warmup since the system is now at steady state
CURRENT_BASELINE=$(sample_baseline)
[[ -z "$CURRENT_BASELINE" ]] && fail "Could not measure post-warmup baseline RTT."
log "Post-warmup baseline RTT: ${CURRENT_BASELINE}ms"
echo ""

# =============================================================================
# Recorded trials
#
# Each trial:
#   1. Re-sample baseline every BASELINE_INTERVAL trials (session stays live,
#      no expire_keys, so ping measures pure ICMP overhead)
#   2. expire_keys  (local UAPI, no SSH)
#   3. ping -c 1    (must complete handshake first, RTT = handshake + ICMP)
#   4. Write "<handshake_rtt> <baseline_rtt>" to RTT_FILE
# =============================================================================
echo "=== Recorded trials ($HANDSHAKE_TRIALS) ==="

# Two-column file: <handshake_rtt_ms> <baseline_rtt_ms>
RTT_FILE="$RESULTS_DIR/handshake_rtts.txt"
> "$RTT_FILE"

FAILED=0

for i in $(seq 1 "$HANDSHAKE_TRIALS"); do

    # Re-sample baseline periodically — session is still live at this point,
    # so no expire_keys needed and the ping measures pure ICMP overhead.
    if [[ $(( i % BASELINE_INTERVAL )) -eq 1 && $i -gt 1 ]]; then
        b=$(sample_baseline)
        if [[ -n "$b" ]]; then
            CURRENT_BASELINE="$b"
            log "Baseline refresh at trial $i: ${CURRENT_BASELINE}ms"
        else
            log "Baseline refresh at trial $i: failed, keeping ${CURRENT_BASELINE}ms"
        fi
    fi

    expire_keys

    rtt=$(ping -c 1 -W "$TRIAL_TIMEOUT" "$PEER2_IP" 2>/dev/null \
        | grep -oP 'time=\K[\d.]+' || echo "")

    if [[ -z "$rtt" ]]; then
        log "Trial $i: FAILED — ping timed out after ${TRIAL_TIMEOUT}s."
        FAILED=$(( FAILED + 1 ))
        if [[ $FAILED -gt $(( HANDSHAKE_TRIALS / 20 )) ]]; then
            echo "VM1 log tail:"
            tail -n 20 "/tmp/vm1_${IF}.log" || true
            fail "More than 5% of trials failed."
        fi
        continue
    fi

    # Write both values so Python can compute per-trial net latency
    echo "$rtt $CURRENT_BASELINE" >> "$RTT_FILE"

    [[ $(( i % 100 )) -eq 0 ]] && log "Progress: $i / $HANDSHAKE_TRIALS"
done

SUCCESSFUL=$(( HANDSHAKE_TRIALS - FAILED ))
log "Trials complete: $SUCCESSFUL successful, $FAILED failed."
echo ""

# =============================================================================
# Statistics
# =============================================================================
python3 - "$RESULTS_DIR" "$KEM_MODE" \
           "$HANDSHAKE_TRIALS" "$SUCCESSFUL" "$FAILED" \
           "$RESULTS_DIR/latency_summary.txt" << 'PYEOF'
import sys, math, statistics

results_dir, algo, req, succ, failed, out_path = sys.argv[1:]

rtt_file = f"{results_dir}/handshake_rtts.txt"
handshake_rtts = []
baseline_rtts  = []
net_rtts       = []

try:
    with open(rtt_file) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 2:
                h, b = float(parts[0]), float(parts[1])
                handshake_rtts.append(h)
                baseline_rtts.append(b)
                net_rtts.append(h - b)
except FileNotFoundError:
    pass

def stats(label, d):
    if not d:
        return [f"{label}_n=0", f"{label}_note=no_data"]
    d = sorted(d)
    n = len(d)
    def pct(p):
        return d[max(0, min(n - 1, math.ceil(n * p) - 1))]
    return [
        f"{label}_n={n}",
        f"{label}_mean_ms={statistics.mean(d):.3f}",
        f"{label}_stddev_ms={statistics.pstdev(d):.3f}",
        f"{label}_min_ms={d[0]:.3f}",
        f"{label}_p50_ms={pct(0.50):.3f}",
        f"{label}_p95_ms={pct(0.95):.3f}",
        f"{label}_p99_ms={pct(0.99):.3f}",
        f"{label}_max_ms={d[-1]:.3f}",
    ]

# Mean and stddev of all per-trial baselines — useful sanity check for drift
baseline_mean   = f"{statistics.mean(baseline_rtts):.3f}"   if baseline_rtts else "n/a"
baseline_stddev = f"{statistics.pstdev(baseline_rtts):.3f}" if baseline_rtts else "n/a"

lines = (
    [
        f"algorithm={algo}",
        f"trials_requested={req}",
        f"trials_successful={succ}",
        f"trials_failed={failed}",
        f"baseline_mean_ms={baseline_mean}",
        f"baseline_stddev_ms={baseline_stddev}",
        f"note=net_handshake subtracts per-trial rolling baseline from handshake RTT",
    ]
    + stats("handshake_rtt", handshake_rtts)
    + stats("net_handshake", net_rtts)
    + stats("baseline", baseline_rtts)
)

for l in lines:
    print(l)

with open(out_path, "w") as f:
    f.write("\n".join(lines) + "\n")
PYEOF

# =============================================================================
# Summary
# =============================================================================
MEAN_RTT=$(grep  '^handshake_rtt_mean_ms=' "$RESULTS_DIR/latency_summary.txt" \
    | cut -d= -f2 || echo "n/a")
MEAN_NET=$(grep  '^net_handshake_mean_ms=' "$RESULTS_DIR/latency_summary.txt" \
    | cut -d= -f2 || echo "n/a")
MEAN_BASE=$(grep '^baseline_mean_ms='      "$RESULTS_DIR/latency_summary.txt" \
    | cut -d= -f2 || echo "n/a")
STDDEV_BASE=$(grep '^baseline_stddev_ms='  "$RESULTS_DIR/latency_summary.txt" \
    | cut -d= -f2 || echo "n/a")

echo ""
echo "============================================"
echo " Benchmark complete"
echo " Algorithm              : $KEM_MODE"
echo " Trials                 : $SUCCESSFUL / $HANDSHAKE_TRIALS successful"
echo " Handshake RTT mean     : ${MEAN_RTT}ms  (includes ICMP baseline)"
echo " Net handshake mean     : ${MEAN_NET}ms  (per-trial baseline subtracted)"
echo " Baseline mean          : ${MEAN_BASE}ms (stddev: ${STDDEV_BASE}ms)"
echo " Results                : $RESULTS_DIR"
echo "============================================"
echo ""
echo "Files written:"
ls -lh "$RESULTS_DIR"
