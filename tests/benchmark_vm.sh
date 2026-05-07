#!/usr/bin/env bash
# =============================================================================
# wireguard-go KEM handshake benchmark
#
# Run this script on VM1 (initiator, 10.27.8.10).
# VM2 (responder, 10.27.8.11) is controlled via passwordless SSH.
#
# Both VMs must have the wireguard-go binary built at:
#   ~/wireguard-go-PQC/wireguard-go
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

VM1_HOST_IP="10.27.8.10"
VM2_HOST="${VM2_HOST:-10.27.8.11}"
VM2_USER="${VM2_USER:-jaevii}"

PEER1_IP="10.199.0.1"
PEER2_IP="10.199.0.2"

IF="wg0"
PORT1="51820"
PORT2="51820"

KEM_MODE="${KEM_MODE:-classic}"
HANDSHAKE_TRIALS="${HANDSHAKE_TRIALS:-1500}"
WARMUP_TRIALS=50
TRIAL_TIMEOUT=15   # seconds to wait for a single handshake to complete
POLL_INTERVAL=0.02 # seconds between log-line polls inside each trial

RESULTS_DIR="$SCRIPT_DIR/results/$(date +%Y%m%d_%H%M%S)_${KEM_MODE}"
TMP_DIR="$(mktemp -d)"

MTU_LIMIT=1472

# Bench log paths — one per VM, written by the Go process
BENCH_LOG_VM1="/tmp/wg_bench_vm1_${KEM_MODE}_$$.log"
BENCH_LOG_VM2="/tmp/wg_bench_vm2_${KEM_MODE}_$$.log"

# =============================================================================
# SSH with ControlMaster — one TCP connection for the entire benchmark run.
# All SSH calls after the first reuse the same socket, eliminating per-call
# TCP + crypto overhead from the measurement path.
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
# Cleanup — tears down both VMs
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

    # Close the ControlMaster socket
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

# Send a UAPI set command to the local socket and verify errno=0.
# Usage: uapi_set <sock> <newline-separated key=value pairs>
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

# Count lines matching a pattern in a file, returns 0 if file missing
count_lines() {
    grep -c "$1" "$2" 2>/dev/null || echo 0
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

# =============================================================================
# Preflight checks
# =============================================================================
echo "============================================"
echo " wireguard-go KEM handshake benchmark"
echo " Mode    : $KEM_MODE"
echo " Trials  : $HANDSHAKE_TRIALS (+ $WARMUP_TRIALS warmup)"
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

command -v "$WG_BIN" >/dev/null 2>&1 || fail "'$WG_BIN' not found."
command -v python3   >/dev/null 2>&1 || fail "'python3' not found."
command -v socat     >/dev/null 2>&1 || fail "'socat' not found — sudo apt install socat"
[[ -x "$WG_GO_BIN" ]]               || fail "wireguard-go binary not found: $WG_GO_BIN"

log "Opening SSH ControlMaster to VM2..."
# -fN opens the connection in the background without running a command;
# subsequent VM2= calls reuse this socket automatically.
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
    echo "  WARNING: $KEM_MODE messages exceed MTU ($MTU_LIMIT bytes)."
    echo "  Initiation: ${MSG_INIT_BYTES}b  Response: ${MSG_RESP_BYTES}b"
    echo "  HQC may require IP fragmentation."
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

# Truncate bench log before starting so line counts start from zero
> "$BENCH_LOG_VM1"

sudo env WIREGUARD_KEM="$KEM_MODE" \
         WIREGUARD_BENCH_LOG="$BENCH_LOG_VM1" \
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

$VM2 "> '$BENCH_LOG_VM2'"
$VM2 "sudo WIREGUARD_KEM='$KEM_MODE' \
           WIREGUARD_BENCH_LOG='$BENCH_LOG_VM2' \
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
# Measure baseline RTT (pure ICMP, established session, no handshake)
# =============================================================================
echo "=== Measuring baseline RTT ==="

# Wait for the first handshake to complete so baseline is not measuring it
log "Waiting for initial handshake..."
ping -c 1 -W 10 "$PEER2_IP" >/dev/null 2>&1 \
    || fail "Initial ping failed — check connectivity."

# Let the session fully establish, then measure ICMP-only RTT
sleep 1
BASELINE_SAMPLES=()
for _ in $(seq 1 30); do
    rtt=$(ping -c 1 -W 2 "$PEER2_IP" 2>/dev/null \
        | grep -oP 'time=\K[\d.]+' || echo "")
    [[ -n "$rtt" ]] && BASELINE_SAMPLES+=("$rtt")
done

if [[ ${#BASELINE_SAMPLES[@]} -eq 0 ]]; then
    fail "Could not measure baseline RTT — no ping responses."
fi

BASELINE_RTT=$(printf '%s\n' "${BASELINE_SAMPLES[@]}" \
    | awk '{s+=$1; n++} END{printf "%.3f", s/n}')
log "Baseline ICMP RTT (mean of ${#BASELINE_SAMPLES[@]} samples): ${BASELINE_RTT}ms"
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
    echo "baseline_rtt_ms=$BASELINE_RTT"
    echo "vm1=$VM1_HOST_IP"
    echo "vm2=$VM2_HOST"
} | tee "$RESULTS_DIR/sizes.txt"
echo ""

# =============================================================================
# Expire-keys helper — forces a fresh handshake on the next outbound packet.
# This is a local-only UAPI call; no SSH in the hot path.
# =============================================================================
expire_keys() {
    uapi_set "$SOCK_LOCAL" \
        "$(printf 'set=1\npublic_key=%s\nexpire_keys=true' "$P2_PUB_HEX")"
}

# =============================================================================
# Warmup — unrecorded trials to bring CPU caches, AES-NI state, and
# Go runtime allocator to steady state before recording begins.
# =============================================================================
echo "=== Warmup ($WARMUP_TRIALS unrecorded trials) ==="

# Truncate bench logs so warmup lines don't appear in recorded data
> "$BENCH_LOG_VM1"
$VM2 "> '$BENCH_LOG_VM2'"

for w in $(seq 1 "$WARMUP_TRIALS"); do
    expire_keys
    ping -c 1 -W "$TRIAL_TIMEOUT" "$PEER2_IP" >/dev/null 2>&1 || true

    # Wait for completion so we don't overlap into the next warmup trial
    DEADLINE=$(( $(date +%s) + TRIAL_TIMEOUT ))
    while [[ $(count_lines '^BENCH_INIT_END_NS' "$BENCH_LOG_VM1") -lt $w ]]; do
        [[ $(date +%s) -ge $DEADLINE ]] && break
        sleep "$POLL_INTERVAL"
    done
done

log "Warmup complete. Truncating bench logs for recorded run."

# Truncate bench logs again — recorded trials start from line 0
> "$BENCH_LOG_VM1"
$VM2 "> '$BENCH_LOG_VM2'"
echo ""

# =============================================================================
# Recorded trials
# =============================================================================
echo "=== Recorded trials ($HANDSHAKE_TRIALS) ==="

FAILED=0

for i in $(seq 1 "$HANDSHAKE_TRIALS"); do
    # Expire keys via local UAPI only — no SSH in this path
    expire_keys

    # Send a single ping to trigger SendStagedPackets -> SendHandshakeInitiation.
    # This ping is NOT timed; the Go binary records the actual handshake boundaries.
    ping -c 1 -W "$TRIAL_TIMEOUT" "$PEER2_IP" >/dev/null 2>&1 || true

    # Wait until the Go binary has logged BENCH_INIT_END_NS for this trial
    DEADLINE=$(( $(date +%s) + TRIAL_TIMEOUT ))
    while [[ $(count_lines '^BENCH_INIT_END_NS' "$BENCH_LOG_VM1") -lt $i ]]; do
        if [[ $(date +%s) -ge $DEADLINE ]]; then
            log "Trial $i: FAILED — no BENCH_INIT_END_NS within ${TRIAL_TIMEOUT}s."
            FAILED=$(( FAILED + 1 ))
            if [[ $FAILED -gt $(( HANDSHAKE_TRIALS / 20 )) ]]; then
                echo "VM1 log tail:"
                tail -n 20 "/tmp/vm1_${IF}.log" || true
                fail "More than 5% of trials failed."
            fi
            # Truncate logs so line counts stay in sync after a failure
            > "$BENCH_LOG_VM1"
            $VM2 "> '$BENCH_LOG_VM2'"
            i_adj=$(( i - FAILED ))
            break
        fi
        sleep "$POLL_INTERVAL"
    done

    [[ $(( i % 100 )) -eq 0 ]] && log "Progress: $i / $HANDSHAKE_TRIALS"
done

SUCCESSFUL=$(( HANDSHAKE_TRIALS - FAILED ))
log "Trials complete: $SUCCESSFUL successful, $FAILED failed."
echo ""

# =============================================================================
# Collect VM2 bench log
# =============================================================================
log "Collecting VM2 bench log..."
scp $SSH_OPTS "${VM2_USER}@${VM2_HOST}:$BENCH_LOG_VM2" \
    "$RESULTS_DIR/bench_vm2_raw.log"
cp "$BENCH_LOG_VM1" "$RESULTS_DIR/bench_vm1_raw.log"
log "Logs collected."
echo ""

# =============================================================================
# Statistics — single Python invocation over all recorded data
# =============================================================================
python3 - "$RESULTS_DIR" "$KEM_MODE" \
           "$HANDSHAKE_TRIALS" "$SUCCESSFUL" "$FAILED" \
           "$BASELINE_RTT" \
           "$RESULTS_DIR/latency_summary.txt" << 'PYEOF'
import sys, math, statistics, re

results_dir, algo, req, succ, failed, baseline_rtt, out_path = sys.argv[1:]

def parse_ns(path, tag):
    """Return list of integer nanosecond timestamps for the given tag."""
    times = []
    try:
        with open(path) as f:
            for line in f:
                m = re.match(rf'^{tag} (\d+)$', line.strip())
                if m:
                    times.append(int(m.group(1)))
    except FileNotFoundError:
        pass
    return times

def paired_durations_ms(starts, ends):
    """Pair start/end timestamps and return durations in milliseconds."""
    n = min(len(starts), len(ends))
    if n == 0:
        return []
    return [(ends[i] - starts[i]) / 1e6 for i in range(n)]

def stats(label, data_ms):
    """Compute and return summary statistics for a list of millisecond values."""
    if not data_ms:
        return [f"{label}_n=0", f"{label}_note=no_data"]
    d = sorted(data_ms)
    n = len(d)
    def pct(p):
        # Nearest-rank method: ceil(n*p) - 1, clamped to valid indices
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

vm1_log = f"{results_dir}/bench_vm1_raw.log"
vm2_log = f"{results_dir}/bench_vm2_raw.log"

init_starts = parse_ns(vm1_log, "BENCH_INIT_START_NS")
init_ends   = parse_ns(vm1_log, "BENCH_INIT_END_NS")
resp_starts = parse_ns(vm2_log, "BENCH_RESP_START_NS")
resp_ends   = parse_ns(vm2_log, "BENCH_RESP_END_NS")

init_ms = paired_durations_ms(init_starts, init_ends)
resp_ms = paired_durations_ms(resp_starts, resp_ends)

# Sanity check: warn if counts are mismatched
if abs(len(init_starts) - len(init_ends)) > 5:
    print(f"WARNING: init start count ({len(init_starts)}) "
          f"differs from end count ({len(init_ends)}) by more than 5")
if abs(len(resp_starts) - len(resp_ends)) > 5:
    print(f"WARNING: resp start count ({len(resp_starts)}) "
          f"differs from end count ({len(resp_ends)}) by more than 5")

lines = (
    [
        f"algorithm={algo}",
        f"trials_requested={req}",
        f"trials_successful={succ}",
        f"trials_failed={failed}",
        f"baseline_rtt_ms={baseline_rtt}",
    ]
    + stats("initiator", init_ms)
    + stats("responder", resp_ms)
)

for l in lines:
    print(l)

with open(out_path, "w") as f:
    f.write("\n".join(lines) + "\n")
PYEOF

# =============================================================================
# Summary
# =============================================================================
MEAN_INIT=$(grep '^initiator_mean_ms=' "$RESULTS_DIR/latency_summary.txt" \
    | cut -d= -f2 || echo "n/a")
MEAN_RESP=$(grep '^responder_mean_ms=' "$RESULTS_DIR/latency_summary.txt" \
    | cut -d= -f2 || echo "n/a")

echo ""
echo "============================================"
echo " Benchmark complete"
echo " Algorithm          : $KEM_MODE"
echo " Trials             : $SUCCESSFUL / $HANDSHAKE_TRIALS successful"
echo " Initiator mean     : ${MEAN_INIT}ms"
echo " Responder mean     : ${MEAN_RESP}ms"
echo " Baseline ICMP RTT  : ${BASELINE_RTT}ms"
echo " Results            : $RESULTS_DIR"
echo "============================================"
echo ""
echo "Files written:"
ls -lh "$RESULTS_DIR"