#!/usr/bin/env bash
# Run the full sign/verify latency sweep for the GOOSE-PQC bench.
# Pins a single core (taskset), records raw per-iteration CSV per scheme into
# data/raw/<host>/, and writes a reproducibility manifest.json.
#
# Usage: src/bench/run_bench.sh [host_label] [core]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
# shellcheck disable=SC1091
source env/activate.sh >/dev/null

HOST="${1:-$(uname -m)}"
CORE="${2:-3}"
MSGLEN=107                       # ~ a real GOOSE APDU (goosePdu) length
OUTDIR="data/raw/$HOST"
mkdir -p "$OUTDIR"
BIN="src/bench/bench_sign"
make -C src/bench >/dev/null

# alg : N : warmup   (SLH-DSA gets fewer iters; -128s sign is very slow)
SWEEP=(
  "EC:10000:500"
  "ML-DSA-44:10000:500"
  "ML-DSA-65:10000:500"
  "falcon512:10000:500"
  "p256_mldsa44:10000:500"
  "p256_falcon512:10000:500"
  "SLH-DSA-SHA2-128f:1000:50"
  "SLH-DSA-SHA2-128s:200:20"
)

SUMM="$OUTDIR/summary.jsonl"
: > "$SUMM"
echo "[run_bench] host=$HOST core=$CORE msglen=$MSGLEN -> $OUTDIR"
for entry in "${SWEEP[@]}"; do
  IFS=: read -r ALG N WARM <<< "$entry"
  safe="${ALG//\//_}"
  out="$OUTDIR/${safe}.csv"
  echo "  - $ALG (N=$N warmup=$WARM)"
  line=$(taskset -c "$CORE" "$BIN" "$ALG" "$N" "$WARM" "$MSGLEN" "$out")
  echo "$line" >> "$SUMM"
done

# reproducibility manifest
CPU=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | xargs || \
      (grep -m1 'Model' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | xargs) || echo unknown)
OSSL=$(openssl version 2>/dev/null)
cat > "$OUTDIR/manifest.json" <<EOF
{
  "host_label": "$HOST",
  "arch": "$(uname -m)",
  "kernel": "$(uname -r)",
  "cpu": "$CPU",
  "pinned_core": $CORE,
  "openssl": "$OSSL",
  "liboqs": "$(ls "$PQC_PREFIX"/lib/liboqs.so.* 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)",
  "msg_len_bytes": $MSGLEN,
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "thermal_note": "see thermal log if constrained hardware"
}
EOF
echo "[run_bench] done. summary: $SUMM  manifest: $OUTDIR/manifest.json"
