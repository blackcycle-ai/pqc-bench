# domain: goose — IEC 61850-8-1 GOOSE

PQC signature feasibility for GOOSE against two budgets: **3 ms** transfer time
(Type 1A trip, IEC 61850-5 TT6) and a **single non-fragmented Ethernet frame** (~1500 B).

## Layout

```
goose/make_goose_frame.py   GOOSE + IEC 62351-6 frame generator (real signatures)
budgets.py                  3 ms TT6 + single-frame verdicts
bench_cortexm.py            STM32 / RP2040 harness (Cortex-M spectrum)
data/raw/                   per-iteration CSV samples (every number)
data/pcap/                  sample GOOSE / 62351-6 frames
firmware/                   pqm4 (STM32) + pico-sdk (RP2040) benchmark firmware
```

## Reproduce

```bash
git clone https://github.com/blackcycle-ai/pqc-bench && cd pqc-bench
python -m venv .venv && source .venv/bin/activate && pip install -e .
source env/activate.sh
make -C src/pqc_bench/harness
bash src/pqc_bench/harness/run_bench.sh x86_64 3    # -> data/raw/x86_64/
```
