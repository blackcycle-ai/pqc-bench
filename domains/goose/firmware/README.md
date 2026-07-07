# Cortex-M PQC benchmark firmware (pqm4 overlay)

Custom harnesses and patches used to measure the NIST PQC signatures on protection-class
Cortex-M silicon (experiment H-GOOSE-CMP-08). They overlay [pqm4](https://github.com/mupq/pqm4);
the collector `../bench_cortexm.py` drives build → flash → semihosting readout → CSV.

## Contents

| File | Role |
|---|---|
| `dudect.c` | Constant-time harness: interleaved fixed-vs-random signing, message mode + `-DDUDECT_KEY` key mode, `DUDECT_N` iterations. Pairs with `../analysis/dudect_ttest.py`. |
| `speedfast.c` | `speed.c` at `CLOCK_FAST` (168 MHz) instead of `CLOCK_BENCHMARK` (24 MHz) — directly-measured deployment wall-clock with flash wait-states. |
| `pqm4-cortexm-bench.patch` | Two pqm4 edits: `common/hal-opencm3.c` (route `hal_send_str` to ARM semihosting `SYS_WRITE0` under `-DSEMIHOSTING`, so output reads over SWD without the unwired ST-Link VCP) and `mk/stm32f4discovery.mk` (`-DSEMIHOSTING` + `DUDECT_N`/`DUDECT_KEY` build knobs). |

## Reproduce (STM32F407 Discovery / Cortex-M4F)

Toolchain: `arm-none-eabi-gcc` 10.3.1, `openocd` 0.11, `stlink-tools`. pqm4 pinned at commit
`cc2c1b9` (see `../data/raw/cortex_m/MANIFEST.json`).

```sh
git clone https://github.com/mupq/pqm4 && cd pqm4 && git checkout cc2c1b9
git submodule update --init --recursive          # libopencm3 + mupq
git apply /path/to/firmware/pqm4-cortexm-bench.patch
cp /path/to/firmware/dudect.c /path/to/firmware/speedfast.c mupq/crypto_sign/
make PLATFORM=stm32f4discovery libopencm3                # one-time
```

Then drive from the collector (handles per-scheme build/flash/parse):

```sh
python3 ../bench_cortexm.py speed     ml-dsa-44 m4f --prefix native  --iters 100
python3 ../bench_cortexm.py speedfast falcon-512 clean --prefix pqclean --iters 30
python3 ../bench_cortexm.py dudect    fndsa_provisional-512 m4f --prefix native --iters 5000 --keymode
```

The `%.c` wildcard rule in `mupq/mk/schemes.mk` builds `dudect`/`speedfast` targets automatically;
no Makefile edit needed beyond the patch.

## Other boards

The semihosting patch is MCU-agnostic and reused as-is. For the M0+/M7 spectrum, a new platform
needs `mk/<platform>.mk` + a `hal-opencm3.c` clock block; for the M7 double-FPU Falcon experiment,
build `falcon-512 clean` with `-mfpu=fpv5-d16 -mfloat-abi=hard`.
