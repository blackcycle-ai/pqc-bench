#!/usr/bin/env python3
"""
Collect pqm4 benchmark results from an STM32F407 Discovery over ARM semihosting.

The board's ST-Link VCP is not wired to the benchmark USART, so we read output via
semihosting (the HAL was patched: hal_send_str -> SYS_WRITE0, built -DSEMIHOSTING).
Flow per (scheme, test): build with MUPQ_ITERATIONS=N -> st-flash -> openocd
"arm semihosting enable; reset run" (openocd exits on the firmware's SYS_EXIT) ->
parse "<op> cycles:\\n<N>" pairs -> write one CSV row per iteration.

Cycle counts are measured at CLOCK_BENCHMARK (24 MHz) — the pqm4-standard, flash-WS-free,
comparable figure. Convert to wall-clock downstream at the deployment clock.

Usage:
  bench_cortexm.py speed  ml-dsa-44 m4f   --prefix native  --iters 100
  bench_cortexm.py speed  falcon-512 clean --prefix pqclean --iters 20
  bench_cortexm.py stack  ml-dsa-44 m4f   --prefix native  --iters 1
"""
import argparse, os, re, subprocess, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
PQM4 = os.environ.get("PQM4", os.path.join(_HERE, "..", "..", "repo", "pqm4"))
RAW_BASE = os.path.join(_HERE, "data", "raw")
FLASH_ADDR = "0x08000000"
# per pqm4 platform: openocd target config + data-dir alias (core+FPU class)
TARGET_CFG = {"stm32f4discovery": "target/stm32f4x.cfg", "stm32f767zi": "target/stm32f7x.cfg"}
BOARD_DIR  = {"stm32f4discovery": "m4f-sp", "stm32f767zi": "m7-dp"}

# (column name, exact emitted label) pairs per test harness
_CYC = [("keypair", "keypair cycles:"), ("sign", "sign cycles:"), ("verify", "verify cycles:")]
_CYC_KEM = [("keypair", "keypair cycles:"), ("encaps", "encaps cycles:"), ("decaps", "decaps cycles:")]
LABELS = {
    "speed":     _CYC,
    "speedfast": _CYC,   # same output, measured at CLOCK_FAST (168 MHz) — deployment wall-clock
    "stack":     [("keypair", "keypair stack usage:"), ("sign", "sign stack usage:"), ("verify", "verify stack usage:")],
    "hashing":   _CYC,
    "test":      [],
}
LABELS_KEM = {
    "speed":     _CYC_KEM,
    "speedfast": _CYC_KEM,
    "stack":     [("keypair", "keypair stack usage:"), ("encaps", "encaps stack usage:"), ("decaps", "decaps stack usage:")],
    "hashing":   _CYC_KEM,
    "test":      [],
}


def target_name(prefix, scheme, impl, test, family="sign"):
    kind = "crypto_kem" if family == "kem" else "crypto_sign"
    base = kind if prefix == "native" else f"mupq_pqclean_{kind}"
    return f"{base}_{scheme}_{impl}_{test}"


def outdir_for(platform):
    return os.path.join(RAW_BASE, BOARD_DIR[platform])


def build(target, iters, platform, extra_vars=None, force=False):
    bin_ = f"bin/{target}.bin"
    if force:  # CFLAGS changes (DUDECT_N/KEY, DOUBLE_FPU) aren't tracked by make: force a relink
        subprocess.run(["rm", "-f", f"elf/{target}.elf", bin_], cwd=PQM4)
    cmd = ["make", "-j4", f"PLATFORM={platform}", f"MUPQ_ITERATIONS={iters}"] + (extra_vars or []) + [bin_]
    print(f"  build: {' '.join(cmd)}")
    r = subprocess.run(cmd, cwd=PQM4, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-1500:]); print(r.stderr[-1500:])
        sys.exit(f"build failed for {target}")
    return os.path.join(PQM4, bin_)


def flash_and_run(binpath, timeout, platform, serial=None):
    flash = ["st-flash"] + (["--serial", serial] if serial else []) + ["--reset", "write", binpath, FLASH_ADDR]
    subprocess.run(flash, capture_output=True, text=True)
    cmd = ["openocd", "-f", "interface/stlink.cfg", "-f", TARGET_CFG[platform]]
    if serial:
        cmd += ["-c", f"hla_serial {serial}"]
    cmd += ["-c", "init", "-c", "arm semihosting enable", "-c", "reset run"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired as e:
        return (e.stdout or b"").decode(errors="ignore") + (e.stderr or b"").decode(errors="ignore")


def parse_labeled(output, pairs):
    """Return {col: [val,...]} pairing each exact label line with the next numeric line."""
    lines = [l.strip() for l in output.replace("\r", "").splitlines()]
    res = {col: [] for col, _ in pairs}
    for i, l in enumerate(lines):
        for col, label in pairs:
            if l == label:
                for j in range(i + 1, min(i + 3, len(lines))):
                    if re.fullmatch(r"\d+", lines[j]):
                        res[col].append(int(lines[j])); break
    return res


def parse_dudect(output):
    """Pair 'dudect-class:'/'dudect-cycles:' labels with their following numeric lines."""
    lines = [l.strip() for l in output.replace("\r", "").splitlines()]
    cls, cyc = [], []
    for i, l in enumerate(lines):
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if l == "dudect-class:" and nxt.isdigit():
            cls.append(int(nxt))
        elif l == "dudect-cycles:" and nxt.isdigit():
            cyc.append(int(nxt))
    n = min(len(cls), len(cyc))
    return cls[:n], cyc[:n]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("test", choices=["speed", "speedfast", "stack", "hashing", "test", "dudect"])
    ap.add_argument("scheme"); ap.add_argument("impl")
    ap.add_argument("--prefix", choices=["native", "pqclean"], required=True)
    ap.add_argument("--iters", type=int, default=100)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--keymode", action="store_true", help="dudect: fix-vs-second KEY instead of message")
    ap.add_argument("--platform", default="stm32f4discovery", choices=list(TARGET_CFG))
    ap.add_argument("--serial", default=None, help="ST-Link serial (multi-board safety)")
    ap.add_argument("--double-fpu", dest="double_fpu", action="store_true",
                    help="F767: hardware double-precision FPU (-mfpu=fpv5-d16) for the Falcon clean sampler")
    ap.add_argument("--family", choices=["sign", "kem"], default="sign",
                    help="crypto_sign (default) or crypto_kem (ML-KEM: keypair/encaps/decaps)")
    args = ap.parse_args()

    outdir = outdir_for(args.platform)
    os.makedirs(outdir, exist_ok=True)
    target = target_name(args.prefix, args.scheme, args.impl, args.test, args.family)
    common = ["DOUBLE_FPU=1"] if args.double_fpu else []
    if args.test == "dudect":
        extra = [f"DUDECT_N={args.iters}"] + (["DUDECT_KEY=1"] if args.keymode else []) + common
        binpath = build(target, args.iters, args.platform, extra_vars=extra, force=True)
    else:
        binpath = build(target, args.iters, args.platform, extra_vars=common, force=bool(common))
    print(f"  run (timeout {args.timeout}s)...")
    out = flash_and_run(binpath, args.timeout, args.platform, args.serial)

    if args.test == "test":
        ok = "error" not in out.lower() and ("OK" in out or "passed" in out.lower() or out.count("+") > 0)
        print(f"  correctness raw tail: {out.strip().splitlines()[-5:]}")
        return

    if args.test == "dudect":
        cls, cyc = parse_dudect(out)
        mode = "key" if args.keymode else "msg"
        safe = f"{args.scheme}_{args.impl}_dudect_{mode}".replace("/", "_")
        csv = os.path.join(outdir, f"{safe}.csv")
        with open(csv, "w") as f:
            f.write("class,cycles\n")
            for c, v in zip(cls, cyc):
                f.write(f"{c},{v}\n")
        print(f"  -> {csv}  ({len(cyc)} samples, classes={set(cls)})")
        return

    pairs = (LABELS_KEM if args.family == "kem" else LABELS)[args.test]
    data = parse_labeled(out, pairs)
    safe = f"{args.scheme}_{args.impl}_{args.test}".replace("/", "_")
    csv = os.path.join(outdir, f"{safe}.csv")
    n = max((len(v) for v in data.values()), default=0)
    cols = [col for col, _ in pairs if data[col]]
    with open(csv, "w") as f:
        f.write("iter," + ",".join(c.replace(" ", "_") for c in cols) + "\n")
        for i in range(n):
            row = [str(i)] + [str(data[c][i]) if i < len(data[c]) else "" for c in cols]
            f.write(",".join(row) + "\n")
    summary = {c: (data[c][len(data[c])//2] if data[c] else None) for c in cols}
    print(f"  -> {csv}  ({n} iters)  median cycles: {summary}")


if __name__ == "__main__":
    main()
