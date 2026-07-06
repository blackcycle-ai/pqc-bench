# pqc-bench

Benchmarks of post-quantum cryptography against protocol timing and size budgets,
measured on one homogeneous crypto stack. A shared measurement core, one domain per protocol.

## Homogeneous stack

Every scheme — the ECDSA baseline and the PQC candidates — is measured through one
OpenSSL 3.5 `libcrypto` via the EVP interface: PQC through oqs-provider over liboqs,
ECDSA through the same stack. Provisioning is in `env/`.

## Layout

```
src/pqc_bench/   measurement core (harness, registry, CLI)
domains/goose/   IEC 61850 GOOSE: 3 ms TT6 + single-frame budgets, frame generator
domains/v2x/     IEEE 1609.2 / TS 103 097 (in progress)
env/             activate.sh + openssl-oqs.cnf
```

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate && pip install -e .
source env/activate.sh
make -C src/pqc_bench/harness
```

Then see `domains/goose/README.md`.

Apache-2.0 · Blackcycle Lab
