# core — dimension-agnostic measurement

Two backends measure the same schemes; domains consume their results through one
versioned JSON schema (`bench.py`).

| Backend | Path | Stack | Use |
|---|---|---|---|
| **Homogeneous (canonical)** | `harness/` | ONE OpenSSL 3.5 `libcrypto` + oqs-provider, via EVP | ECDSA and PQC share one ISA-optimized path. C, `clock_gettime`, raw per-iteration CSV. |
| Portable (fallback) | `algorithms.py`, `bench.py` | `cryptography` (ECDSA) + `pqcrypto` (PQC) | Quick runs where the homogeneous stack is not provisioned. Two libcryptos — NOT for published comparisons. |

`report.py` (JSON/Markdown/CSV) and `cli.py` (`list / run / report / compare`) are
shared. `compare` diffs a `baselines/*.json` against a fresh run with a ±% threshold.

## Open core task

Unify the two backends: make `algorithms.py` drive the `harness/` C binary (so the
CLI's `run` uses the homogeneous path by default and emits the same schema), and have
`harness/run_bench.sh`'s per-iteration CSV flow into `BenchReport`. Until then the C
harness is run directly (see `domains/goose/README.md`) and the portable backend
powers the CLI. Paths in `harness/Makefile` and `run_bench.sh` assume the repo-root
`repo/openssl3-pqc` symlink + `env/activate.sh`.
