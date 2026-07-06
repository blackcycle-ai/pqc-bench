# domain: v2x — IEEE 1609.2 / ETSI TS 103 097

PQC signature feasibility for V2X PKI (SCMS / CCMS): authenticating CAM/DENM safety
messages and the certificate chain, with the HNDL / Mosca framing for long-lived
trust anchors.

## Status: migrated from `pqc-v2x-bench`

The standalone repo `github.com/blackcycle-ai/pqc-v2x-bench` is the origin of this
domain and of the shared core (CLI, schema, baselines). Two migration tasks remain:

1. **Move the V2X budget/wire layer here** (CAM/DENM size budgets, TS 103 097 framing)
   as `budgets.py`, mirroring `domains/goose/budgets.py`.
2. **Re-base its measurements on the homogeneous core.** The original repo measures
   ECDSA via `cryptography` and PQC via `pqcrypto` — two `libcrypto`s, an asymmetric
   stack. Re-running through `src/pqc_bench/harness` (one OpenSSL 3.5
   libcrypto + oqs-provider) removes that confound and makes the V2X and GOOSE numbers
   directly comparable. This is the "homogeneous-libcrypto" measurement the V2X paper
   anticipates.

Until then, the original V2X figures stand on their own stack; see the upstream repo.

## Reproduce

Once re-based, identical to the GOOSE recipe with `domains/v2x` and the V2X budgets.
