#!/usr/bin/env bash
# Activate the homogeneous GOOSE-PQC crypto stack (CLAUDE.md §4).
#   OpenSSL 3.5.6 + liboqs 0.15.0 + oqs-provider 0.11.0, single libcrypto root.
# Usage:  source env/activate.sh
#
# After sourcing:  `openssl` -> the PQC build; ML-DSA/SLH-DSA/ECDSA native, Falcon
# + composites via oqs-provider. liboqs-python picks up liboqs from the same prefix.

_ENV_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PQC_ROOT="$( cd "$_ENV_DIR/.." && pwd )"
PQC_PREFIX="$PQC_ROOT/repo/openssl3-pqc"   # per-host symlink to the OpenSSL 3.5 + oqs-provider prefix

if [ ! -e "$PQC_PREFIX/bin/openssl" ]; then
  echo "ERROR: PQC OpenSSL not found at $PQC_PREFIX" >&2
  return 1 2>/dev/null || exit 1
fi

export PQC_PREFIX
export PATH="$PQC_PREFIX/bin:$PATH"
export LD_LIBRARY_PATH="$PQC_PREFIX/lib:${LD_LIBRARY_PATH:-}"
export OPENSSL_MODULES="$PQC_PREFIX/lib/ossl-modules"
export OPENSSL_CONF="$PQC_ROOT/env/openssl-oqs.cnf"
# liboqs-python: use the liboqs from this prefix, do not auto-download/build.
export OQS_INSTALL_PATH="$PQC_PREFIX"

echo "[pqc-goose] stack active:"
echo "  openssl : $(command -v openssl)  ($(openssl version 2>/dev/null))"
echo "  liboqs  : $(ls "$PQC_PREFIX"/lib/liboqs.so.* 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
echo "  oqsprov : $OPENSSL_MODULES/oqsprovider.so"
