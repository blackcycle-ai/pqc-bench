// SPDX-License-Identifier: Apache-2.0 or CC0-1.0
// HMAC-SHA-256 (RFC 2104) over a GOOSE-sized message, at CLOCK_FAST (deployment
// clock, same basis as speedfast.c) — the per-frame MAC cost of the symmetric
// authentication path, measured on the same silicon as the signatures.
// Built via the crypto_sign test wildcard; the carrier scheme is linked but unused.
#include "api.h"
#include "hal.h"
#include "sendfn.h"
#include "randombytes.h"
#include "sha2.h"

#include <stdint.h>
#include <string.h>

#define MLEN 130      /* GOOSE hdr + APDU + 62351-6 session wrapper, per the paper */
#define KLEN 32
#define BLK 64

#define printcycles(S, U) send_unsignedll((S), (U))

static void hmac_sha256(uint8_t tag[32], const uint8_t *key, const uint8_t *msg, size_t mlen)
{
  uint8_t ibuf[BLK + MLEN];
  uint8_t obuf[BLK + 32];
  size_t i;

  for (i = 0; i < KLEN; i++) {
    ibuf[i] = key[i] ^ 0x36;
    obuf[i] = key[i] ^ 0x5c;
  }
  for (; i < BLK; i++) {
    ibuf[i] = 0x36;
    obuf[i] = 0x5c;
  }
  memcpy(ibuf + BLK, msg, mlen);
  sha256(obuf + BLK, ibuf, BLK + mlen);
  sha256(tag, obuf, BLK + 32);
}

int main(void)
{
  uint8_t key[KLEN], msg[MLEN], tag[32];
  unsigned long long t0, t1;
  int i;

  hal_setup(CLOCK_FAST);
  hal_send_str("==========================");

  randombytes(key, KLEN);
  for (i = 0; i < MUPQ_ITERATIONS; i++) {
    randombytes(msg, MLEN);
    t0 = hal_get_time();
    hmac_sha256(tag, key, msg, MLEN);
    t1 = hal_get_time();
    printcycles("hmac cycles:", t1 - t0);
    hal_send_str("+");
  }
  hal_send_str("#");
  return 0;
}
