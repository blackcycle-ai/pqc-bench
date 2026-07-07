// SPDX-License-Identifier: Apache-2.0 or CC0-1.0
// dudect-style constant-time harness for signing: interleaved fixed-vs-random
// input timing, Welch t-test off-device. Two modes:
//   default (message mode): class 0 signs a FIXED message, class 1 a RANDOM message,
//     under one fixed key. Tests timing dependence on the (public) message input.
//   -DDUDECT_KEY (key mode): class 0 signs with a FIXED secret key, class 1 with a
//     SECOND fixed key (a stand-in for "random key" without per-sample keygen), both
//     over random messages. Tests timing dependence on the SECRET key — the property
//     NIST IR 8413 flags for Falcon's FP Gaussian sampler.
// Emits "dudect-class:<c>"+"dudect-cycles:<n>" per iteration. N via -DMUPQ_DUDECT_ITERS.
#include "api.h"
#include "hal.h"
#include "sendfn.h"
#include "randombytes.h"

#include <stdint.h>
#include <string.h>

#define MLEN 59

#define PASTER(x, y) x##y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)

#define MUPQ_CRYPTO_PUBLICKEYBYTES NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_BYTES          NAMESPACE(CRYPTO_BYTES)

#define MUPQ_crypto_sign_keypair NAMESPACE(crypto_sign_keypair)
#define MUPQ_crypto_sign         NAMESPACE(crypto_sign)

#ifndef MUPQ_DUDECT_ITERS
#define MUPQ_DUDECT_ITERS 1000
#endif

int main(void)
{
  unsigned char skA[MUPQ_CRYPTO_SECRETKEYBYTES];
  unsigned char skB[MUPQ_CRYPTO_SECRETKEYBYTES];
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES];
  unsigned char sm[MLEN + MUPQ_CRYPTO_BYTES];
  unsigned char msg[MLEN];
  unsigned char msg_fixed[MLEN];
  size_t smlen;
  unsigned long long t0, t1;
  int i;

  hal_setup(CLOCK_FAST);   /* 168 MHz: realistic deployment clock; flash wait-states are
                              constant so they don't bias the constant-time t-test, and it
                              runs ~7x faster than CLOCK_BENCHMARK. */
  hal_send_str("==========================");

  MUPQ_crypto_sign_keypair(pk, skA);  /* fixed key A */
  MUPQ_crypto_sign_keypair(pk, skB);  /* second fixed key B (key mode) */
  memset(msg_fixed, 0x42, MLEN);      /* the fixed-class message (message mode) */

  for (i = 0; i < MUPQ_DUDECT_ITERS; i++) {
    int cls = i & 1;                  /* interleave classes to cancel drift */
#ifdef DUDECT_KEY
    unsigned char *sk = cls ? skB : skA;   /* fixed-vs-second key; messages random */
    randombytes(msg, MLEN);
#else
    unsigned char *sk = skA;               /* fixed key; fixed-vs-random message */
    if (cls) randombytes(msg, MLEN);
    else     memcpy(msg, msg_fixed, MLEN);
#endif
    memcpy(sm, msg, MLEN);

    t0 = hal_get_time();
    MUPQ_crypto_sign(sm, &smlen, sm, MLEN, sk);
    t1 = hal_get_time();

    send_unsigned("dudect-class:", (unsigned)cls);
    send_unsignedll("dudect-cycles:", t1 - t0);
  }
  hal_send_str("#");
  return 0;
}
