// SPDX-License-Identifier: Apache-2.0 or CC0-1.0
// Same as speed.c but runs at CLOCK_FAST (168 MHz on the F407) instead of
// CLOCK_BENCHMARK (24 MHz). This reports the real deployment wall-clock cycle
// count WITH flash wait-states, so cycles/168MHz is the directly-measured time
// against the 3 ms GOOSE budget (vs the 24 MHz benchmark figure + conversion).
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

#define MUPQ_CRYPTO_SECRETKEYBYTES NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_PUBLICKEYBYTES NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_BYTES          NAMESPACE(CRYPTO_BYTES)

#define MUPQ_crypto_sign_keypair NAMESPACE(crypto_sign_keypair)
#define MUPQ_crypto_sign         NAMESPACE(crypto_sign)
#define MUPQ_crypto_sign_open    NAMESPACE(crypto_sign_open)

#define printcycles(S, U) send_unsignedll((S), (U))

int main(void)
{
  unsigned char sk[MUPQ_CRYPTO_SECRETKEYBYTES];
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES];
  unsigned char sm[MLEN + MUPQ_CRYPTO_BYTES];
  size_t smlen;
  unsigned int rc;
  unsigned long long t0, t1;
  int i;

  hal_setup(CLOCK_FAST);   /* 168 MHz deployment clock */
  hal_send_str("==========================");

  for (i = 0; i < MUPQ_ITERATIONS; i++) {
    t0 = hal_get_time();
    MUPQ_crypto_sign_keypair(pk, sk);
    t1 = hal_get_time();
    printcycles("keypair cycles:", t1 - t0);

    randombytes(sm, MLEN);
    t0 = hal_get_time();
    MUPQ_crypto_sign(sm, &smlen, sm, MLEN, sk);
    t1 = hal_get_time();
    printcycles("sign cycles:", t1 - t0);

    t0 = hal_get_time();
    rc = MUPQ_crypto_sign_open(sm, &smlen, sm, smlen, pk);
    t1 = hal_get_time();
    printcycles("verify cycles:", t1 - t0);

    if (rc) hal_send_str("ERROR Signature did not verify correctly!\n");
    hal_send_str("+");
  }
  hal_send_str("#");
  return 0;
}
