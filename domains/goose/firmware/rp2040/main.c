// PQC benchmark harness for the Raspberry Pi Pico (RP2040, Cortex-M0+, no FPU/DSP).
// pqm4 doesn't target M0+, so this is a standalone pico-sdk harness over the PQClean 'clean'
// (portable) implementations. Measures keygen/sign/verify cycles with the M0+ SysTick (no DWT
// on ARMv6-M) and prints over USB CDC in the pqm4-compatible "<op> cycles:\n<N>" format, read
// by a serial collector (/dev/ttyACM). Bring-up scheme: ML-DSA-44 clean (hard-coded namespace).
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/stdio_usb.h"
#include "hardware/structs/systick.h"
#include "hardware/gpio.h"
#include "api.h"

// scheme namespace selected by -DSCHEME_{FALCON,MLKEM} (else ML-DSA-44); include dir set in CMake
#if defined(SCHEME_MLKEM)
#define NS(x) PQCLEAN_MLKEM512_CLEAN_##x
#define KEM 1
#define KP  NS(crypto_kem_keypair)
#define ENC NS(crypto_kem_enc)
#define DEC NS(crypto_kem_dec)
#define PKB NS(CRYPTO_PUBLICKEYBYTES)
#define SKB NS(CRYPTO_SECRETKEYBYTES)
#define CTB NS(CRYPTO_CIPHERTEXTBYTES)
#define SSB NS(CRYPTO_BYTES)
#elif defined(SCHEME_FALCON)
#define NS(x) PQCLEAN_FALCON512_CLEAN_##x
#define KP   NS(crypto_sign_keypair)
#define SG   NS(crypto_sign)
#define OPEN NS(crypto_sign_open)
#define PKB  NS(CRYPTO_PUBLICKEYBYTES)
#define SKB  NS(CRYPTO_SECRETKEYBYTES)
#define SIGB NS(CRYPTO_BYTES)
#else
#define NS(x) PQCLEAN_MLDSA44_CLEAN_##x
#define KP   NS(crypto_sign_keypair)
#define SG   NS(crypto_sign)
#define OPEN NS(crypto_sign_open)
#define PKB  NS(CRYPTO_PUBLICKEYBYTES)
#define SKB  NS(CRYPTO_SECRETKEYBYTES)
#define SIGB NS(CRYPTO_BYTES)
#endif
#define LED_PIN 25  // Pico onboard LED (GPIO25)

#ifndef N_ITERS
#define N_ITERS 50
#endif
#define MLEN 59

// SysTick: 24-bit downcounter @ processor clock + overflow ISR → 64-bit up-counting cycles.
static volatile uint64_t ovf = 0;
void isr_systick(void) { ovf++; }
static void systick_setup(void) {
    systick_hw->rvr = 0x00FFFFFFu;
    systick_hw->cvr = 0;
    systick_hw->csr = (1u << 2) | (1u << 1) | (1u << 0); // CLKSOURCE=core, TICKINT, ENABLE
}
static uint64_t cyc(void) {
    uint32_t c; uint64_t o;
    do { o = ovf; c = systick_hw->cvr; } while (o != ovf);   // consistent (count, overflow)
    return (o << 24) + (0x00FFFFFFu - c);
}

// Deterministic xorshift randombytes — for benchmarking only, NOT cryptographic.
// PQClean schemes call PQCLEAN_randombytes (namespaced), not randombytes.
static uint64_t rng = 0x123456789abcdef0ULL;
int PQCLEAN_randombytes(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; buf[i] = (uint8_t)rng; }
    return 0;
}

int main(void) {
    stdio_init_all();
    systick_setup();
    gpio_init(LED_PIN); gpio_set_dir(LED_PIN, GPIO_OUT);
    for (int k = 0; k < 3; k++) { gpio_put(LED_PIN, 1); sleep_ms(120); gpio_put(LED_PIN, 0); sleep_ms(120); }  // boot: alive
    while (!stdio_usb_connected()) {  // slow blink = waiting for the host to open the port
        gpio_put(LED_PIN, 1); sleep_ms(80); gpio_put(LED_PIN, 0); sleep_ms(400);
    }
    sleep_ms(500);

    uint64_t t0, t1;
    printf("==========================\n");
#ifdef KEM
    static uint8_t pk[PKB], sk[SKB], ct[CTB], ss[SSB];
    for (int i = 0; i < N_ITERS; i++) {
        gpio_put(LED_PIN, 1);
        t0 = cyc(); KP(pk, sk); t1 = cyc();
        printf("keypair cycles:\n%llu\n", (unsigned long long)(t1 - t0));
        t0 = cyc(); ENC(ct, ss, pk); t1 = cyc();
        printf("encaps cycles:\n%llu\n", (unsigned long long)(t1 - t0));
        t0 = cyc(); DEC(ss, ct, sk); t1 = cyc();
        printf("decaps cycles:\n%llu\n", (unsigned long long)(t1 - t0));
        gpio_put(LED_PIN, 0);
        printf("+\n");
    }
#else
    static uint8_t pk[PKB], sk[SKB], sm[MLEN + SIGB];
    size_t smlen;
    for (int i = 0; i < N_ITERS; i++) {
        gpio_put(LED_PIN, 1);  // LED on while this iteration runs (M0+ is slow → clearly visible)
        t0 = cyc(); KP(pk, sk); t1 = cyc();
        printf("keypair cycles:\n%llu\n", (unsigned long long)(t1 - t0));
        PQCLEAN_randombytes(sm, MLEN);
        t0 = cyc(); SG(sm, &smlen, sm, MLEN, sk); t1 = cyc();
        printf("sign cycles:\n%llu\n", (unsigned long long)(t1 - t0));
        t0 = cyc(); int rc = OPEN(sm, &smlen, sm, smlen, pk); t1 = cyc();
        printf("verify cycles:\n%llu\n", (unsigned long long)(t1 - t0));
        if (rc) printf("ERROR verify\n");
        gpio_put(LED_PIN, 0);
        printf("+\n");
    }
#endif
    printf("#\n");
    while (1) tight_loop_contents();
}
