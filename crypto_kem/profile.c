#include "api.h"
#include "pqm4-hal.h"
#include "randombytes.h"

#include <string.h>

uint8_t en_rand = 1;
bool trigger = false;
// uint32_t randclear;

// The profile_{before_keypair,after_keypair,after_enc,after_dec} functions
// are meant as markers for the debugger to break on.  They implement nop
// slides of different lenghts to prevent the compiler from merging them
// into a single function.

__attribute__((optimize("-O0"))) void profile_before_keypair() {
       asm("nop");
}

__attribute__((optimize("-O0"))) void profile_after_keypair() {
       asm("nop");
       asm("nop");
}

__attribute__((optimize("-O0"))) void profile_after_enc() {
       asm("nop");
       asm("nop");
       asm("nop");
}

__attribute__((optimize("-O0"))) void profile_after_dec() {
       asm("nop");
       asm("nop");
       asm("nop");
       asm("nop");
}

static int profile_kem(void)
{
    static const int CRYPTO_ITERATIONS = 1000;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    masked_sk sk;
    uint8_t ct[CRYPTO_SECRETKEYBYTES];
    uint8_t unmasked_ss[CRYPTO_BYTES];
    masked_ss ss;

    profile_before_keypair();
    for (int i = 0; i < CRYPTO_ITERATIONS; i++)
    {
        crypto_kem_keypair(pk, &sk);
    }

    profile_after_keypair();

    for (int i = 0; i < CRYPTO_ITERATIONS; i++)
    {
        crypto_kem_enc(ct, unmasked_ss, pk);
    }

    profile_after_enc();

    for (int i = 0; i < CRYPTO_ITERATIONS; i++)
    {
        crypto_kem_dec_masked(&ss, ct, &sk);
    }

    profile_after_dec();
    return 0;
}


int main(void)
{
    hal_setup(CLOCK_BENCHMARK);
    profile_kem();
    while(1);
    return 0;
}

