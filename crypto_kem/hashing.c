#include "api.h"
#include "pqm4-hal.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

// https://stackoverflow.com/a/1489985/1711232
#define PASTER(x, y) x####y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)

// use different names so we can have empty namespaces
#define MUPQ_CRYPTO_BYTES           NAMESPACE(CRYPTO_BYTES)
#define MUPQ_CRYPTO_PUBLICKEYBYTES  NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES  NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_CIPHERTEXTBYTES NAMESPACE(CRYPTO_CIPHERTEXTBYTES)
#define MUPQ_CRYPTO_ALGNAME NAMESPACE(CRYPTO_ALGNAME)

#define MUPQ_crypto_kem_keypair NAMESPACE(crypto_kem_keypair)
#define MUPQ_crypto_kem_enc NAMESPACE(crypto_kem_enc)
#define MUPQ_crypto_kem_dec NAMESPACE(crypto_kem_dec_masked)

static void printcycles(const char *s, unsigned long long c)
{
  char outs[32];
  hal_send_str(s);
  snprintf(outs,sizeof(outs),"%llu\n",c);
  hal_send_str(outs);
}

unsigned long long hash_cycles;
unsigned long long cbd_cycles;
unsigned long long xof_cycles;
unsigned long long enc_cycles;
unsigned long long dec_cycles;
unsigned long long g_cycles;
unsigned long long A2A_10_1_cycles;
unsigned long long A2A_13_10_cycles;
unsigned long long A2A_10_4_cycles;
unsigned long long gen_A_cycles;
unsigned long long mask_comp_cycles;
unsigned long long poly_enc_cycles;
unsigned long long poly_dec_cycles;
unsigned long long rng_cycles;
unsigned long long rng_calls = 0;

bool trigger = false;
uint8_t en_rand = 1;

int main(void)
{
  unsigned char key_a[MUPQ_CRYPTO_BYTES], key_b[MUPQ_CRYPTO_BYTES];
  unsigned char sk[MUPQ_CRYPTO_SECRETKEYBYTES];
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES];
  unsigned char ct[MUPQ_CRYPTO_CIPHERTEXTBYTES];
  unsigned long long t0, t1;

  hal_setup(CLOCK_BENCHMARK);

  hal_send_str("==========================");

  // Key-pair generation
  hash_cycles = 0;
  t0 = hal_get_time();
  MUPQ_crypto_kem_keypair(pk, sk);
  t1 = hal_get_time();
  printcycles("keypair cycles:", t1-t0);
  printcycles("keypair hash cycles:", hash_cycles);

  // Encapsulation
  hash_cycles = 0;
  t0 = hal_get_time();
  MUPQ_crypto_kem_enc(ct, key_a, pk);
  t1 = hal_get_time();
  printcycles("encaps cycles: ", t1-t0);
  printcycles("encaps hash cycles: ", hash_cycles);

  // Decapsulation
  hash_cycles = 0;
  cbd_cycles = xof_cycles = enc_cycles = dec_cycles = g_cycles = 0;
  t0 = hal_get_time();
  MUPQ_crypto_kem_dec(key_b, ct, sk);
  t1 = hal_get_time();
  printcycles("decaps cycles: ", t1-t0);
  printcycles("decaps cbd cycles: ", cbd_cycles);
  printcycles("decaps xof cycles: ", xof_cycles);
  printcycles("decaps gen_secret cycles: ", cbd_cycles + xof_cycles);
  printcycles("decaps enc cycles: ", enc_cycles-mask_comp_cycles);
  printcycles("decaps dec cycles: ", dec_cycles);
  printcycles("decaps g cycles: ", g_cycles);
  printcycles("decaps A2A_10_1 cycles: ", A2A_10_1_cycles);
  printcycles("decaps A2A_13_10 cycles: ", A2A_13_10_cycles);
  printcycles("decaps A2A_10_4 cycles: ", A2A_10_4_cycles);
  printcycles("decaps gen_A cycles: ", gen_A_cycles);
  printcycles("decaps mask_comp_A cycles: ", mask_comp_cycles);
  printcycles("decaps poly_enc cycles: ", poly_enc_cycles);
  printcycles("decaps poly_dec cycles: ", poly_dec_cycles);
  printcycles("decaps rng cycles: ", rng_cycles);
  printcycles("decaps rng calls: ", rng_calls);

  if (memcmp(key_a, key_b, MUPQ_CRYPTO_BYTES)) {
    hal_send_str("ERROR KEYS\n");
  }
  else {
    hal_send_str("OK KEYS\n");
  }

  hal_send_str("#");
  while(1);
  return 0;
}
