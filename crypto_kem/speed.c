#include "api.h"
#include "pqm4-hal.h"
#include "poly.h"

#include <math.h>
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

uint8_t en_rand = 1;
bool trigger = false;
// uint32_t randclear;

int main(void)
{
  unsigned char key_a[CRYPTO_BYTES];
  unsigned char key_b[CRYPTO_BYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];
  unsigned char sendb[CRYPTO_CIPHERTEXTBYTES];
  masked_ss masked_key_a;
  masked_sk masked_sk_a;
  //static const size_t ITERATIONS = 10;
  uint64_t t0, t1, baseline;

  hal_setup(CLOCK_BENCHMARK);
  hal_send_str("==========================");

  struct { uint64_t keygen, encaps, decaps; } measurements[ITERATIONS] = {0};
  #ifdef DETAILBENCHMARK
  struct decaps_measurements details[ITERATIONS] = {0};
  #endif

  bool ok_keys = true;
  for (size_t i = 0; i < ITERATIONS; i++) {

    t0 = hal_get_time();
    t1 = hal_get_time();
    baseline = t1 - t0;

    // Key-pair generation
    t0 = hal_get_time();
    crypto_kem_keypair(pk, &masked_sk_a);
    t1 = hal_get_time();
    measurements[i].keygen = t1 - t0 - baseline;

    // Encapsulation
    t0 = hal_get_time();
    crypto_kem_enc(sendb, key_b, pk);
    t1 = hal_get_time();
    measurements[i].encaps = t1 - t0 - baseline;

    // Decapsulation
    t0 = hal_get_time();
    #ifdef DETAILBENCHMARK
    crypto_kem_dec_masked(&masked_key_a, sendb, &masked_sk_a, &details[i]);
    #else
    crypto_kem_dec_masked(&masked_key_a, sendb, &masked_sk_a);
    #endif
    t1 = hal_get_time();
    measurements[i].decaps = t1 - t0 - baseline;

  // MATRIX-VECTOR MULTIPLICATION
  //   uint16_t bw_ar[SABER_K][7][9][N_SB_16];
  //   uint16_t skpv[SABER_K][SABER_N];
  //   polyvec a[SABER_K];// skpv;
  //   uint16_t res[SABER_K][SABER_N];
  //   t0 = hal_get_time();  
  // #ifdef PQM4_VERSION_1
  //   MatrixVectorMul(a,skpv,res,SABER_Q-1,1);
  // #else
  //   int i;
  //   for(i=0;i<SABER_K;i++) {
  //     evaluation_single_kara((const uint16_t *)skpv[i], bw_ar[i]);
  //   }
  //   MatrixVectorMul(a,bw_ar,skpv,res,SABER_Q-1,1);
  // #endif
  //   t1 = hal_get_time();
  //   printcycles("MVmult cycles: ", t1-t0-baseline);

    masked_ss_unmask(key_a, &masked_key_a);
    if (memcmp(key_a, key_b, CRYPTO_BYTES) != 0) {
      ok_keys = false;
      hal_send_str("ERROR KEYS\n");
      break;
    }
  }

  double keygen_avg = 0, encaps_avg = 0, decaps_avg = 0;
  double keygen_stdev = 0, encaps_stdev = 0, decaps_stdev = 0;
  for (size_t i = 0; i < ITERATIONS; i++) {
    keygen_avg += measurements[i].keygen;
    encaps_avg += measurements[i].encaps;
    decaps_avg += measurements[i].decaps;
  }
  keygen_avg /= ITERATIONS;
  encaps_avg /= ITERATIONS;
  decaps_avg /= ITERATIONS;

  for (size_t i = 0; i < ITERATIONS; i++) {
    keygen_stdev += (measurements[i].keygen - keygen_avg) * (measurements[i].keygen - keygen_avg);
    encaps_stdev += (measurements[i].encaps - encaps_avg) * (measurements[i].encaps - encaps_avg);
    decaps_stdev += (measurements[i].decaps - decaps_avg) * (measurements[i].decaps - decaps_avg);
  }
  keygen_stdev = sqrt(keygen_stdev / ITERATIONS);
  encaps_stdev = sqrt(encaps_stdev / ITERATIONS);
  decaps_stdev = sqrt(decaps_stdev / ITERATIONS);

  char buf[80] = {0};
  snprintf(buf, sizeof(buf), "iterations: %d", ITERATIONS);
  hal_send_str(buf);
  snprintf(buf, sizeof(buf), "keygen: avg %.2f, stdev %.2f [cc]", keygen_avg, keygen_stdev);
  hal_send_str(buf);
  snprintf(buf, sizeof(buf), "encaps: avg %.2f, stdev %.2f [cc]", encaps_avg, encaps_stdev);
  hal_send_str(buf);
  snprintf(buf, sizeof(buf), "decaps: avg %.2f, stdev %.2f [cc]", decaps_avg, decaps_stdev);
  hal_send_str(buf);
  hal_send_str("==========================");
  snprintf(buf, sizeof(buf), "indcpadec: avg %lld", details[0].indcpadec);
  hal_send_str(buf);
  snprintf(buf, sizeof(buf), "unpackdecomp: avg %lld", details[0].unpackdecomp);
  hal_send_str(buf);
  snprintf(buf, sizeof(buf), "arithmetic: avg %lld", details[0].decarith);
  hal_send_str(buf);
  snprintf(buf, sizeof(buf), "compress: avg %lld", details[0].compress);
  hal_send_str(buf);
  hal_send_str("==========================");
  snprintf(buf, sizeof(buf), "indcpa_(re)enc: avg %lld", details[0].reenc);
  hal_send_str(buf);
  snprintf(buf, sizeof(buf), "noise: avg %lld", details[0].encsample);
  hal_send_str(buf);
  snprintf(buf, sizeof(buf), "matacc: avg %lld", details[0].encmatacc);
  hal_send_str(buf);
  snprintf(buf, sizeof(buf), "arithmetic: avg %lld", details[0].encarith);
  hal_send_str(buf);
  snprintf(buf, sizeof(buf), "decompress: avg %lld", details[0].decompress);
  hal_send_str(buf);
  hal_send_str("==========================");
    snprintf(buf, sizeof(buf), "compare: avg %lld", details[0].comp);
  hal_send_str(buf);
  snprintf(buf, sizeof(buf), "hash H: avg %lld", details[0].hashh);
  hal_send_str(buf);
  snprintf(buf, sizeof(buf), "hash G: avg %lld", details[0].hashg);
  hal_send_str(buf);
  snprintf(buf, sizeof(buf), "kdf: avg %lld", details[0].kdf);
  hal_send_str(buf);

  if (ok_keys) {
    hal_send_str("OK KEYS\n");
  }

  hal_send_str("#");
  while(1);
  return 0;
}
