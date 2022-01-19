#include "api.h"
#include "masked-poly.h"
#include "masked.h"
#include "poly.h"
#include "pqm4-hal.h"
#include "randombytes.h"
#include "transformpower2.h"
#include <stdio.h>
#include <string.h>
#include "a2b.h"

#define NTESTS 10

// https://stackoverflow.com/a/1489985/1711232
#define PASTER(x, y) x####y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(NAMESPACE, fun)

// use different names so we can have empty namespaces
// #define CRYPTO_BYTES           NAMESPACE(CRYPTO_BYTES)
// #define CRYPTO_PUBLICKEYBYTES  NAMESPACE(CRYPTO_PUBLICKEYBYTES)
// #define CRYPTO_SECRETKEYBYTES  NAMESPACE(CRYPTO_SECRETKEYBYTES)
// #define CRYPTO_CIPHERTEXTBYTES NAMESPACE(CRYPTO_CIPHERTEXTBYTES)
// #define CRYPTO_ALGNAME NAMESPACE(CRYPTO_ALGNAME)

// #define crypto_kem_keypair NAMESPACE(crypto_kem_keypair)
// #define crypto_kem_enc NAMESPACE(crypto_kem_enc)
// #define crypto_kem_dec NAMESPACE(crypto_kem_dec_masked)
/* allocate a bit more for all keys and messages and
 * make sure it is not touched by the implementations.
 */
static void write_canary(unsigned char *d)
{
  *((uint64_t *) d)= 0x0123456789ABCDEF;
}

static int check_canary(unsigned char *d)
{
  if(*(uint64_t *) d !=  0x0123456789ABCDEF)
    return -1;
  else
    return 0;
}

static int test_keys(void)
{
  unsigned char key_a[CRYPTO_BYTES+16];
  unsigned char key_b[CRYPTO_BYTES+16];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES+16];
  unsigned char sendb[CRYPTO_CIPHERTEXTBYTES+16];
  unsigned char masked_sk_a_buf[sizeof(masked_sk)+16];
  unsigned char masked_key_a_buf[sizeof(masked_ss) + 16];

  write_canary(key_a); write_canary(key_a+sizeof(key_a)-8);
  write_canary(key_b); write_canary(key_b+sizeof(key_b)-8);
  write_canary(pk); write_canary(pk+sizeof(pk)-8);
  write_canary(sendb); write_canary(sendb+sizeof(sendb)-8);
  write_canary(masked_key_a_buf); write_canary(masked_key_a_buf+sizeof(masked_key_a_buf)-8);
  write_canary(masked_sk_a_buf); write_canary(masked_sk_a_buf+sizeof(masked_sk_a_buf)-8);

  masked_ss *masked_key_a = (masked_ss*)&masked_key_a_buf[8];
  masked_sk *masked_sk_a = (masked_sk*)&masked_sk_a_buf[8];

  int i;

  for(i=0; i<NTESTS; i++)
  {
    //Alice generates a public key
    crypto_kem_keypair(pk+8, masked_sk_a);
    hal_send_str("DONE key pair generation!");

    //Bob derives a secret key and creates a response
    crypto_kem_enc(sendb+8, key_b+8, pk+8);
    hal_send_str("DONE encapsulation!");

    //Alice uses Bobs response to get her secret key
    crypto_kem_dec_masked(masked_key_a, sendb+8, masked_sk_a);
    hal_send_str("DONE decapsulation!");

    masked_ss_unmask(key_a+8, masked_key_a);

    if(memcmp(key_a+8, key_b+8, CRYPTO_BYTES))
    {
      hal_send_str("ERROR KEYS\n");
    }
    else if(check_canary(masked_key_a_buf) || check_canary(masked_key_a_buf+sizeof(masked_key_a_buf)-8) ||
            check_canary(key_b) || check_canary(key_b+sizeof(key_b)-8) ||
            check_canary(pk) || check_canary(pk+sizeof(pk)-8) ||
            check_canary(sendb) || check_canary(sendb+sizeof(sendb)-8) ||
            check_canary(masked_sk_a_buf) || check_canary(masked_sk_a_buf+sizeof(masked_sk_a_buf)-8))
    {
      hal_send_str("ERROR canary overwritten\n");
    }
    else
    {
      hal_send_str("OK KEYS\n");
    }
  }

  return 0;
}


// static int test_invalid_sk_a(void)
// {
//   unsigned char sk_a[CRYPTO_SECRETKEYBYTES];
//   unsigned char key_a[CRYPTO_BYTES], key_b[CRYPTO_BYTES];
//   unsigned char pk[CRYPTO_PUBLICKEYBYTES];
//   unsigned char sendb[CRYPTO_CIPHERTEXTBYTES];
//   int i;

//   for(i=0; i<NTESTS; i++)
//   {
//     //Alice generates a public key
//     crypto_kem_keypair(pk, sk_a);

//     //Bob derives a secret key and creates a response
//     crypto_kem_enc(sendb, key_b, pk);

//     //Replace secret key with random values
//     randombytes(sk_a, CRYPTO_SECRETKEYBYTES);

//     //Alice uses Bobs response to get her secre key
//     crypto_kem_dec(key_a, sendb, sk_a);

//     if(!memcmp(key_a, key_b, CRYPTO_BYTES))
//     {
//       hal_send_str("ERROR invalid sk_a\n");
//     }
//     else
//     {
//       hal_send_str("OK invalid sk_a\n");
//     }
//   }

//   return 0;
// }


// static int test_invalid_ciphertext(void)
// {
//   unsigned char sk_a[CRYPTO_SECRETKEYBYTES];
//   unsigned char key_a[CRYPTO_BYTES], key_b[CRYPTO_BYTES];
//   unsigned char pk[CRYPTO_PUBLICKEYBYTES];
//   unsigned char sendb[CRYPTO_CIPHERTEXTBYTES];
//   int i;
//   size_t pos;

//   for(i=0; i<NTESTS; i++)
//   {
//     randombytes((unsigned char *)&pos, sizeof(size_t));

//     //Alice generates a public key
//     crypto_kem_keypair(pk, sk_a);

//     //Bob derives a secret key and creates a response
//     crypto_kem_enc(sendb, key_b, pk);

//     //Change some byte in the ciphertext (i.e., encapsulated key)
//     sendb[pos % CRYPTO_CIPHERTEXTBYTES] ^= 23;

//     //Alice uses Bobs response to get her secret key
//     crypto_kem_dec(key_a, sendb, sk_a);

//     if(!memcmp(key_a, key_b, CRYPTO_BYTES))
//     {
//       hal_send_str("ERROR invalid ciphertext\n");
//     }
//     else
//     {
//       hal_send_str("OK invalid ciphertext\n");
//     }
//   }

//   return 0;
// }

static int test_transformpower2(void)
{
  static const uint16_t UPPER_BOUND = KYBER_Q;
  
  int16_t x1 = 0;
  int16_t x2 = 0;

  // The idea here is to just test a bunch of different shared pairs.
  for (size_t idx = 0; idx < 10000; idx++)
  {
      randombytes((uint8_t*)&x1, sizeof(x1));
      randombytes((uint8_t*)&x2, sizeof(x2));
      x1 = (uint16_t)x1 % UPPER_BOUND;
      x2 = (uint16_t)x2 % UPPER_BOUND;

      const int16_t x = (x1 + x2) % KYBER_Q;

      const masked_coeff_q coeff_q = {.i16 = {x1, x2}};
      masked_coeff_pow2 coeff_pow2 = transformpower2(coeff_q);

      const int16_t y1 = coeff_pow2.i16[0];
      const int16_t y2 = coeff_pow2.i16[1];
      const int16_t y = y1 + y2;

      char msg[80] = {};
      if (x != y)
      {
        snprintf(msg, sizeof(msg), "transformpower2: x1: %d, x2: %d", x1, x2);
        hal_send_str(msg);
        snprintf(msg, sizeof(msg), "transformpower2: y1: %d, y2: %d", y1, y2);
        hal_send_str(msg);
        snprintf(msg, sizeof(msg), "transformpower2: x: %d, y: %d", x, y);
        hal_send_str(msg);
        return -1;
      }
      // Uncomment these lines if you also want to see all the correct cases:
      // snprintf(msg, sizeof(msg), "transformpower2: x: %d, y: %d ✔︎", x, y);
      // hal_send_str(msg);
  }
  return 0;
}

static void unittest(void)
{

  poly a, b, c, d;
  masked_poly amasked, bmasked, cmasked;
  uint8_t seed[KYBER_SYMBYTES];
  masked_u8_symbytes seedmasked;

  // test masking
  randombytes((uint8_t *)&a, sizeof(poly));
  poly_reduce(&a);
  masked_poly_mask(&amasked, &a);
  masked_poly_unmask(&b, &amasked);

  if(memcmp(&a, &b, sizeof(poly))){
    hal_send_str("mask: bad");
  } else {
    hal_send_str("mask: good");
  }

  // test ntt
  randombytes((uint8_t *)&a, sizeof(poly));
  poly_reduce(&a);

  masked_poly_mask(&amasked, &a);
  poly_ntt(&a);
  masked_poly_ntt(&amasked);
  masked_poly_unmask(&b, &amasked);

  if(memcmp(&a, &b, sizeof(poly))){
     hal_send_str("ntt: bad");
  } else {
     hal_send_str("ntt: good");
  }

  // test invntt
  randombytes((uint8_t *)&a, sizeof(poly));
  poly_reduce(&a);

  masked_poly_mask(&amasked, &a);
  poly_invntt(&a);
  poly_reduce(&a);
  masked_poly_invntt(&amasked);
  masked_poly_unmask(&b, &amasked);
  poly_reduce(&b);
  if(memcmp(&a, &b, sizeof(poly))){
     hal_send_str("invntt: this is bad");
  } else {
     hal_send_str("invntt: good");
  }

  // test poly_add
  randombytes((uint8_t *)&a, sizeof(poly));
  poly_reduce(&a);
  randombytes((uint8_t *)&b, sizeof(poly));
  poly_reduce(&b);

  masked_poly_mask(&amasked, &a);
  masked_poly_mask(&bmasked, &b);
  poly_add(&c, &a, &b);
  masked_poly_add2(&amasked, &bmasked);
  masked_poly_unmask(&b, &amasked);

  poly_reduce(&c);

  if(memcmp(&c, &b, sizeof(poly))){
     hal_send_str("poly_add: this is bad");
  } else {
     hal_send_str("poly_add: good");
  }


  // test poly_sub
  randombytes((uint8_t *)&a, sizeof(poly));
  poly_reduce(&a);
  randombytes((uint8_t *)&b, sizeof(poly));
  poly_reduce(&b);

  masked_poly_mask(&bmasked, &b);
  poly_sub(&c, &a, &b);
  masked_poly_sub(&cmasked, &a, &bmasked);
  masked_poly_unmask(&d, &cmasked);
  poly_reduce(&c);
  poly_reduce(&d);
  if (memcmp(&c, &d, sizeof(poly)))
  {
    hal_send_str("poly_sub: this is bad");
  }
  else
  {
    hal_send_str("poly_sub: good");
  }
  
  // test transformpower2
  if (test_transformpower2() != 0)
  {
    hal_send_str("transformpower2: this is bad");
  }
  else
  {
    hal_send_str("transformpower2: good");
  }
  
  // test A2B
  uint32_t error_flag = 0;
  for (uint32_t i = 0; i < 10000 && !error_flag; i++)
  {
    randombytes((uint8_t *)&a, sizeof(poly));
    poly_reduce(&a);
    masked_poly_mask(&amasked, &a);
    for (size_t j = 0; j < KYBER_N && !error_flag; j++)
    {
      if ((A2B_convert(amasked.polys[0].coeffs[j], amasked.polys[1].coeffs[j]) ^ amasked.polys[1].coeffs[j]) != (uint32_t)a.coeffs[j])
      {
        error_flag = 1;
      }
    }
  }
  if (!error_flag)
  {
     hal_send_str("A2B: this is bad");
  } else {
     hal_send_str("A2B: good");
  }

  // test poly_noise
  randombytes(seed, KYBER_SYMBYTES);
  poly_noise(&a, seed, 0, 0);
  poly_reduce(&a);

  masked_u8_mask(&seedmasked, seed, KYBER_SYMBYTES);
  masked_poly_noise(&amasked, &seedmasked, 0, 0);
  masked_poly_unmask(&b, &amasked);
  
  if(memcmp(&a, &b, sizeof(poly))){
     hal_send_str("poly_noise: this is bad");
  } else {
     hal_send_str("poly_noise: good");
  }
}

uint8_t en_rand = 1;

int main(void)
{
  hal_setup(CLOCK_FAST);

  // marker for automated testing
  hal_send_str("==========================");
  test_keys();
  // test_invalid_sk_a();
  // test_invalid_ciphertext();
  unittest();
  hal_send_str("#");

  while(1);

  return 0;
}
