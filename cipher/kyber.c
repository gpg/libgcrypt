/*
  Original code from:

  Repository: https://github.com/pq-crystals/kyber.git
  Branch: standard
  Commit: 11d00ff1f20cfca1f72d819e5a45165c1e0a2816

  Licence:
  Public Domain (https://creativecommons.org/share-your-work/public-domain/cc0/);
  or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).

  Authors:
        Joppe Bos
        Léo Ducas
        Eike Kiltz
        Tancrède Lepoint
        Vadim Lyubashevsky
        John Schanck
        Peter Schwabe
        Gregor Seiler
        Damien Stehlé

  Kyber Home: https://www.pq-crystals.org/kyber/
 */

/*************** kyber/ref/fips202.h */
#define SHAKE128_RATE 168

typedef struct {
  uint64_t s[25];
  unsigned int pos;
} keccak_state;

void shake128_init(keccak_state *state);
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void shake128_finalize(keccak_state *state);
void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);

void shake256_init(keccak_state *state);
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void shake256_finalize(keccak_state *state);
void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
void shake256_squeezeblocks(uint8_t *out, size_t nblocks,  keccak_state *state);

void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);

/*************** kyber/ref/params.h */
#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define KYBER_POLYBYTES          384

#define KYBER_ETA2 2

/* KYBER_K dependent values */
#define KYBER_ETA1_2   3
#define KYBER_ETA1_3_4 2

#define KYBER_POLYCOMPRESSEDBYTES_2_3 128
#define KYBER_POLYCOMPRESSEDBYTES_4   160

#if KYBER_K == 2
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 4
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif
#define KYBER_POLYVECBYTES      (KYBER_K * KYBER_POLYBYTES)
#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)

/*************** kyber/ref/poly.h */
/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
  int16_t coeffs[KYBER_N];
} poly;

#if !defined(KYBER_K) || KYBER_K == 2 || KYBER_K == 3
static void poly_compress_128(uint8_t r[KYBER_POLYCOMPRESSEDBYTES_2_3], const poly *a);
static void poly_decompress_128(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES_2_3]);
#endif
#if !defined(KYBER_K) || KYBER_K == 4
static void poly_compress_160(uint8_t r[KYBER_POLYCOMPRESSEDBYTES_4], const poly *a);
static void poly_decompress_160(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES_4]);
#endif
static void poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a);
static void poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]);

static void poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]);
static void poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *r);
#if !defined(KYBER_K) || KYBER_K == 2
static void poly_getnoise_eta1_2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);
#endif
#if !defined(KYBER_K) || KYBER_K == 3 || KYBER_K == 4
static void poly_getnoise_eta1_3_4(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);
#endif
static void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

static void poly_ntt(poly *r);
static void poly_invntt_tomont(poly *r);
static void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
static void poly_tomont(poly *r);

static void poly_reduce(poly *r);

static void poly_add(poly *r, const poly *a, const poly *b);
static void poly_sub(poly *r, const poly *a, const poly *b);

/*************** kyber/ref/polyvec.h */
typedef struct{
  poly vec[KYBER_K];
} polyvec;

static void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a);
static void polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]);

static void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a);
static void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);

static void polyvec_ntt(polyvec *r);
static void polyvec_invntt_tomont(polyvec *r);

static void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b);

static void polyvec_reduce(polyvec *r);

static void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

/*************** kyber/ref/indcpa.h */
static void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);

static void indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                                  uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                                  const uint8_t coins[KYBER_SYMBYTES]);

static void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]);

static void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

/*************** kyber/ref/kem.h */
#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KYBER_SSBYTES

#if   (KYBER_K == 2)
#define CRYPTO_ALGNAME "Kyber512"
#elif (KYBER_K == 3)
#define CRYPTO_ALGNAME "Kyber768"
#elif (KYBER_K == 4)
#define CRYPTO_ALGNAME "Kyber1024"
#endif

static int crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

static int crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/*************** kyber/ref/ntt.h */
static const int16_t zetas[128];

static void ntt(int16_t poly[256]);

static void invntt(int16_t poly[256]);

static void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

/*************** kyber/ref/randombytes.h */
void randombytes(uint8_t *out, size_t outlen);

/*************** kyber/ref/reduce.h */
#define MONT -1044 // 2^16 mod q
#define QINV -3327 // q^-1 mod 2^16

static int16_t montgomery_reduce(int32_t a);

static int16_t barrett_reduce(int16_t a);

/*************** kyber/ref/symmetric.h */
typedef keccak_state xof_state;

static void kyber_shake128_absorb(keccak_state *s,
                                  const uint8_t seed[KYBER_SYMBYTES],
                                  uint8_t x,
                                  uint8_t y);

static void kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

static void kyber_shake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) kyber_shake256_rkprf(OUT, KEY, INPUT)

/*************** kyber/ref/verify.h */
int verify(const uint8_t *a, const uint8_t *b, size_t len);

void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);
/*************** kyber/ref/symmetric-shake.c */

/*************************************************
* Name:        kyber_shake128_absorb
*
* Description: Absorb step of the SHAKE128 specialized for the Kyber context.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *seed: pointer to KYBER_SYMBYTES input to be absorbed into state
*              - uint8_t i: additional byte of input
*              - uint8_t j: additional byte of input
**************************************************/
void kyber_shake128_absorb(keccak_state *state,
                           const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y)
{
  uint8_t extseed[KYBER_SYMBYTES+2];

  memcpy(extseed, seed, KYBER_SYMBYTES);
  extseed[KYBER_SYMBYTES+0] = x;
  extseed[KYBER_SYMBYTES+1] = y;

  shake128_absorb_once(state, extseed, sizeof(extseed));
}

/*************************************************
* Name:        kyber_shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
*              - uint8_t nonce: single-byte nonce (public PRF input)
**************************************************/
void kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t extkey[KYBER_SYMBYTES+1];

  memcpy(extkey, key, KYBER_SYMBYTES);
  extkey[KYBER_SYMBYTES] = nonce;

  shake256(out, outlen, extkey, sizeof(extkey));
}

/*************************************************
* Name:        kyber_shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
*              - uint8_t nonce: single-byte nonce (public PRF input)
**************************************************/
void kyber_shake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES])
{
  keccak_state s;

  shake256_init(&s);
  shake256_absorb(&s, key, KYBER_SYMBYTES);
  shake256_absorb(&s, input, KYBER_CIPHERTEXTBYTES);
  shake256_finalize(&s);
  shake256_squeeze(out, KYBER_SSBYTES, &s);
}

#include "kyber-common.c"
#include "kyber-kdep.c"
