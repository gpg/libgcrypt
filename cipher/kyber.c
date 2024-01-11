#include <config.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <gpg-error.h>

#include "types.h"
#include "g10lib.h"
#include "gcrypt-int.h"
#include "const-time.h"
#include "kyber.h"

static int crypto_kem_keypair_2(uint8_t *pk, uint8_t *sk);
static int crypto_kem_keypair_3(uint8_t *pk, uint8_t *sk);
static int crypto_kem_keypair_4(uint8_t *pk, uint8_t *sk);

static int crypto_kem_enc_2(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
static int crypto_kem_enc_3(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
static int crypto_kem_enc_4(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

static int crypto_kem_dec_2(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
static int crypto_kem_dec_3(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
static int crypto_kem_dec_4(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

void
kyber_keypair (int algo, uint8_t *pk, uint8_t *sk)
{
  switch (algo)
    {
    case GCRY_KEM_MLKEM512:
      crypto_kem_keypair_2 (pk, sk);
      break;
    case GCRY_KEM_MLKEM768:
    default:
      crypto_kem_keypair_3 (pk, sk);
      break;
    case GCRY_KEM_MLKEM1024:
      crypto_kem_keypair_4 (pk, sk);
      break;
    }
}

void
kyber_encap (int algo, uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
  switch (algo)
    {
    case GCRY_KEM_MLKEM512:
      crypto_kem_enc_2 (ct, ss, pk);
      break;
    case GCRY_KEM_MLKEM768:
    default:
      crypto_kem_enc_3 (ct, ss, pk);
      break;
    case GCRY_KEM_MLKEM1024:
      crypto_kem_enc_4 (ct, ss, pk);
      break;
    }
}

void
kyber_decap (int algo, uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
  switch (algo)
    {
    case GCRY_KEM_MLKEM512:
      crypto_kem_dec_2 (ss, ct, sk);
      break;
    case GCRY_KEM_MLKEM768:
    default:
      crypto_kem_dec_3 (ss, ct, sk);
      break;
    case GCRY_KEM_MLKEM1024:
      crypto_kem_dec_4 (ss, ct, sk);
      break;
    }
}

static void
randombytes (uint8_t *out, size_t outlen)
{
  _gcry_randomize (out, outlen, GCRY_VERY_STRONG_RANDOM);
}

typedef struct {
  gcry_md_hd_t h;
} keccak_state;

static void
shake128_absorb_once (keccak_state *state, const uint8_t *in, size_t inlen)
{
  gcry_err_code_t ec;

  ec = _gcry_md_open (&state->h, GCRY_MD_SHAKE128, 0);
  if (ec)
    log_fatal ("internal md_open failed: %d\n", ec);
  _gcry_md_write (state->h, in, inlen);
}

#define SHAKE128_RATE 168
static void
shake128_squeezeblocks (uint8_t *out, size_t nblocks, keccak_state *state)
{
  gcry_err_code_t ec;

  ec = _gcry_md_extract (state->h, GCRY_MD_SHAKE128, out,
                         SHAKE128_RATE * nblocks);
  if (ec)
    log_fatal ("internal md_extract failed: %d\n", ec);
}

static void
shake128_close (keccak_state *state)
{
  _gcry_md_close (state->h);
}

#define MAX_ARGS 16
static void
shake256v (uint8_t *out, size_t outlen, ...)
{
  gcry_buffer_t iov[MAX_ARGS];
  va_list ap;
  int i;
  void *p;
  size_t len;

  va_start (ap, outlen);
  for (i = 0; i < MAX_ARGS; i++)
    {
      p = va_arg (ap, void *);
      len = va_arg (ap, size_t);
      if (!p)
        break;

      iov[i].size = 0;
      iov[i].data = p;
      iov[i].off = 0;
      iov[i].len = len;
    }
  va_end (ap);

  _gcry_md_hash_buffers_extract (GCRY_MD_SHAKE256, 0, out, outlen,
                                 iov, i);
}

static void
sha3_256 (uint8_t h[32], const uint8_t *in, size_t inlen)
{
  _gcry_md_hash_buffer (GCRY_MD_SHA3_256, h, in, inlen);
}

static void
sha3_512 (uint8_t h[64], const uint8_t *in, size_t inlen)
{
  _gcry_md_hash_buffer (GCRY_MD_SHA3_512, h, in, inlen);
}

/*
  Code from:

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

#if 0
typedef struct {
  uint64_t s[25];
  unsigned int pos;
} keccak_state;

void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);

void shake256_init(keccak_state *state);
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void shake256_finalize(keccak_state *state);
void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);

void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);
#endif

/*************** kyber/ref/params.h */
#undef KYBER_K

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define KYBER_POLYBYTES		384
//#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)
#define KYBER_POLYVECBYTES2	(2 * KYBER_POLYBYTES)
#define KYBER_POLYVECBYTES3	(3 * KYBER_POLYBYTES)
#define KYBER_POLYVECBYTES4	(4 * KYBER_POLYBYTES)

#define KYBER_ETA1_2   3
#define KYBER_ETA1_3_4 2

#if 0
#if KYBER_K == 2
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 4
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif
#endif
#define KYBER_POLYCOMPRESSEDBYTES2   128
#define KYBER_POLYCOMPRESSEDBYTES3   128
#define KYBER_POLYCOMPRESSEDBYTES4   160
#define KYBER_POLYVECCOMPRESSEDBYTES2 (2 * 320)
#define KYBER_POLYVECCOMPRESSEDBYTES3 (3 * 320)
#define KYBER_POLYVECCOMPRESSEDBYTES4 (4 * 352)

#define KYBER_ETA2 2

#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
//#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES2 (KYBER_POLYVECBYTES2 + KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES3 (KYBER_POLYVECBYTES3 + KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES4 (KYBER_POLYVECBYTES4 + KYBER_SYMBYTES)

//#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES2 (KYBER_POLYVECBYTES2)
#define KYBER_INDCPA_SECRETKEYBYTES3 (KYBER_POLYVECBYTES3)
#define KYBER_INDCPA_SECRETKEYBYTES4 (KYBER_POLYVECBYTES4)
//#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)
#define KYBER_INDCPA_BYTES2      (KYBER_POLYVECCOMPRESSEDBYTES2 + KYBER_POLYCOMPRESSEDBYTES2)
#define KYBER_INDCPA_BYTES3      (KYBER_POLYVECCOMPRESSEDBYTES3 + KYBER_POLYCOMPRESSEDBYTES3)
#define KYBER_INDCPA_BYTES4      (KYBER_POLYVECCOMPRESSEDBYTES4 + KYBER_POLYCOMPRESSEDBYTES4)

//#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
#define KYBER_PUBLICKEYBYTES2  (KYBER_INDCPA_PUBLICKEYBYTES2)
#define KYBER_PUBLICKEYBYTES3  (KYBER_INDCPA_PUBLICKEYBYTES3)
#define KYBER_PUBLICKEYBYTES4  (KYBER_INDCPA_PUBLICKEYBYTES4)
/* 32 bytes of additional space to save H(pk) */
//#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_SECRETKEYBYTES2  (KYBER_INDCPA_SECRETKEYBYTES2 + KYBER_INDCPA_PUBLICKEYBYTES2 + 2*KYBER_SYMBYTES)
#define KYBER_SECRETKEYBYTES3  (KYBER_INDCPA_SECRETKEYBYTES3 + KYBER_INDCPA_PUBLICKEYBYTES3 + 2*KYBER_SYMBYTES)
#define KYBER_SECRETKEYBYTES4  (KYBER_INDCPA_SECRETKEYBYTES4 + KYBER_INDCPA_PUBLICKEYBYTES4 + 2*KYBER_SYMBYTES)
//#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)
#define KYBER_CIPHERTEXTBYTES2 (KYBER_INDCPA_BYTES2)
#define KYBER_CIPHERTEXTBYTES3 (KYBER_INDCPA_BYTES3)
#define KYBER_CIPHERTEXTBYTES4 (KYBER_INDCPA_BYTES4)

/*************** kyber/ref/poly.h */
/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
  int16_t coeffs[KYBER_N];
} poly;

static void poly_compress_128(uint8_t r[128], const poly *a);
static void poly_compress_160(uint8_t r[160], const poly *a);
static void poly_decompress_128(poly *r, const uint8_t a[128]);
static void poly_decompress_160(poly *r, const uint8_t a[160]);

static void poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a);
static void poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]);

static void poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]);
static void poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *r);

static void poly_getnoise_eta1_2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);
static void poly_getnoise_eta1_3_4(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

static void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

static void poly_ntt(poly *r);
static void poly_invntt_tomont(poly *r);
static void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
static void poly_tomont(poly *r);

static void poly_reduce(poly *r);

static void poly_add(poly *r, const poly *a, const poly *b);
static void poly_sub(poly *r, const poly *a, const poly *b);

/*************** kyber/ref/ntt.h */
static const int16_t zetas[128];

static void ntt(int16_t poly[256]);

static void invntt(int16_t poly[256]);

static void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

/*************** kyber/ref/randombytes.h */
#if 0
void randombytes(uint8_t *out, size_t outlen);
#endif

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

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) shake256v(OUT, OUTBYTES, KEY, KYBER_SYMBYTES, &nonce, 1, NULL, 0)
#define rkprf(OUT, KEY, INPUT) shake256v(OUT, KYBER_SSBYTES, KEY, KYBER_SYMBYTES, INPUT, KYBER_CIPHERTEXTBYTES, NULL, 0)

/*************** kyber/ref/verify.h */
#if 0
int verify(const uint8_t *a, const uint8_t *b, size_t len);

void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);
#else
#define verify ct_memequal
#define cmov   ct_memmov_cond
#endif

/*************** kyber/ref/cbd.c */

/*************************************************
* Name:        load32_littleendian
*
* Description: load 4 bytes into a 32-bit integer
*              in little-endian order
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x
**************************************************/
static uint32_t load32_littleendian(const uint8_t x[4])
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  r |= (uint32_t)x[3] << 24;
  return r;
}

/*************************************************
* Name:        load24_littleendian
*
* Description: load 3 bytes into a 32-bit integer
*              in little-endian order.
*              This function is only needed for Kyber-512
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x (most significant byte is zero)
**************************************************/
static uint32_t load24_littleendian(const uint8_t x[3])
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  return r;
}


/*************************************************
* Name:        cbd2
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=2
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
static void cbd2(poly *r, const uint8_t buf[2*KYBER_N/4])
{
  unsigned int i,j;
  uint32_t t,d;
  int16_t a,b;

  for(i=0;i<KYBER_N/8;i++) {
    t  = load32_littleendian(buf+4*i);
    d  = t & 0x55555555;
    d += (t>>1) & 0x55555555;

    for(j=0;j<8;j++) {
      a = (d >> (4*j+0)) & 0x3;
      b = (d >> (4*j+2)) & 0x3;
      r->coeffs[8*i+j] = a - b;
    }
  }
}

/*************************************************
* Name:        cbd3
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=3.
*              This function is only needed for Kyber-512
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
static void cbd3(poly *r, const uint8_t buf[3*KYBER_N/4])
{
  unsigned int i,j;
  uint32_t t,d;
  int16_t a,b;

  for(i=0;i<KYBER_N/4;i++) {
    t  = load24_littleendian(buf+3*i);
    d  = t & 0x00249249;
    d += (t>>1) & 0x00249249;
    d += (t>>2) & 0x00249249;

    for(j=0;j<4;j++) {
      a = (d >> (6*j+0)) & 0x7;
      b = (d >> (6*j+3)) & 0x7;
      r->coeffs[4*i+j] = a - b;
    }
  }
}

/*************** kyber/ref/indcpa.c */
/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < KYBER_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

/*************** kyber/ref/ntt.c */
/* Code to generate zetas and zetas_inv used in the number-theoretic transform:

#define KYBER_ROOT_OF_UNITY 17

static const uint8_t tree[128] = {
  0, 64, 32, 96, 16, 80, 48, 112, 8, 72, 40, 104, 24, 88, 56, 120,
  4, 68, 36, 100, 20, 84, 52, 116, 12, 76, 44, 108, 28, 92, 60, 124,
  2, 66, 34, 98, 18, 82, 50, 114, 10, 74, 42, 106, 26, 90, 58, 122,
  6, 70, 38, 102, 22, 86, 54, 118, 14, 78, 46, 110, 30, 94, 62, 126,
  1, 65, 33, 97, 17, 81, 49, 113, 9, 73, 41, 105, 25, 89, 57, 121,
  5, 69, 37, 101, 21, 85, 53, 117, 13, 77, 45, 109, 29, 93, 61, 125,
  3, 67, 35, 99, 19, 83, 51, 115, 11, 75, 43, 107, 27, 91, 59, 123,
  7, 71, 39, 103, 23, 87, 55, 119, 15, 79, 47, 111, 31, 95, 63, 127
};

void init_ntt() {
  unsigned int i;
  int16_t tmp[128];

  tmp[0] = MONT;
  for(i=1;i<128;i++)
    tmp[i] = fqmul(tmp[i-1],MONT*KYBER_ROOT_OF_UNITY % KYBER_Q);

  for(i=0;i<128;i++) {
    zetas[i] = tmp[tree[i]];
    if(zetas[i] > KYBER_Q/2)
      zetas[i] -= KYBER_Q;
    if(zetas[i] < -KYBER_Q/2)
      zetas[i] += KYBER_Q;
  }
}
*/

static const int16_t zetas[128] = {
  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
   -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
   -681,  1017,   732,   608, -1542,   411,  -205, -1571,
   1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
   -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
   -398,   961, -1508,  -725,   448, -1065,   677, -1275,
  -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
   -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
  -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
  -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
  -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
   -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

/*************************************************
* Name:        fqmul
*
* Description: Multiplication followed by Montgomery reduction
*
* Arguments:   - int16_t a: first factor
*              - int16_t b: second factor
*
* Returns 16-bit integer congruent to a*b*R^{-1} mod q
**************************************************/
static int16_t fqmul(int16_t a, int16_t b) {
  return montgomery_reduce((int32_t)a*b);
}

/*************************************************
* Name:        ntt
*
* Description: Inplace number-theoretic transform (NTT) in Rq.
*              input is in standard order, output is in bitreversed order
*
* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
**************************************************/
void ntt(int16_t r[256]) {
  unsigned int len, start, j, k;
  int16_t t, zeta;

  k = 1;
  for(len = 128; len >= 2; len >>= 1) {
    for(start = 0; start < 256; start = j + len) {
      zeta = zetas[k++];
      for(j = start; j < start + len; j++) {
        t = fqmul(zeta, r[j + len]);
        r[j + len] = r[j] - t;
        r[j] = r[j] + t;
      }
    }
  }
}

/*************************************************
* Name:        invntt_tomont
*
* Description: Inplace inverse number-theoretic transform in Rq and
*              multiplication by Montgomery factor 2^16.
*              Input is in bitreversed order, output is in standard order
*
* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
**************************************************/
void invntt(int16_t r[256]) {
  unsigned int start, len, j, k;
  int16_t t, zeta;
  const int16_t f = 1441; // mont^2/128

  k = 127;
  for(len = 2; len <= 128; len <<= 1) {
    for(start = 0; start < 256; start = j + len) {
      zeta = zetas[k--];
      for(j = start; j < start + len; j++) {
        t = r[j];
        r[j] = barrett_reduce(t + r[j + len]);
        r[j + len] = r[j + len] - t;
        r[j + len] = fqmul(zeta, r[j + len]);
      }
    }
  }

  for(j = 0; j < 256; j++)
    r[j] = fqmul(r[j], f);
}

/*************************************************
* Name:        basemul
*
* Description: Multiplication of polynomials in Zq[X]/(X^2-zeta)
*              used for multiplication of elements in Rq in NTT domain
*
* Arguments:   - int16_t r[2]: pointer to the output polynomial
*              - const int16_t a[2]: pointer to the first factor
*              - const int16_t b[2]: pointer to the second factor
*              - int16_t zeta: integer defining the reduction polynomial
**************************************************/
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)
{
  r[0]  = fqmul(a[1], b[1]);
  r[0]  = fqmul(r[0], zeta);
  r[0] += fqmul(a[0], b[0]);
  r[1]  = fqmul(a[0], b[1]);
  r[1] += fqmul(a[1], b[0]);
}
/*************** kyber/ref/poly.c */

/*************************************************
* Name:        poly_compress
*
* Description: Compression and subsequent serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (of length KYBER_POLYCOMPRESSEDBYTES)
*              - const poly *a: pointer to input polynomial
**************************************************/
void poly_compress_128(uint8_t r[KYBER_POLYCOMPRESSEDBYTES2], const poly *a)
{
  unsigned int i,j;
  int32_t u;
  uint32_t d0;
  uint8_t t[8];

  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      // map to positive standard representatives
      u  = a->coeffs[8*i+j];
      u += (u >> 15) & KYBER_Q;
/*    t[j] = ((((uint16_t)u << 4) + KYBER_Q/2)/KYBER_Q) & 15; */
      d0 = u << 4;
      d0 += 1665;
      d0 *= 80635;
      d0 >>= 28;
      t[j] = d0 & 0xf;
    }

    r[0] = t[0] | (t[1] << 4);
    r[1] = t[2] | (t[3] << 4);
    r[2] = t[4] | (t[5] << 4);
    r[3] = t[6] | (t[7] << 4);
    r += 4;
  }
}

void poly_compress_160(uint8_t r[KYBER_POLYCOMPRESSEDBYTES4], const poly *a)
{
  unsigned int i,j;
  int32_t u;
  uint32_t d0;
  uint8_t t[8];

  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      // map to positive standard representatives
      u  = a->coeffs[8*i+j];
      u += (u >> 15) & KYBER_Q;
/*    t[j] = ((((uint32_t)u << 5) + KYBER_Q/2)/KYBER_Q) & 31; */
      d0 = u << 5;
      d0 += 1664;
      d0 *= 40318;
      d0 >>= 27;
      t[j] = d0 & 0x1f;
    }

    r[0] = (t[0] >> 0) | (t[1] << 5);
    r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
    r[2] = (t[3] >> 1) | (t[4] << 4);
    r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
    r[4] = (t[6] >> 2) | (t[7] << 3);
    r += 5;
  }
}

/*************************************************
* Name:        poly_decompress
*
* Description: De-serialization and subsequent decompression of a polynomial;
*              approximate inverse of poly_compress
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of length KYBER_POLYCOMPRESSEDBYTES bytes)
**************************************************/
void poly_decompress_128(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES2])
{
  unsigned int i;
  for(i=0;i<KYBER_N/2;i++) {
    r->coeffs[2*i+0] = (((uint16_t)(a[0] & 15)*KYBER_Q) + 8) >> 4;
    r->coeffs[2*i+1] = (((uint16_t)(a[0] >> 4)*KYBER_Q) + 8) >> 4;
    a += 1;
  }
}

void poly_decompress_160(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES4])
{
  unsigned int i;
  unsigned int j;
  uint8_t t[8];
  for(i=0;i<KYBER_N/8;i++) {
    t[0] = (a[0] >> 0);
    t[1] = (a[0] >> 5) | (a[1] << 3);
    t[2] = (a[1] >> 2);
    t[3] = (a[1] >> 7) | (a[2] << 1);
    t[4] = (a[2] >> 4) | (a[3] << 4);
    t[5] = (a[3] >> 1);
    t[6] = (a[3] >> 6) | (a[4] << 2);
    t[7] = (a[4] >> 3);
    a += 5;

    for(j=0;j<8;j++)
      r->coeffs[8*i+j] = ((uint32_t)(t[j] & 31)*KYBER_Q + 16) >> 5;
  }
}

/*************************************************
* Name:        poly_tobytes
*
* Description: Serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYBYTES bytes)
*              - const poly *a: pointer to input polynomial
**************************************************/
void poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a)
{
  unsigned int i;
  uint16_t t0, t1;

  for(i=0;i<KYBER_N/2;i++) {
    // map to positive standard representatives
    t0  = a->coeffs[2*i];
    t0 += ((int16_t)t0 >> 15) & KYBER_Q;
    t1 = a->coeffs[2*i+1];
    t1 += ((int16_t)t1 >> 15) & KYBER_Q;
    r[3*i+0] = (t0 >> 0);
    r[3*i+1] = (t0 >> 8) | (t1 << 4);
    r[3*i+2] = (t1 >> 4);
  }
}

/*************************************************
* Name:        poly_frombytes
*
* Description: De-serialization of a polynomial;
*              inverse of poly_tobytes
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of KYBER_POLYBYTES bytes)
**************************************************/
void poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES])
{
  unsigned int i;
  for(i=0;i<KYBER_N/2;i++) {
    r->coeffs[2*i]   = ((a[3*i+0] >> 0) | ((uint16_t)a[3*i+1] << 8)) & 0xFFF;
    r->coeffs[2*i+1] = ((a[3*i+1] >> 4) | ((uint16_t)a[3*i+2] << 4)) & 0xFFF;
  }
}

/*************************************************
* Name:        poly_frommsg
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *msg: pointer to input message
**************************************************/
void poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES])
{
  unsigned int i,j;
  int16_t mask;

#if (KYBER_INDCPA_MSGBYTES != KYBER_N/8)
#error "KYBER_INDCPA_MSGBYTES must be equal to KYBER_N/8 bytes!"
#endif

  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      mask = -(int16_t)((msg[i] >> j)&1);
      r->coeffs[8*i+j] = mask & ((KYBER_Q+1)/2);
    }
  }
}

/*************************************************
* Name:        poly_tomsg
*
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - uint8_t *msg: pointer to output message
*              - const poly *a: pointer to input polynomial
**************************************************/
void poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *a)
{
  unsigned int i,j;
  uint32_t t;

  for(i=0;i<KYBER_N/8;i++) {
    msg[i] = 0;
    for(j=0;j<8;j++) {
      t  = a->coeffs[8*i+j];
      // t += ((int16_t)t >> 15) & KYBER_Q;
      // t  = (((t << 1) + KYBER_Q/2)/KYBER_Q) & 1;
      t <<= 1;
      t += 1665;
      t *= 80635;
      t >>= 28;
      t &= 1;
      msg[i] |= t << j;
    }
  }
}

/*************************************************
* Name:        poly_getnoise_eta1
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA1
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed
*                                     (of length KYBER_SYMBYTES bytes)
*              - uint8_t nonce: one-byte input nonce
**************************************************/
void poly_getnoise_eta1_2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t buf[KYBER_ETA1_2*KYBER_N/4];
  prf(buf, sizeof(buf), seed, nonce);
  cbd3(r, buf);
}

void poly_getnoise_eta1_3_4(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t buf[KYBER_ETA1_3_4*KYBER_N/4];
  prf(buf, sizeof(buf), seed, nonce);
  cbd2(r, buf);
}

/*************************************************
* Name:        poly_getnoise_eta2
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA2
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed
*                                     (of length KYBER_SYMBYTES bytes)
*              - uint8_t nonce: one-byte input nonce
**************************************************/
void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t buf[KYBER_ETA2*KYBER_N/4];
  prf(buf, sizeof(buf), seed, nonce);
  cbd2(r, buf);
}


/*************************************************
* Name:        poly_ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *r: pointer to in/output polynomial
**************************************************/
void poly_ntt(poly *r)
{
  ntt(r->coeffs);
  poly_reduce(r);
}

/*************************************************
* Name:        poly_invntt_tomont
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT)
*              of a polynomial in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
void poly_invntt_tomont(poly *r)
{
  invntt(r->coeffs);
}

/*************************************************
* Name:        poly_basemul_montgomery
*
* Description: Multiplication of two polynomials in NTT domain
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b)
{
  unsigned int i;
  for(i=0;i<KYBER_N/4;i++) {
    basemul(&r->coeffs[4*i], &a->coeffs[4*i], &b->coeffs[4*i], zetas[64+i]);
    basemul(&r->coeffs[4*i+2], &a->coeffs[4*i+2], &b->coeffs[4*i+2], -zetas[64+i]);
  }
}

/*************************************************
* Name:        poly_tomont
*
* Description: Inplace conversion of all coefficients of a polynomial
*              from normal domain to Montgomery domain
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void poly_tomont(poly *r)
{
  unsigned int i;
  const int16_t f = (1ULL << 32) % KYBER_Q;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i]*f);
}

/*************************************************
* Name:        poly_reduce
*
* Description: Applies Barrett reduction to all coefficients of a polynomial
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void poly_reduce(poly *r)
{
  unsigned int i;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = barrett_reduce(r->coeffs[i]);
}

/*************************************************
* Name:        poly_add
*
* Description: Add two polynomials; no modular reduction is performed
*
* Arguments: - poly *r: pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void poly_add(poly *r, const poly *a, const poly *b)
{
  unsigned int i;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract two polynomials; no modular reduction is performed
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void poly_sub(poly *r, const poly *a, const poly *b)
{
  unsigned int i;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/*************** kyber/ref/reduce.c */

/*************************************************
* Name:        montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^-1 mod q, where R=2^16
*
* Arguments:   - int32_t a: input integer to be reduced;
*                           has to be in {-q2^15,...,q2^15-1}
*
* Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
**************************************************/
int16_t montgomery_reduce(int32_t a)
{
  int16_t t;

  t = (int16_t)a*QINV;
  t = (a - (int32_t)t*KYBER_Q) >> 16;
  return t;
}

/*************************************************
* Name:        barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}
*
* Arguments:   - int16_t a: input integer to be reduced
*
* Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
**************************************************/
int16_t barrett_reduce(int16_t a) {
  int16_t t;
  const int16_t v = ((1<<26) + KYBER_Q/2)/KYBER_Q;

  t  = ((int32_t)v*a + (1<<25)) >> 26;
  t *= KYBER_Q;
  return a - t;
}
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

#define VARIANT2(name) name ## _2
#define VARIANT3(name) name ## _3
#define VARIANT4(name) name ## _4

#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)
#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)

#define KYBER_K 2
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#define poly_compress poly_compress_128
#define poly_decompress poly_decompress_128
#define poly_getnoise_eta1 poly_getnoise_eta1_2
#define crypto_kem_keypair_derand VARIANT2(crypto_kem_keypair_derand)
#define crypto_kem_enc_derand VARIANT2(crypto_kem_enc_derand)
#define crypto_kem_keypair VARIANT2(crypto_kem_keypair)
#define crypto_kem_enc VARIANT2(crypto_kem_enc)
#define crypto_kem_dec VARIANT2(crypto_kem_dec)
#define polyvec VARIANT2(polyvec)
#define polyvec_compress VARIANT2(polyvec_compress)
#define polyvec_decompress VARIANT2(polyvec_decompress)
#define polyvec_tobytes VARIANT2(polyvec_tobytes)
#define polyvec_frombytes VARIANT2(polyvec_frombytes)
#define polyvec_ntt VARIANT2(polyvec_ntt)
#define polyvec_invntt_tomont VARIANT2(polyvec_invntt_tomont)
#define polyvec_basemul_acc_montgomery VARIANT2(polyvec_basemul_acc_montgomery)
#define polyvec_reduce VARIANT2(polyvec_reduce)
#define polyvec_add VARIANT2(polyvec_add)
#define pack_pk VARIANT2(pack_pk)
#define unpack_pk VARIANT2(unpack_pk)
#define pack_sk VARIANT2(pack_sk)
#define unpack_sk VARIANT2(unpack_sk)
#define pack_ciphertext VARIANT2(pack_ciphertext)
#define unpack_ciphertext VARIANT2(unpack_ciphertext)
#define gen_matrix VARIANT2(gen_matrix)
#define indcpa_keypair_derand VARIANT2(indcpa_keypair_derand)
#define indcpa_enc VARIANT2(indcpa_enc)
#define indcpa_dec VARIANT2(indcpa_dec)
#include "kyber-impl.c"

#undef KYBER_K
#undef KYBER_POLYCOMPRESSEDBYTES
#undef KYBER_POLYVECCOMPRESSEDBYTES
#undef poly_compress
#undef poly_decompress
#undef poly_getnoise_eta1
#undef crypto_kem_keypair_derand
#undef crypto_kem_enc_derand
#undef crypto_kem_keypair
#undef crypto_kem_enc
#undef crypto_kem_dec
#undef polyvec
#undef polyvec_compress
#undef polyvec_decompress
#undef polyvec_tobytes
#undef polyvec_frombytes
#undef polyvec_ntt
#undef polyvec_invntt_tomont
#undef polyvec_basemul_acc_montgomery
#undef polyvec_reduce
#undef polyvec_add
#undef pack_pk
#undef unpack_pk
#undef pack_sk
#undef unpack_sk
#undef pack_ciphertext
#undef unpack_ciphertext
#undef gen_matrix
#undef indcpa_keypair_derand
#undef indcpa_enc
#undef indcpa_dec

#define KYBER_K 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#define poly_compress poly_compress_128
#define poly_decompress poly_decompress_128
#define poly_getnoise_eta1 poly_getnoise_eta1_3_4
#define crypto_kem_keypair_derand VARIANT3(crypto_kem_keypair_derand)
#define crypto_kem_enc_derand VARIANT3(crypto_kem_enc_derand)
#define crypto_kem_keypair VARIANT3(crypto_kem_keypair)
#define crypto_kem_enc VARIANT3(crypto_kem_enc)
#define crypto_kem_dec VARIANT3(crypto_kem_dec)
#define polyvec VARIANT3(polyvec)
#define polyvec_compress VARIANT3(polyvec_compress)
#define polyvec_decompress VARIANT3(polyvec_decompress)
#define polyvec_tobytes VARIANT3(polyvec_tobytes)
#define polyvec_frombytes VARIANT3(polyvec_frombytes)
#define polyvec_ntt VARIANT3(polyvec_ntt)
#define polyvec_invntt_tomont VARIANT3(polyvec_invntt_tomont)
#define polyvec_basemul_acc_montgomery VARIANT3(polyvec_basemul_acc_montgomery)
#define polyvec_reduce VARIANT3(polyvec_reduce)
#define polyvec_add VARIANT3(polyvec_add)
#define pack_pk VARIANT3(pack_pk)
#define unpack_pk VARIANT3(unpack_pk)
#define pack_sk VARIANT3(pack_sk)
#define unpack_sk VARIANT3(unpack_sk)
#define pack_ciphertext VARIANT3(pack_ciphertext)
#define unpack_ciphertext VARIANT3(unpack_ciphertext)
#define gen_matrix VARIANT3(gen_matrix)
#define indcpa_keypair_derand VARIANT3(indcpa_keypair_derand)
#define indcpa_enc VARIANT3(indcpa_enc)
#define indcpa_dec VARIANT3(indcpa_dec)
#include "kyber-impl.c"

#undef KYBER_K
#undef KYBER_POLYCOMPRESSEDBYTES
#undef KYBER_POLYVECCOMPRESSEDBYTES
#undef poly_compress
#undef poly_decompress
#undef poly_getnoise_eta1
#undef crypto_kem_keypair_derand
#undef crypto_kem_enc_derand
#undef crypto_kem_keypair
#undef crypto_kem_enc
#undef crypto_kem_dec
#undef polyvec
#undef polyvec_compress
#undef polyvec_decompress
#undef polyvec_tobytes
#undef polyvec_frombytes
#undef polyvec_ntt
#undef polyvec_invntt_tomont
#undef polyvec_basemul_acc_montgomery
#undef polyvec_reduce
#undef polyvec_add
#undef pack_pk
#undef unpack_pk
#undef pack_sk
#undef unpack_sk
#undef pack_ciphertext
#undef unpack_ciphertext
#undef gen_matrix
#undef indcpa_keypair_derand
#undef indcpa_enc
#undef indcpa_dec

#define KYBER_K 4
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#define poly_compress poly_compress_160
#define poly_decompress poly_decompress_160
#define poly_getnoise_eta1 poly_getnoise_eta1_3_4
#define crypto_kem_keypair_derand VARIANT4(crypto_kem_keypair_derand)
#define crypto_kem_enc_derand VARIANT4(crypto_kem_enc_derand)
#define crypto_kem_keypair VARIANT4(crypto_kem_keypair)
#define crypto_kem_enc VARIANT4(crypto_kem_enc)
#define crypto_kem_dec VARIANT4(crypto_kem_dec)
#define polyvec VARIANT4(polyvec)
#define polyvec_compress VARIANT4(polyvec_compress)
#define polyvec_decompress VARIANT4(polyvec_decompress)
#define polyvec_tobytes VARIANT4(polyvec_tobytes)
#define polyvec_frombytes VARIANT4(polyvec_frombytes)
#define polyvec_ntt VARIANT4(polyvec_ntt)
#define polyvec_invntt_tomont VARIANT4(polyvec_invntt_tomont)
#define polyvec_basemul_acc_montgomery VARIANT4(polyvec_basemul_acc_montgomery)
#define polyvec_reduce VARIANT4(polyvec_reduce)
#define polyvec_add VARIANT4(polyvec_add)
#define pack_pk VARIANT4(pack_pk)
#define unpack_pk VARIANT4(unpack_pk)
#define pack_sk VARIANT4(pack_sk)
#define unpack_sk VARIANT4(unpack_sk)
#define pack_ciphertext VARIANT4(pack_ciphertext)
#define unpack_ciphertext VARIANT4(unpack_ciphertext)
#define gen_matrix VARIANT4(gen_matrix)
#define indcpa_keypair_derand VARIANT4(indcpa_keypair_derand)
#define indcpa_enc VARIANT4(indcpa_enc)
#define indcpa_dec VARIANT4(indcpa_dec)
#include "kyber-impl.c"
