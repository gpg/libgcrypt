/* dilithium.c - the Dilithium (main part)
 * Copyright (C) 2025 g10 Code GmbH
 *
 * This file was modified for use by Libgcrypt.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * You can also use this file under the same licence of original code.
 * SPDX-License-Identifier: CC0 OR Apache-2.0
 *
 */
/*
  Original code from:

  Repository: https://github.com/pq-crystals/dilithium.git
  Branch: master
  Commit: 444cdcc84eb36b66fe27b3a2529ee48f6d8150c2

  Licence:
  Public Domain (https://creativecommons.org/share-your-work/public-domain/cc0/);
  or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).

  Authors:
        Léo Ducas
        Eike Kiltz
        Tancrède Lepoint
        Vadim Lyubashevsky
        Gregor Seiler
        Peter Schwabe
        Damien Stehlé

  Dilithium Home: https://github.com/pq-crystals/dilithium.git
 */
/*************** dilithium/ref/fips202.h */
#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136


typedef struct {
  uint64_t s[25];
  unsigned int pos;
} keccak_state;

extern const uint64_t KeccakF_RoundConstants[];

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

/*************** dilithium/ref/params.h */
#define SEEDBYTES 32
#define CRHBYTES 64
#define TRBYTES 64
#define RNDBYTES 32
#define N 256
#define Q 8380417
#define D 13
#define ROOT_OF_UNITY 1753

#if DILITHIUM_MODE == 2
#define K 4
#define L 4
#define ETA 2
#define TAU 39
#define BETA 78
#define GAMMA1 (1 << 17)
#define GAMMA2 ((Q-1)/88)
#define OMEGA 80
#define CTILDEBYTES 32

#elif DILITHIUM_MODE == 3
#define K 6
#define L 5
#define ETA 4
#define TAU 49
#define BETA 196
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q-1)/32)
#define OMEGA 55
#define CTILDEBYTES 48

#elif DILITHIUM_MODE == 5
#define K 8
#define L 7
#define ETA 2
#define TAU 60
#define BETA 120
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q-1)/32)
#define OMEGA 75
#define CTILDEBYTES 64

#endif

#define POLYT1_PACKEDBYTES  320
#define POLYT0_PACKEDBYTES  416
#define POLYVECH_PACKEDBYTES (OMEGA + K)

#if GAMMA1 == (1 << 17)
#define POLYZ_PACKEDBYTES   576
#elif GAMMA1 == (1 << 19)
#define POLYZ_PACKEDBYTES   640
#endif

#if GAMMA2 == (Q-1)/88
#define POLYW1_PACKEDBYTES  192
#elif GAMMA2 == (Q-1)/32
#define POLYW1_PACKEDBYTES  128
#endif

#if ETA == 2
#define POLYETA_PACKEDBYTES  96
#elif ETA == 4
#define POLYETA_PACKEDBYTES 128
#endif

#define CRYPTO_PUBLICKEYBYTES (SEEDBYTES + K*POLYT1_PACKEDBYTES)
#define CRYPTO_SECRETKEYBYTES (2*SEEDBYTES \
                               + TRBYTES \
                               + L*POLYETA_PACKEDBYTES \
                               + K*POLYETA_PACKEDBYTES \
                               + K*POLYT0_PACKEDBYTES)
#define CRYPTO_BYTES (CTILDEBYTES + L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)

/*************** dilithium/ref/poly.h */
typedef struct {
  int32_t coeffs[N];
} poly;

static void poly_reduce(poly *a);
static void poly_caddq(poly *a);

static void poly_add(poly *c, const poly *a, const poly *b);
static void poly_sub(poly *c, const poly *a, const poly *b);
static void poly_shiftl(poly *a);

static void poly_ntt(poly *a);
static void poly_invntt_tomont(poly *a);
static void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);

static void poly_power2round(poly *a1, poly *a0, const poly *a);
static void poly_decompose(poly *a1, poly *a0, const poly *a);
static unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1);
static void poly_use_hint(poly *b, const poly *a, const poly *h);

static int poly_chknorm(const poly *a, int32_t B);
static void poly_uniform(poly *a,
                         const uint8_t seed[SEEDBYTES],
                         uint16_t nonce);
static void poly_uniform_eta(poly *a,
                             const uint8_t seed[CRHBYTES],
                             uint16_t nonce);
static void poly_uniform_gamma1(poly *a,
                                const uint8_t seed[CRHBYTES],
                                uint16_t nonce);
static void poly_challenge(poly *c, const uint8_t seed[CTILDEBYTES]);

static void polyeta_pack(uint8_t *r, const poly *a);
static void polyeta_unpack(poly *r, const uint8_t *a);

static void polyt1_pack(uint8_t *r, const poly *a);
static void polyt1_unpack(poly *r, const uint8_t *a);

static void polyt0_pack(uint8_t *r, const poly *a);
static void polyt0_unpack(poly *r, const uint8_t *a);

static void polyz_pack(uint8_t *r, const poly *a);
static void polyz_unpack(poly *r, const uint8_t *a);

static void polyw1_pack(uint8_t *r, const poly *a);

/*************** dilithium/ref/randombytes.h */
void randombytes(uint8_t *out, size_t outlen);

/*************** dilithium/ref/reduce.h */
#define MONT -4186625 /* 2^32 % Q */
#define QINV 58728449 /* q^(-1) mod 2^32 */

static int32_t montgomery_reduce(int64_t a);

static int32_t reduce32(int32_t a);

static int32_t caddq(int32_t a);

static int32_t freeze(int32_t a);

/*************** dilithium/ref/rounding.h */
static int32_t power2round(int32_t *a0, int32_t a);

static int32_t decompose(int32_t *a0, int32_t a);

static unsigned int make_hint(int32_t a0, int32_t a1);

static int32_t use_hint(int32_t a, unsigned int hint);

/*************** dilithium/ref/sign.h */
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

int crypto_sign_signature_internal(uint8_t *sig,
                                   size_t *siglen,
                                   const uint8_t *m,
                                   size_t mlen,
                                   const uint8_t *pre,
                                   size_t prelen,
                                   const uint8_t rnd[RNDBYTES],
                                   const uint8_t *sk);

int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *ctx, size_t ctxlen,
                          const uint8_t *sk);

int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *ctx, size_t ctxlen,
                const uint8_t *sk);

int crypto_sign_verify_internal(const uint8_t *sig,
                                size_t siglen,
                                const uint8_t *m,
                                size_t mlen,
                                const uint8_t *pre,
                                size_t prelen,
                                const uint8_t *pk);

int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *ctx, size_t ctxlen,
                       const uint8_t *pk);

int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *ctx, size_t ctxlen,
                     const uint8_t *pk);

/*************** dilithium/ref/symmetric.h */
typedef keccak_state stream128_state;
typedef keccak_state stream256_state;

static void dilithium_shake128_stream_init(keccak_state *state,
                                           const uint8_t seed[SEEDBYTES],
                                           uint16_t nonce);

static void dilithium_shake256_stream_init(keccak_state *state,
                                           const uint8_t seed[CRHBYTES],
                                           uint16_t nonce);

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

#define stream128_init(STATE, SEED, NONCE) \
        dilithium_shake128_stream_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) \
        shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_init(STATE, SEED, NONCE) \
        dilithium_shake256_stream_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) \
        shake256_squeezeblocks(OUT, OUTBLOCKS, STATE)

/*************** dilithium/ref/symmetric-shake.c */

void dilithium_shake128_stream_init(keccak_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake128_init(state);
  shake128_absorb(state, seed, SEEDBYTES);
  shake128_absorb(state, t, 2);
  shake128_finalize(state);
}

void dilithium_shake256_stream_init(keccak_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake256_init(state);
  shake256_absorb(state, seed, CRHBYTES);
  shake256_absorb(state, t, 2);
  shake256_finalize(state);
}

#include "dilithium-common.c"
#include "dilithium-dep.c"
