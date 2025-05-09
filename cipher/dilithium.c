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
/*
 * This implementation consists of four files: dilithium.h (header),
 * dilithium.c (this), dilithium-common.c (common part), and
 * dilithium-dep.c (DILITHIUM_MODE dependent part).
 *
 * It is for inclusion in libgcrypt library.  Also, standalone use of
 * the implementation is possible.  With DILITHIUM_MODE defined, it
 * can offer the variant of that DILITHIUM_MODE specified.  Otherwise,
 * three variants are offered.
 *
 * From original code, following modification was made.
 *
 * - C++ style comments are changed to C-style.
 *
 * - No use of DILITHIUM_NAMESPACE and FIPS202_NAMESPACE.  Don't export
 *   internal symbols.
 *
 * - Different external API for shake128 and shake256, having _init
 *   and _close.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef _GCRYPT_IN_LIBGCRYPT
#include <stdarg.h>
#include <gpg-error.h>

#include "types.h"
#include "g10lib.h"
#include "gcrypt-int.h"
#include "const-time.h"

#define DILITHIUM_MODE 2
#include "dilithium.h"

static void
randombytes (uint8_t *out, size_t outlen)
{
  _gcry_randomize (out, outlen, GCRY_VERY_STRONG_RANDOM);
}

typedef struct {
  gcry_md_hd_t h;
} keccak_state;

static void
shake128_init (keccak_state *state)
{
  gcry_err_code_t ec;

  ec = _gcry_md_open (&state->h, GCRY_MD_SHAKE128, 0);
  if (ec)
    log_fatal ("internal md_open failed: %d\n", ec);
}

static void
shake128_absorb (keccak_state *state, const uint8_t *in, size_t inlen)
{
  _gcry_md_write (state->h, in, inlen);
}

static void
shake128_finalize (keccak_state *state)
{
  (void)state;
}

static void
shake128_squeeze (uint8_t *out, size_t outlen, keccak_state *state)
{
  _gcry_md_extract (state->h, GCRY_MD_SHAKE128, out, outlen);
}

static void
shake128_close (keccak_state *state)
{
  _gcry_md_close (state->h);
}

static void
shake256_init (keccak_state *state)
{
  gcry_err_code_t ec;

  ec = _gcry_md_open (&state->h, GCRY_MD_SHAKE256, 0);
  if (ec)
    log_fatal ("internal md_open failed: %d\n", ec);
}

static void
shake256_absorb (keccak_state *state, const uint8_t *in, size_t inlen)
{
  _gcry_md_write (state->h, in, inlen);
}

static void
shake256_finalize (keccak_state *state)
{
  (void)state;
}

static void
shake256_squeeze (uint8_t *out, size_t outlen, keccak_state *state)
{
  _gcry_md_extract (state->h, GCRY_MD_SHAKE256, out, outlen);
}

static void
shake256_close (keccak_state *state)
{
  _gcry_md_close (state->h);
}

static void
shake256 (uint8_t *out, size_t outlen, const uint8_t *in,
	  size_t inlen)
{
  gcry_buffer_t iov[1];

  iov[0].size = 0;
  iov[0].data = (uint8_t *)in;
  iov[0].off = 0;
  iov[0].len = inlen;

  _gcry_md_hash_buffers_extract (GCRY_MD_SHAKE256, 0, out, outlen,
                                 iov, 1);
}
#else
/* to be filled soon...  */
#endif

/*************** dilithium/ref/config.h */
#define DILITHIUM_RANDOMIZED_SIGNING

/*************** dilithium/ref/fips202.h */
#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

/*************** dilithium/ref/params.h */
#define SEEDBYTES 32
#define CRHBYTES 64
#define TRBYTES 64
#define RNDBYTES 32
#define N 256
#define Q 8380417
#define D 13
#define ROOT_OF_UNITY 1753

/* DILITHIUM_MODE dependent values (part 1) */
#define ETA2 2
#define ETA4 4
#define GAMMA1_17 (1 << 17)
#define GAMMA1_19 (1 << 19)
#define GAMMA2_32 ((Q-1)/32)
#define GAMMA2_88 ((Q-1)/88)
#define POLYZ_PACKEDBYTES_17   576
#define POLYZ_PACKEDBYTES_19   640
#define POLYW1_PACKEDBYTES_88  192
#define POLYW1_PACKEDBYTES_32  128
#define POLYETA_PACKEDBYTES_2  96
#define POLYETA_PACKEDBYTES_4 128

/*************** dilithium/ref/poly.h */
typedef struct {
  int32_t coeffs[N];
} poly;

/*************** dilithium/ref/reduce.h */
#define MONT -4186625 /* 2^32 % Q */
#define QINV 58728449 /* q^(-1) mod 2^32 */

/*************** dilithium/ref/symmetric.h */
typedef keccak_state stream128_state;
typedef keccak_state stream256_state;

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

/*************** dilithium/ref/params.h */
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

/*************** */
/* Forward declarations */
int32_t montgomery_reduce(int64_t a);
int32_t reduce32(int32_t a);
int32_t caddq(int32_t a);
int32_t power2round(int32_t *a0, int32_t a);
int32_t decompose(int32_t *a0, int32_t a);
unsigned int make_hint(int32_t a0, int32_t a1);
int32_t use_hint(int32_t a, unsigned int hint);
void polyz_pack(uint8_t *r, const poly *a);
void polyz_unpack(poly *r, const uint8_t *a);

/* Glue code */
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) \
	shake128_squeeze(OUT, SHAKE128_RATE*OUTBLOCKS, STATE)
#define stream128_close(STATE) shake128_close(STATE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) \
	shake256_squeeze(OUT, SHAKE256_RATE*OUTBLOCKS, STATE)
#define stream256_close(STATE) shake256_close(STATE)

#define shake256_squeezeblocks(OUT, OUTBLOCKS, STATE) \
	shake256_squeeze(OUT, SHAKE256_RATE*OUTBLOCKS, STATE)

void stream128_init(keccak_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake128_init(state);
  shake128_absorb(state, seed, SEEDBYTES);
  shake128_absorb(state, t, 2);
  shake128_finalize(state);
}

void stream256_init(keccak_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce)
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
