/* scrypt.c - Scrypt password-based key derivation function.
 *
 * This file is part of Libgcrypt.
 */

/* Adapted from the nettle, low-level cryptographics library for
 * libgcrypt by Christian Grothoff; original license:
 *
 * Copyright (C) 2012 Simon Josefsson
 *
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

#include <config.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "g10lib.h"
#include "scrypt.h"
#include "memxor.h"



#define _SALSA20_INPUT_LENGTH 16

#define ROTL32(n,x) (((x)<<(n)) | ((x)>>(32-(n))))


/* Reads a 64-bit integer, in network, big-endian, byte order */
#define READ_UINT64(p)                          \
(  (((uint64_t) (p)[0]) << 56)                  \
 | (((uint64_t) (p)[1]) << 48)                  \
 | (((uint64_t) (p)[2]) << 40)                  \
 | (((uint64_t) (p)[3]) << 32)                  \
 | (((uint64_t) (p)[4]) << 24)                  \
 | (((uint64_t) (p)[5]) << 16)                  \
 | (((uint64_t) (p)[6]) << 8)                   \
 |  ((uint64_t) (p)[7]))



/* And the other, little-endian, byteorder */
#define LE_READ_UINT64(p)                       \
(  (((uint64_t) (p)[7]) << 56)                  \
 | (((uint64_t) (p)[6]) << 48)                  \
 | (((uint64_t) (p)[5]) << 40)                  \
 | (((uint64_t) (p)[4]) << 32)                  \
 | (((uint64_t) (p)[3]) << 24)                  \
 | (((uint64_t) (p)[2]) << 16)                  \
 | (((uint64_t) (p)[1]) << 8)                   \
 |  ((uint64_t) (p)[0]))



#ifdef WORDS_BIGENDIAN
#define LE_SWAP32(v)				\
  ((ROTL32(8,  v) & 0x00FF00FFUL) |		\
   (ROTL32(24, v) & 0xFF00FF00UL))
#else
#define LE_SWAP32(v) (v)
#endif

#define QROUND(x0, x1, x2, x3) do { \
  x1 ^= ROTL32(7, x0 + x3);	    \
  x2 ^= ROTL32(9, x1 + x0);	    \
  x3 ^= ROTL32(13, x2 + x1);	    \
  x0 ^= ROTL32(18, x3 + x2);	    \
  } while(0)


static void
_salsa20_core(uint32_t *dst, const uint32_t *src, unsigned rounds)
{
  uint32_t x[_SALSA20_INPUT_LENGTH];
  unsigned i;

  assert ( (rounds & 1) == 0);

  memcpy (x, src, sizeof(x));
  for (i = 0; i < rounds;i += 2)
    {
      QROUND(x[0], x[4], x[8], x[12]);
      QROUND(x[5], x[9], x[13], x[1]);
      QROUND(x[10], x[14], x[2], x[6]);
      QROUND(x[15], x[3], x[7], x[11]);

      QROUND(x[0], x[1], x[2], x[3]);
      QROUND(x[5], x[6], x[7], x[4]);
      QROUND(x[10], x[11], x[8], x[9]);
      QROUND(x[15], x[12], x[13], x[14]);
    }

  for (i = 0; i < _SALSA20_INPUT_LENGTH; i++)
    {
      uint32_t t = x[i] + src[i];
      dst[i] = LE_SWAP32 (t);
    }
}


static void
_scryptBlockMix (uint32_t r, uint8_t *B, uint8_t *tmp2)
{
  uint64_t i;
  uint8_t *X = tmp2;
  uint8_t *Y = tmp2 + 64;

#if 0
  for (i = 0; i < 2 * r; i++)
    {
      size_t j;
      printf ("B[%d]: ", i);
      for (j = 0; j < 64; j++)
	{
	  if (j % 4 == 0)
	    printf (" ");
	  printf ("%02x", B[i * 64 + j]);
	}
      printf ("\n");
    }
#endif

  /* X = B[2 * r - 1] */
  memcpy (X, &B[(2 * r - 1) * 64], 64);

  /* for i = 0 to 2 * r - 1 do */
  for (i = 0; i <= 2 * r - 1; i++)
    {
      /* T = X xor B[i] */
      memxor(X, &B[i * 64], 64);

      /* X = Salsa (T) */
      _salsa20_core (X, X, 8);

      /* Y[i] = X */
      memcpy (&Y[i * 64], X, 64);
    }

  for (i = 0; i < r; i++)
    {
      memcpy (&B[i * 64], &Y[2 * i * 64], 64);
      memcpy (&B[(r + i) * 64], &Y[(2 * i + 1) * 64], 64);
    }

#if 0
  for (i = 0; i < 2 * r; i++)
    {
      size_t j;
      printf ("B'[%d]: ", i);
      for (j = 0; j < 64; j++)
	{
	  if (j % 4 == 0)
	    printf (" ");
	  printf ("%02x", B[i * 64 + j]);
	}
      printf ("\n");
    }
#endif
}

static void
_scryptROMix (uint32_t r, uint8_t *B, uint64_t N,
	      uint8_t *tmp1, uint8_t *tmp2)
{
  uint8_t *X = B, *T = B;
  uint64_t i;

#if 0
  printf ("B: ");
  for (i = 0; i < 128 * r; i++)
    {
      size_t j;
      if (i % 4 == 0)
	printf (" ");
      printf ("%02x", B[i]);
    }
  printf ("\n");
#endif

  /* for i = 0 to N - 1 do */
  for (i = 0; i <= N - 1; i++)
    {
      /* V[i] = X */
      memcpy (&tmp1[i * 128 * r], X, 128 * r);

      /* X =  ScryptBlockMix (X) */
      _scryptBlockMix (r, X, tmp2);
    }

  /* for i = 0 to N - 1 do */
  for (i = 0; i <= N - 1; i++)
    {
      uint64_t j;

      /* j = Integerify (X) mod N */
      j = LE_READ_UINT64 (&X[128 * r - 64]) % N;

      /* T = X xor V[j] */
      memxor (T, &tmp1[j * 128 * r], 128 * r);

      /* X = scryptBlockMix (T) */
      _scryptBlockMix (r, T, tmp2);
    }

#if 0
  printf ("B': ");
  for (i = 0; i < 128 * r; i++)
    {
      size_t j;
      if (i % 4 == 0)
	printf (" ");
      printf ("%02x", B[i]);
    }
  printf ("\n");
#endif
}

/**
 */
gcry_err_code_t
scrypt (const uint8_t * passwd, size_t passwdlen,
	int subalgo,
	const uint8_t * salt, size_t saltlen,
	unsigned long iterations,
	size_t dkLen, uint8_t * DK)
{
  /* XXX sanity-check parameters */
  uint64_t N = subalgo; /* CPU/memory cost paramter */
  uint32_t r = 8; /* block size, should be sane enough */
  uint32_t p = iterations; /* parallelization parameter */

  uint32_t i;
  uint8_t *B;
  uint8_t *tmp1;
  uint8_t *tmp2;


  B = malloc (p * 128 * r);
  if (B == NULL)
    return GPG_ERR_ENOMEM;

  tmp1 = malloc (N * 128 * r);
  if (tmp1 == NULL)
  {
    free (B);
    return GPG_ERR_ENOMEM;
  }

  tmp2 = malloc (64 + 128 * r);
  if (tmp2 == NULL)
  {
    free (B);
    free (tmp1);
    return GPG_ERR_ENOMEM;
  }

  pkdf2 (passwd, passwdlen, GCRY_MD_SHA256, salt, saltlen, 1 /* iterations */, p * 128 * r, B);

  for (i = 0; i < p; i++)
    _scryptROMix (r, &B[i * 128 * r], N, tmp1, tmp2);

  for (i = 0; i < p; i++)
    pkdf2 (passwd, passwdlen, GCRY_MD_SHA256, B, p * 128 * r, 1 /* iterations */, dkLen, DK);

  free (tmp2);
  free (tmp1);
  free (B);

  return 0;
}
