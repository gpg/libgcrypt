/* Elgamal.c  -  ElGamal Public Key encryption
 * Copyright (C) 1998, 2000, 2001, 2002, 2003, 2005 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 * For a description of the algorithm, see:
 *   Bruce Schneier: Applied Cryptography. John Wiley & Sons, 1996.
 *   ISBN 0-471-11709-9. Pages 476 ff.
 */

#include <gcrypt-ac-internal.h>

#include <gcrypt-mpi-internal.h>
#include <gcrypt-prime-internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sha1.h>
#include <elg.h>



typedef struct
{
  gcry_core_mpi_t p;	    /* prime */
  gcry_core_mpi_t g;	    /* group generator */
  gcry_core_mpi_t y;	    /* g^x mod p */
} ELG_public_key;


typedef struct
{
  gcry_core_mpi_t p;	    /* prime */
  gcry_core_mpi_t g;	    /* group generator */
  gcry_core_mpi_t y;	    /* g^x mod p */
  gcry_core_mpi_t x;	    /* secret exponent */
} ELG_secret_key;


static void test_keys (gcry_core_context_t ctx, ELG_secret_key *sk, unsigned nbits);
static gcry_core_mpi_t gen_k (gcry_core_context_t ctx,
			 gcry_core_mpi_t p, int small_k);
static void generate (gcry_core_context_t ctx,
		      ELG_secret_key *sk, unsigned nbits, gcry_core_mpi_t **factors);
static int  check_secret_key (gcry_core_context_t ctx, ELG_secret_key *sk);
static void do_encrypt (gcry_core_context_t ctx,
			gcry_core_mpi_t a, gcry_core_mpi_t b, gcry_core_mpi_t input,
                        ELG_public_key *pkey);
static void decrypt (gcry_core_context_t ctx,
		     gcry_core_mpi_t output, gcry_core_mpi_t a, gcry_core_mpi_t b,
                     ELG_secret_key *skey);
static void sign (gcry_core_context_t ctx,
		  gcry_core_mpi_t a, gcry_core_mpi_t b, gcry_core_mpi_t input,
                  ELG_secret_key *skey);
static int  verify (gcry_core_context_t ctx,
		    gcry_core_mpi_t a, gcry_core_mpi_t b, gcry_core_mpi_t input,
                    ELG_public_key *pkey);

#define progress(ctx, c) _gcry_core_progress (ctx, "pk_elg", c, 0, 0)



/****************
 * Michael Wiener's table on subgroup sizes to match field sizes
 * (floating around somewhere - Fixme: need a reference)
 */
static unsigned int
wiener_map( unsigned int n )
{
  static struct { unsigned int p_n, q_n; } t[] =
    { /*   p	  q	 attack cost */
      {  512, 119 },	/* 9 x 10^17 */
      {  768, 145 },	/* 6 x 10^21 */
      { 1024, 165 },	/* 7 x 10^24 */
      { 1280, 183 },	/* 3 x 10^27 */
      { 1536, 198 },	/* 7 x 10^29 */
      { 1792, 212 },	/* 9 x 10^31 */
      { 2048, 225 },	/* 8 x 10^33 */
      { 2304, 237 },	/* 5 x 10^35 */
      { 2560, 249 },	/* 3 x 10^37 */
      { 2816, 259 },	/* 1 x 10^39 */
      { 3072, 269 },	/* 3 x 10^40 */
      { 3328, 279 },	/* 8 x 10^41 */
      { 3584, 288 },	/* 2 x 10^43 */
      { 3840, 296 },	/* 4 x 10^44 */
      { 4096, 305 },	/* 7 x 10^45 */
      { 4352, 313 },	/* 1 x 10^47 */
      { 4608, 320 },	/* 2 x 10^48 */
      { 4864, 328 },	/* 2 x 10^49 */
      { 5120, 335 },	/* 3 x 10^50 */
      { 0, 0 }
    };
  int i;

  for(i=0; t[i].p_n; i++ )  
    {
      if( n <= t[i].p_n )
        return t[i].q_n;
    }
  /* Not in table - use an arbitrary high number. */
  return  n / 8 + 200;
}

static void
test_keys(gcry_core_context_t ctx, ELG_secret_key *sk, unsigned nbits )
{
  ELG_public_key pk;
  gcry_core_mpi_t test = gcry_core_mpi_new (ctx, 0 );
  gcry_core_mpi_t out1_a = gcry_core_mpi_new (ctx, nbits );
  gcry_core_mpi_t out1_b = gcry_core_mpi_new (ctx, nbits );
  gcry_core_mpi_t out2 = gcry_core_mpi_new (ctx, nbits );

  pk.p = sk->p;
  pk.g = sk->g;
  pk.y = sk->y;

  gcry_core_mpi_randomize( ctx, test, nbits, GCRY_WEAK_RANDOM );

  do_encrypt(ctx, out1_a, out1_b, test, &pk );
  decrypt(ctx, out2, out1_a, out1_b, sk );
  if( gcry_core_mpi_cmp(ctx, test, out2 ) )
    log_fatal(ctx, "ElGamal operation: encrypt, decrypt failed\n");

  sign(ctx, out1_a, out1_b, test, sk );
  if( !verify(ctx, out1_a, out1_b, test, &pk ) )
    log_fatal(ctx, "ElGamal operation: sign, verify failed\n");

  gcry_core_mpi_release (ctx, test );
  gcry_core_mpi_release (ctx, out1_a );
  gcry_core_mpi_release (ctx, out1_b );
  gcry_core_mpi_release (ctx, out2 );
}


/****************
 * Generate a random secret exponent k from prime p, so that k is
 * relatively prime to p-1.  With SMALL_K set, k will be selected for
 * better encryption performance - this must never be used signing!
 */
static gcry_core_mpi_t
gen_k(gcry_core_context_t ctx, gcry_core_mpi_t p, int small_k )
{
  gcry_core_mpi_t k = gcry_core_mpi_snew(ctx, 0 );
  gcry_core_mpi_t temp = gcry_core_mpi_new(ctx,
				      gcry_core_mpi_get_nbits(ctx, p) );
  gcry_core_mpi_t p_1 = gcry_core_mpi_copy(ctx, p);
  unsigned int orig_nbits = gcry_core_mpi_get_nbits(ctx, p);
  unsigned int nbits, nbytes;
  char *rndbuf = NULL;

  if (small_k)
    {
      /* Using a k much lesser than p is sufficient for encryption and
       * it greatly improves the encryption performance.  We use
       * Wiener's table and add a large safety margin. */
      nbits = wiener_map( orig_nbits ) * 3 / 2;
      if( nbits >= orig_nbits )
        BUG(ctx);
    }
  else
    nbits = orig_nbits;


  nbytes = (nbits+7)/8;
  if( GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx))
    log_debug(ctx, "choosing a random k ");
  gcry_core_mpi_sub_ui(ctx, p_1, p, 1);
  for(;;) 
    {
      if( !rndbuf || nbits < 32 ) 
        {
          gcry_core_free(ctx, rndbuf);
          rndbuf = gcry_core_random_bytes_secure(ctx,
						 nbytes, GCRY_STRONG_RANDOM );
        }
      else
        { 
          /* Change only some of the higher bits.  We could improve
             this by directly requesting more memory at the first call
             to get_random_bytes() and use this the here maybe it is
             easier to do this directly in random.c Anyway, it is
             highly inlikely that we will ever reach this code. */
          char *pp = gcry_core_random_bytes_secure(ctx,
						   4, GCRY_STRONG_RANDOM );
          memcpy( rndbuf, pp, 4 );
          gcry_core_free(ctx, pp);
	}
      gcry_core_mpi_set_buffer(ctx, k, rndbuf, nbytes, 0 );
        
      for(;;)
        {
          if( !(gcry_core_mpi_cmp(ctx, k, p_1 ) < 0) )  /* check: k < (p-1) */
            {
              if( GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx) )
                progress(ctx, '+');
              break; /* no  */
            }
          if( !(gcry_core_mpi_cmp_ui(ctx, k, 0 ) > 0) )  /* check: k > 0 */
            {
              if( GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx) )
                progress(ctx, '-');
              break; /* no */
            }
          if (gcry_core_mpi_gcd(ctx, temp, k, p_1 ))
            goto found;  /* okay, k is relative prime to (p-1) */
          gcry_core_mpi_add_ui(ctx, k, k, 1 );
          if( GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx) )
            progress(ctx, '.');
	}
    }
 found:
  gcry_core_free(ctx, rndbuf);
  if( GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx) )
    progress(ctx, '\n');
  gcry_core_mpi_release(ctx, p_1);
  gcry_core_mpi_release(ctx, temp);

  return k;
}

/****************
 * Generate a key pair with a key of size NBITS
 * Returns: 2 structures filles with all needed values
 *	    and an array with n-1 factors of (p-1)
 */
static void
generate (gcry_core_context_t ctx,
	  ELG_secret_key *sk, unsigned int nbits, gcry_core_mpi_t **ret_factors )
{
  gcry_core_mpi_t p;    /* the prime */
  gcry_core_mpi_t p_min1;
  gcry_core_mpi_t g;
  gcry_core_mpi_t x;    /* the secret exponent */
  gcry_core_mpi_t y;
  gcry_core_mpi_t temp;
  unsigned int qbits;
  unsigned int xbits;
  byte *rndbuf;

  p_min1 = gcry_core_mpi_new (ctx, nbits );
  temp   = gcry_core_mpi_new(ctx, nbits );
  qbits = wiener_map( nbits );
  if( qbits & 1 ) /* better have a even one */
    qbits++;
  g = gcry_core_mpi_new (ctx, 1); /* FIXME?  */
  p = gcry_core_prime_generate_elg (ctx, 0, nbits, qbits, g, ret_factors);
  gcry_core_mpi_sub_ui (ctx, p_min1, p, 1);


  /* Select a random number which has these properties:
   *	 0 < x < p-1
   * This must be a very good random number because this is the
   * secret part.  The prime is public and may be shared anyway,
   * so a random generator level of 1 is used for the prime.
   *
   * I don't see a reason to have a x of about the same size
   * as the p.  It should be sufficient to have one about the size
   * of q or the later used k plus a large safety margin. Decryption
   * will be much faster with such an x.
   */
  xbits = qbits * 3 / 2;
  if( xbits >= nbits )
    BUG(ctx);
  x = gcry_core_mpi_snew ( ctx, xbits );
  if( GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx) )
    log_debug(ctx, "choosing a random x of size %u", xbits );
  rndbuf = NULL;
  do 
    {
      if( GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx) )
        progress(ctx, '.');
      if( rndbuf )
        { /* Change only some of the higher bits */
          if( xbits < 16 ) /* should never happen ... */
            {
              gcry_core_free (ctx, rndbuf);
              rndbuf = gcry_core_random_bytes_secure(ctx,
						     (xbits+7)/8,
						     GCRY_VERY_STRONG_RANDOM );
            }
          else
            {
              char *r = gcry_core_random_bytes_secure(ctx, 2,
						      GCRY_VERY_STRONG_RANDOM );
              memcpy(rndbuf, r, 2 );
              gcry_core_free(ctx, r);
            }
	}
      else 
        {
          rndbuf = gcry_core_random_bytes_secure(ctx,
						 (xbits+7)/8,
						 GCRY_VERY_STRONG_RANDOM );
	}
      gcry_core_mpi_set_buffer(ctx, x, rndbuf, (xbits+7)/8, 0 );
      gcry_core_mpi_clear_highbit(ctx, x, xbits+1 );
    } 
  while( !( gcry_core_mpi_cmp_ui(ctx, x, 0 )>0
	    && gcry_core_mpi_cmp(ctx, x, p_min1 )<0 ) );
  gcry_core_free(ctx, rndbuf);

  y = gcry_core_mpi_new (ctx, nbits);
  gcry_core_mpi_powm(ctx, y, g, x, p );

  /* FIXME, moritz!!  */
  if( GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx) ) 
    {
      progress(ctx, '\n');
      _gcry_log_mpidump(ctx, "elg  p= ", p );
      _gcry_log_mpidump(ctx, "elg  g= ", g );
      _gcry_log_mpidump(ctx, "elg  y= ", y );
      _gcry_log_mpidump(ctx, "elg  x= ", x );
    }

  /* Copy the stuff to the key structures */
  sk->p = p;
  sk->g = g;
  sk->y = y;
  sk->x = x;

  /* Now we can test our keys (this should never fail!) */
  test_keys(ctx, sk, nbits - 64 );

  gcry_core_mpi_release (ctx, p_min1 );
  gcry_core_mpi_release (ctx, temp   );
}


/****************
 * Test whether the secret key is valid.
 * Returns: if this is a valid key.
 */
static int
check_secret_key(gcry_core_context_t ctx, ELG_secret_key *sk )
{
  int rc;
  gcry_core_mpi_t y = gcry_core_mpi_new(ctx,
				   gcry_core_mpi_get_nbits(ctx, sk->y) );

  gcry_core_mpi_powm(ctx, y, sk->g, sk->x, sk->p );
  rc = !gcry_core_mpi_cmp(ctx, y, sk->y );
  gcry_core_mpi_release(ctx, y );
  return rc;
}


static void
do_encrypt(gcry_core_context_t ctx,
	   gcry_core_mpi_t a, gcry_core_mpi_t b, gcry_core_mpi_t input, ELG_public_key *pkey )
{
  gcry_core_mpi_t k;

  /* Note: maybe we should change the interface, so that it
   * is possible to check that input is < p and return an
   * error code.
   */

  k = gen_k(ctx, pkey->p, 1 );
  gcry_core_mpi_powm(ctx, a, pkey->g, k, pkey->p );
  /* b = (y^k * input) mod p
   *	 = ((y^k mod p) * (input mod p)) mod p
   * and because input is < p
   *	 = ((y^k mod p) * input) mod p
   */
  gcry_core_mpi_powm(ctx, b, pkey->y, k, pkey->p );
  gcry_core_mpi_mulm(ctx, b, b, input, pkey->p );
#if 0
  if( GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx) )
    {
      _gcry_log_mpidump("elg encrypted y= ", pkey->y);
      _gcry_log_mpidump("elg encrypted p= ", pkey->p);
      _gcry_log_mpidump("elg encrypted k= ", k);
      _gcry_log_mpidump("elg encrypted M= ", input);
      _gcry_log_mpidump("elg encrypted a= ", a);
      _gcry_log_mpidump("elg encrypted b= ", b);
    }
#endif
  gcry_core_mpi_release(ctx, k);
}




static void
decrypt(gcry_core_context_t ctx,
	gcry_core_mpi_t output, gcry_core_mpi_t a, gcry_core_mpi_t b, ELG_secret_key *skey )
{
  gcry_core_mpi_t t1 = gcry_core_mpi_snew (ctx,
				      gcry_core_mpi_get_nbits(ctx, skey->p ) );

  /* output = b/(a^x) mod p */
  gcry_core_mpi_powm(ctx, t1, a, skey->x, skey->p );
  gcry_core_mpi_invm(ctx, t1, t1, skey->p );
  gcry_core_mpi_mulm(ctx, output, b, t1, skey->p );
#if 0
  if( GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx) ) 
    {
      _gcry_log_mpidump("elg decrypted x= ", skey->x);
      _gcry_log_mpidump("elg decrypted p= ", skey->p);
      _gcry_log_mpidump("elg decrypted a= ", a);
      _gcry_log_mpidump("elg decrypted b= ", b);
      _gcry_log_mpidump("elg decrypted M= ", output);
    }
#endif
  gcry_core_mpi_release(ctx, t1);
}


/****************
 * Make an Elgamal signature out of INPUT
 */

static void
sign(gcry_core_context_t ctx,
     gcry_core_mpi_t a, gcry_core_mpi_t b, gcry_core_mpi_t input, ELG_secret_key *skey )
{
    gcry_core_mpi_t k;
    gcry_core_mpi_t t   = gcry_core_mpi_new(ctx,
				       gcry_core_mpi_get_nbits(ctx, a) );
    gcry_core_mpi_t inv = gcry_core_mpi_new(ctx,
				       gcry_core_mpi_get_nbits(ctx, a) );
    gcry_core_mpi_t p_1 = gcry_core_mpi_copy(ctx, skey->p);

   /*
    * b = (t * inv) mod (p-1)
    * b = (t * inv(k,(p-1),(p-1)) mod (p-1)
    * b = (((M-x*a) mod (p-1)) * inv(k,(p-1),(p-1))) mod (p-1)
    *
    */
    gcry_core_mpi_sub_ui(ctx, p_1, p_1, 1);
    k = gen_k(ctx, skey->p, 0 /* no small K ! */ );
    gcry_core_mpi_powm(ctx, a, skey->g, k, skey->p );
    gcry_core_mpi_mul(ctx, t, skey->x, a );
    gcry_core_mpi_subm(ctx, t, input, t, p_1 );
    gcry_core_mpi_invm(ctx, inv, k, p_1 );
    gcry_core_mpi_mulm(ctx, b, t, inv, p_1 );

#if 0
    /* FIXME, why was this disabled?  */
    if( GCRY_CORE_DEBUGGING_ASYM_CIPHER (ctx) ) 
      {
	_gcry_log_mpidump("elg sign p= ", skey->p);
	_gcry_log_mpidump("elg sign g= ", skey->g);
	_gcry_log_mpidump("elg sign y= ", skey->y);
	_gcry_log_mpidump("elg sign x= ", skey->x);
	_gcry_log_mpidump("elg sign k= ", k);
	_gcry_log_mpidump("elg sign M= ", input);
	_gcry_log_mpidump("elg sign a= ", a);
	_gcry_log_mpidump("elg sign b= ", b);
      }
#endif
    
    gcry_core_mpi_release(ctx, k);
    gcry_core_mpi_release (ctx, t);
    gcry_core_mpi_release (ctx, inv);
    gcry_core_mpi_release (ctx, p_1);
}


/****************
 * Returns true if the signature composed of A and B is valid.
 */
static int
verify(gcry_core_context_t ctx,
       gcry_core_mpi_t a, gcry_core_mpi_t b, gcry_core_mpi_t input, ELG_public_key *pkey )
{
  int rc;
  gcry_core_mpi_t t1;
  gcry_core_mpi_t t2;
  gcry_core_mpi_t base[4];
  gcry_core_mpi_t ex[4];

  if( !(gcry_core_mpi_cmp_ui(ctx, a, 0 ) > 0
	&& gcry_core_mpi_cmp(ctx, a, pkey->p ) < 0) )
    return 0; /* assertion	0 < a < p  failed */
  /* FIXME: pseudo assertion?  why?  */

  t1 = gcry_core_mpi_new(ctx, gcry_core_mpi_get_nbits(ctx, a) );
  t2 = gcry_core_mpi_new(ctx, gcry_core_mpi_get_nbits(ctx, a) );

#if 0
  /* t1 = (y^a mod p) * (a^b mod p) mod p */
  gcry_mpi_powm( t1, pkey->y, a, pkey->p );
  gcry_mpi_powm( t2, a, b, pkey->p );
  mpi_mulm( t1, t1, t2, pkey->p );

  /* t2 = g ^ input mod p */
  gcry_mpi_powm( t2, pkey->g, input, pkey->p );

  rc = !mpi_cmp( t1, t2 );
#elif 0
  /* t1 = (y^a mod p) * (a^b mod p) mod p */
  base[0] = pkey->y; ex[0] = a;
  base[1] = a;       ex[1] = b;
  base[2] = NULL;    ex[2] = NULL;
  mpi_mulpowm( t1, base, ex, pkey->p );

  /* t2 = g ^ input mod p */
  gcry_mpi_powm( t2, pkey->g, input, pkey->p );

  rc = !mpi_cmp( t1, t2 );
#else
  /* t1 = g ^ - input * y ^ a * a ^ b  mod p */
  gcry_core_mpi_invm(ctx, t2, pkey->g, pkey->p );
  base[0] = t2     ; ex[0] = input;
  base[1] = pkey->y; ex[1] = a;
  base[2] = a;       ex[2] = b;
  base[3] = NULL;    ex[3] = NULL;
  gcry_core_mpi_mulpowm(ctx, t1, base, ex, pkey->p );
  rc = !gcry_core_mpi_cmp_ui(ctx, t1, 1 );

#endif

  gcry_core_mpi_release (ctx, t1);
  gcry_core_mpi_release (ctx, t2);
  return rc;
}

/*********************************************
 **************  interface  ******************
 *********************************************/

gcry_err_code_t
_gcry_elg_generate (gcry_core_context_t ctx,
		    unsigned int flags,
		    unsigned nbits, void *spec,
                    gcry_core_mpi_t *skey, gcry_core_mpi_t **retfactors)
{
  ELG_secret_key sk;

  generate (ctx, &sk, nbits, retfactors);
  skey[0] = sk.p;
  skey[1] = sk.g;
  skey[2] = sk.y;
  skey[3] = sk.x;
  
  return GPG_ERR_NO_ERROR;
}


gcry_err_code_t
_gcry_elg_check_secret_key (gcry_core_context_t ctx,
		    unsigned int flags,
			    gcry_core_mpi_t *skey)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  ELG_secret_key sk;

  if ((! skey[0]) || (! skey[1]) || (! skey[2]) || (! skey[3]))
    err = GPG_ERR_BAD_MPI;
  else
    {
      sk.p = skey[0];
      sk.g = skey[1];
      sk.y = skey[2];
      sk.x = skey[3];
      
      if (! check_secret_key (ctx, &sk))
	err = GPG_ERR_BAD_SECKEY;
    }

  return err;
}


gcry_err_code_t
_gcry_elg_encrypt (gcry_core_context_t ctx,
		    unsigned int flags,
		   gcry_core_mpi_t *resarr,
                   gcry_core_mpi_t data, gcry_core_mpi_t *pkey)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  ELG_public_key pk;

  if ((! data) || (! pkey[0]) || (! pkey[1]) || (! pkey[2]))
    err = GPG_ERR_BAD_MPI;
  else
    {
      pk.p = pkey[0];
      pk.g = pkey[1];
      pk.y = pkey[2];
      resarr[0] = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, pk.p));
      resarr[1] = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, pk.p));
      do_encrypt (ctx, resarr[0], resarr[1], data, &pk);
    }
  return err;
}


gcry_err_code_t
_gcry_elg_decrypt (gcry_core_context_t ctx,
		    unsigned int flags,
		   gcry_core_mpi_t *result,
                   gcry_core_mpi_t *data, gcry_core_mpi_t *skey)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  ELG_secret_key sk;

  if ((! data[0]) || (! data[1])
      || (! skey[0]) || (! skey[1]) || (! skey[2]) || (! skey[3]))
    err = GPG_ERR_BAD_MPI;
  else
    {
      sk.p = skey[0];
      sk.g = skey[1];
      sk.y = skey[2];
      sk.x = skey[3];
      *result = gcry_core_mpi_snew (ctx, gcry_core_mpi_get_nbits (ctx, sk.p));
      decrypt (ctx, *result, data[0], data[1], &sk);
    }
  return err;
}


gcry_err_code_t
_gcry_elg_sign (gcry_core_context_t ctx,
		    unsigned int flags,
		gcry_core_mpi_t *resarr, gcry_core_mpi_t data, gcry_core_mpi_t *skey)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  ELG_secret_key sk;

  if ((! data)
      || (! skey[0]) || (! skey[1]) || (! skey[2]) || (! skey[3]))
    err = GPG_ERR_BAD_MPI;
  else
    {
      sk.p = skey[0];
      sk.g = skey[1];
      sk.y = skey[2];
      sk.x = skey[3];
      resarr[0] = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, sk.p));
      resarr[1] = gcry_core_mpi_new (ctx, gcry_core_mpi_get_nbits (ctx, sk.p));
      sign (ctx, resarr[0], resarr[1], data, &sk);
    }
  
  return err;
}

gcry_err_code_t
_gcry_elg_verify (gcry_core_context_t ctx,
		    unsigned int flags,
		  gcry_core_mpi_t hash, gcry_core_mpi_t *data, gcry_core_mpi_t *pkey,
		  int (*cmp) (void *, gcry_core_mpi_t), void *opaquev)
{
  gcry_err_code_t err = GPG_ERR_NO_ERROR;
  ELG_public_key pk;

  if ((! data[0]) || (! data[1]) || (! hash)
      || (! pkey[0]) || (! pkey[1]) || (! pkey[2]))
    err = GPG_ERR_BAD_MPI;
  else
    {
      pk.p = pkey[0];
      pk.g = pkey[1];
      pk.y = pkey[2];
      if (! verify (ctx, data[0], data[1], hash, &pk))
	err = GPG_ERR_BAD_SIGNATURE;
    }

  return err;
}


unsigned int
_gcry_elg_get_nbits (gcry_core_context_t ctx,
		     unsigned int flags,
		     gcry_core_mpi_t *pkey)
{
  return gcry_core_mpi_get_nbits (ctx, pkey[0]);
}

gcry_error_t
_gcry_elg_keygrip (gcry_core_context_t ctx,
		     unsigned int flags,
		   gcry_core_mpi_t *pkey,
		   unsigned char *grip)
{
  gcry_core_md_spec_t algorithm;
  const char *elements;
  gcry_core_md_hd_t md;
  unsigned char *buffer;
  size_t buffer_n;
  unsigned char *hash;
  gcry_error_t err;
  unsigned int i;
  char buf[30];

  algorithm = gcry_core_digest_sha1;
  elements = gcry_core_ac_elg->elements_grip;
  assert (elements);

  buffer = NULL;
  buffer_n = 0;
  md = NULL;
  
  err = gcry_core_md_open (ctx, &md, algorithm, 0);
  if (err)
    goto out;

  for (i = 0; elements[i]; i++)
    {
      err = gcry_core_mpi_aprint (ctx, GCRYMPI_FMT_STD,
				  &buffer, &buffer_n, pkey[i]);
      if (err)
	break;

      sprintf (buf, "(1:%c%u:", elements[i], (unsigned int) buffer_n);
      gcry_core_md_write (ctx, md, buf, strlen (buf));
      gcry_core_md_write (ctx, md, buffer, buffer_n);
      gcry_core_md_write (ctx, md, ")", 1);

      gcry_core_free (ctx, buffer);
      buffer = NULL;
      buffer_n = 0;
    }
  if (err)
    goto out;

  hash = gcry_core_md_read (ctx, md, NULL);
  assert (hash);		/* FIXME?  */

  memcpy (grip, hash, 20);	/* FIXME, constant.  */

 out:

  gcry_core_md_close (ctx, md);
  gcry_core_free (ctx, buffer);

  return err;
}



static char *elg_names[] =
  {
    "elg",
    "openpgp-elg",
    "openpgp-elg-sig",
    NULL,
  };


static struct gcry_core_ac_spec gcry_core_ac_elg_struct =
  {
    "ELG", elg_names,
    "pgy", "pgyx", "ab", "rs", "pgy",
    GCRY_AC_KEY_USAGE_SIGN | GCRY_AC_KEY_USAGE_ENCR, 20,
    _gcry_elg_generate,
    _gcry_elg_check_secret_key,
    _gcry_elg_encrypt,
    _gcry_elg_decrypt,
    _gcry_elg_sign,
    _gcry_elg_verify,
    _gcry_elg_get_nbits,
    _gcry_elg_keygrip
  };

gcry_core_ac_spec_t gcry_core_ac_elg = &gcry_core_ac_elg_struct;
