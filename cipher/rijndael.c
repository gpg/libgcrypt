/* Rijndael (AES) for GnuPG
 * Copyright (C) 2000, 2001, 2002, 2003, 2007,
 *               2008 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 *******************************************************************
 * The code here is based on the optimized implementation taken from
 * http://www.esat.kuleuven.ac.be/~rijmen/rijndael/ on Oct 2, 2000,
 * which carries this notice:
 *------------------------------------------
 * rijndael-alg-fst.c   v2.3   April '2000
 *
 * Optimised ANSI C code
 *
 * authors: v1.0: Antoon Bosselaers
 *          v2.0: Vincent Rijmen
 *          v2.3: Paulo Barreto
 *
 * This code is placed in the public domain.
 *------------------------------------------
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* for memcmp() */

#include "types.h"  /* for byte and u32 typedefs */
#include "g10lib.h"
#include "cipher.h"

#define MAXKC			(256/32)
#define MAXROUNDS		14
#define BLOCKSIZE               (128/8)


/* USE_PADLOCK indicates whether to compile the padlock specific
   code.  */
#undef USE_PADLOCK
#ifdef ENABLE_PADLOCK_SUPPORT
# if defined (__i386__) && SIZEOF_UNSIGNED_LONG == 4 && defined (__GNUC__)
# define USE_PADLOCK
# endif
#endif /*ENABLE_PADLOCK_SUPPORT*/

static const char *selftest(void);

typedef struct 
{
  int   ROUNDS;             /* Key-length-dependent number of rounds.  */
  int decryption_prepared;  /* The decryption key schedule is available.  */
#ifdef USE_PADLOCK
  int use_padlock;          /* Padlock shall be used.  */
  /* The key as passed to the padlock engine.  */
  unsigned char padlock_key[16] __attribute__ ((aligned (16)));
#endif
  union
  {
    PROPERLY_ALIGNED_TYPE dummy;
    byte keyschedule[MAXROUNDS+1][4][4];
  } u1;
  union
  {
    PROPERLY_ALIGNED_TYPE dummy;
    byte keyschedule[MAXROUNDS+1][4][4];	
  } u2;
} RIJNDAEL_context;

#define keySched  u1.keyschedule
#define keySched2 u2.keyschedule

/* All the numbers.  */
#include "rijndael-tables.h"


/* Perform the key setup.  */  
static gcry_err_code_t
do_setkey (RIJNDAEL_context *ctx, const byte *key, const unsigned keylen)
{
  static int initialized = 0;
  static const char *selftest_failed=0;
  int ROUNDS;
  byte k[MAXKC][4];
  int i,j, r, t, rconpointer = 0;
  byte tk[MAXKC][4];
  int KC;
  
  if (!initialized)
    {
      initialized = 1;
      selftest_failed = selftest ();
      if( selftest_failed )
        log_error ("%s\n", selftest_failed );
    }
  if( selftest_failed )
    return GPG_ERR_SELFTEST_FAILED;

  ctx->decryption_prepared = 0;
#ifdef USE_PADLOCK
  ctx->use_padlock = 0;
#endif

  if( keylen == 128/8 )
    {
      ROUNDS = 10;
      KC = 4;
#ifdef USE_PADLOCK
      if ((_gcry_get_hw_features () & HWF_PADLOCK_AES))
        {
          ctx->use_padlock = 1;
          memcpy (ctx->padlock_key, key, keylen);
        }
#endif
    }
  else if ( keylen == 192/8 )
    {
      ROUNDS = 12;
      KC = 6;
    }
  else if ( keylen == 256/8 )
    {
      ROUNDS = 14;
      KC = 8;
    }
  else
    return GPG_ERR_INV_KEYLEN;

  ctx->ROUNDS = ROUNDS;

#ifdef USE_PADLOCK
  if (ctx->use_padlock)
    {
      /* Nothing to do as we support only hardware key generation for
         now.  */
    }
  else
#endif /*USE_PADLOCK*/
    {
#define W (ctx->keySched)
      for (i = 0; i < keylen; i++) 
        {
          k[i >> 2][i & 3] = key[i]; 
        }
      
      for (j = KC-1; j >= 0; j--) 
        {
          *((u32*)tk[j]) = *((u32*)k[j]);
        }
      r = 0;
      t = 0;
      /* Copy values into round key array.  */
      for (j = 0; (j < KC) && (r < ROUNDS + 1); )
        {
          for (; (j < KC) && (t < 4); j++, t++)
            {
              *((u32*)W[r][t]) = *((u32*)tk[j]);
            }
          if (t == 4)
            {
              r++;
              t = 0;
            }
        }
      
      while (r < ROUNDS + 1)
        {
          /* While not enough round key material calculated calculate
             new values.  */
          tk[0][0] ^= S[tk[KC-1][1]];
          tk[0][1] ^= S[tk[KC-1][2]];
          tk[0][2] ^= S[tk[KC-1][3]];
          tk[0][3] ^= S[tk[KC-1][0]];
          tk[0][0] ^= rcon[rconpointer++];
          
          if (KC != 8)
            {
              for (j = 1; j < KC; j++) 
                {
                  *((u32*)tk[j]) ^= *((u32*)tk[j-1]);
                }
            } 
          else 
            {
              for (j = 1; j < KC/2; j++)
                {
                  *((u32*)tk[j]) ^= *((u32*)tk[j-1]);
                }
              tk[KC/2][0] ^= S[tk[KC/2 - 1][0]];
              tk[KC/2][1] ^= S[tk[KC/2 - 1][1]];
              tk[KC/2][2] ^= S[tk[KC/2 - 1][2]];
              tk[KC/2][3] ^= S[tk[KC/2 - 1][3]];
              for (j = KC/2 + 1; j < KC; j++)
                {
                  *((u32*)tk[j]) ^= *((u32*)tk[j-1]);
                }
            }
          
          /* Copy values into round key array.  */
          for (j = 0; (j < KC) && (r < ROUNDS + 1); )
            {
              for (; (j < KC) && (t < 4); j++, t++)
                {
                  *((u32*)W[r][t]) = *((u32*)tk[j]);
                }
              if (t == 4)
                {
                  r++;
                  t = 0;
                }
            }
        }		
#undef W    
    }

  return 0;
}


static gcry_err_code_t
rijndael_setkey (void *context, const byte *key, const unsigned keylen)
{
  RIJNDAEL_context *ctx = context;

  int rc = do_setkey (ctx, key, keylen);
  _gcry_burn_stack ( 100 + 16*sizeof(int));
  return rc;
}


/* Make a decryption key from an encryption key. */
static void
prepare_decryption( RIJNDAEL_context *ctx )
{
  int r;
  byte *w;

  for (r=0; r < MAXROUNDS+1; r++ )
    {
      *((u32*)ctx->keySched2[r][0]) = *((u32*)ctx->keySched[r][0]);
      *((u32*)ctx->keySched2[r][1]) = *((u32*)ctx->keySched[r][1]);
      *((u32*)ctx->keySched2[r][2]) = *((u32*)ctx->keySched[r][2]);
      *((u32*)ctx->keySched2[r][3]) = *((u32*)ctx->keySched[r][3]);
    }
#define W (ctx->keySched2)
  for (r = 1; r < ctx->ROUNDS; r++)
    {
      w = W[r][0];
      *((u32*)w) = *((u32*)U1[w[0]]) ^ *((u32*)U2[w[1]])
        ^ *((u32*)U3[w[2]]) ^ *((u32*)U4[w[3]]);
       
      w = W[r][1];
      *((u32*)w) = *((u32*)U1[w[0]]) ^ *((u32*)U2[w[1]])
        ^ *((u32*)U3[w[2]]) ^ *((u32*)U4[w[3]]);
        
      w = W[r][2];
      *((u32*)w) = *((u32*)U1[w[0]]) ^ *((u32*)U2[w[1]])
        ^ *((u32*)U3[w[2]]) ^ *((u32*)U4[w[3]]);
        
      w = W[r][3];
      *((u32*)w) = *((u32*)U1[w[0]]) ^ *((u32*)U2[w[1]])
        ^ *((u32*)U3[w[2]]) ^ *((u32*)U4[w[3]]);
    }
#undef W
}	



/* Encrypt one block.  A and B need to be aligned on a 4 byte
   boundary.  A and B may be the same. */
static void
do_encrypt_aligned (const RIJNDAEL_context *ctx, 
                    unsigned char *b, const unsigned char *a)
{
#define rk (ctx->keySched)
  int ROUNDS = ctx->ROUNDS;
  int r;
  union
  {
    u32  tempu32[4];  /* Force correct alignment. */
    byte temp[4][4];
  } u;

  *((u32*)u.temp[0]) = *((u32*)(a   )) ^ *((u32*)rk[0][0]);
  *((u32*)u.temp[1]) = *((u32*)(a+ 4)) ^ *((u32*)rk[0][1]);
  *((u32*)u.temp[2]) = *((u32*)(a+ 8)) ^ *((u32*)rk[0][2]);
  *((u32*)u.temp[3]) = *((u32*)(a+12)) ^ *((u32*)rk[0][3]);
  *((u32*)(b    ))   = (*((u32*)T1[u.temp[0][0]])
                        ^ *((u32*)T2[u.temp[1][1]])
                        ^ *((u32*)T3[u.temp[2][2]]) 
                        ^ *((u32*)T4[u.temp[3][3]]));
  *((u32*)(b + 4))   = (*((u32*)T1[u.temp[1][0]])
                        ^ *((u32*)T2[u.temp[2][1]])
                        ^ *((u32*)T3[u.temp[3][2]]) 
                        ^ *((u32*)T4[u.temp[0][3]]));
  *((u32*)(b + 8))   = (*((u32*)T1[u.temp[2][0]])
                        ^ *((u32*)T2[u.temp[3][1]])
                        ^ *((u32*)T3[u.temp[0][2]]) 
                        ^ *((u32*)T4[u.temp[1][3]]));
  *((u32*)(b +12))   = (*((u32*)T1[u.temp[3][0]])
                        ^ *((u32*)T2[u.temp[0][1]])
                        ^ *((u32*)T3[u.temp[1][2]]) 
                        ^ *((u32*)T4[u.temp[2][3]]));

  for (r = 1; r < ROUNDS-1; r++)
    {
      *((u32*)u.temp[0]) = *((u32*)(b   )) ^ *((u32*)rk[r][0]);
      *((u32*)u.temp[1]) = *((u32*)(b+ 4)) ^ *((u32*)rk[r][1]);
      *((u32*)u.temp[2]) = *((u32*)(b+ 8)) ^ *((u32*)rk[r][2]);
      *((u32*)u.temp[3]) = *((u32*)(b+12)) ^ *((u32*)rk[r][3]);

      *((u32*)(b    ))   = (*((u32*)T1[u.temp[0][0]])
                            ^ *((u32*)T2[u.temp[1][1]])
                            ^ *((u32*)T3[u.temp[2][2]]) 
                            ^ *((u32*)T4[u.temp[3][3]]));
      *((u32*)(b + 4))   = (*((u32*)T1[u.temp[1][0]])
                            ^ *((u32*)T2[u.temp[2][1]])
                            ^ *((u32*)T3[u.temp[3][2]]) 
                            ^ *((u32*)T4[u.temp[0][3]]));
      *((u32*)(b + 8))   = (*((u32*)T1[u.temp[2][0]])
                            ^ *((u32*)T2[u.temp[3][1]])
                            ^ *((u32*)T3[u.temp[0][2]]) 
                            ^ *((u32*)T4[u.temp[1][3]]));
      *((u32*)(b +12))   = (*((u32*)T1[u.temp[3][0]])
                            ^ *((u32*)T2[u.temp[0][1]])
                            ^ *((u32*)T3[u.temp[1][2]]) 
                            ^ *((u32*)T4[u.temp[2][3]]));
    }

  /* Last round is special. */   
  *((u32*)u.temp[0]) = *((u32*)(b   )) ^ *((u32*)rk[ROUNDS-1][0]);
  *((u32*)u.temp[1]) = *((u32*)(b+ 4)) ^ *((u32*)rk[ROUNDS-1][1]);
  *((u32*)u.temp[2]) = *((u32*)(b+ 8)) ^ *((u32*)rk[ROUNDS-1][2]);
  *((u32*)u.temp[3]) = *((u32*)(b+12)) ^ *((u32*)rk[ROUNDS-1][3]);
  b[ 0] = T1[u.temp[0][0]][1];
  b[ 1] = T1[u.temp[1][1]][1];
  b[ 2] = T1[u.temp[2][2]][1];
  b[ 3] = T1[u.temp[3][3]][1];
  b[ 4] = T1[u.temp[1][0]][1];
  b[ 5] = T1[u.temp[2][1]][1];
  b[ 6] = T1[u.temp[3][2]][1];
  b[ 7] = T1[u.temp[0][3]][1];
  b[ 8] = T1[u.temp[2][0]][1];
  b[ 9] = T1[u.temp[3][1]][1];
  b[10] = T1[u.temp[0][2]][1];
  b[11] = T1[u.temp[1][3]][1];
  b[12] = T1[u.temp[3][0]][1];
  b[13] = T1[u.temp[0][1]][1];
  b[14] = T1[u.temp[1][2]][1];
  b[15] = T1[u.temp[2][3]][1];
  *((u32*)(b   )) ^= *((u32*)rk[ROUNDS][0]);
  *((u32*)(b+ 4)) ^= *((u32*)rk[ROUNDS][1]);
  *((u32*)(b+ 8)) ^= *((u32*)rk[ROUNDS][2]);
  *((u32*)(b+12)) ^= *((u32*)rk[ROUNDS][3]);
#undef rk
}


static void
do_encrypt (const RIJNDAEL_context *ctx,
            unsigned char *bx, const unsigned char *ax)
{
  /* BX and AX are not necessary correctly aligned.  Thus we need to
     copy them here. */
  union
  {
    u32  dummy[4]; 
    byte a[16];
  } a;
  union
  {
    u32  dummy[4]; 
    byte b[16];
  } b;

  memcpy (a.a, ax, 16);
  do_encrypt_aligned (ctx, b.b, a.a);
  memcpy (bx, b.b, 16);
}


/* Encrypt or decrypt one block using the padlock engine.  A and B may
   be the same. */
#ifdef USE_PADLOCK
static void
do_padlock (const RIJNDAEL_context *ctx, int decrypt_flag,
            unsigned char *bx, const unsigned char *ax)
{
  /* BX and AX are not necessary correctly aligned.  Thus we need to
     copy them here. */
  unsigned char a[16] __attribute__ ((aligned (16)));
  unsigned char b[16] __attribute__ ((aligned (16)));
  unsigned int cword[4] __attribute__ ((aligned (16)));

  /* The control word fields are:
      127:12   11:10 9     8     7     6     5     4     3:0
      RESERVED KSIZE CRYPT INTER KEYGN CIPHR ALIGN DGEST ROUND  */
  cword[0] = (ctx->ROUNDS & 15);  /* (The mask is just a safeguard.)  */
  cword[1] = 0;
  cword[2] = 0;
  cword[3] = 0;
  if (decrypt_flag)
    cword[0] |= 0x00000200;

  memcpy (a, ax, 16);
   
  asm volatile 
    ("pushfl\n\t"          /* Force key reload.  */            
     "popfl\n\t"
     "xchg %3, %%ebx\n\t"  /* Load key.  */
     "movl $1, %%ecx\n\t"  /* Init counter for just one block.  */
     ".byte 0xf3, 0x0f, 0xa7, 0xc8\n\t" /* REP XSTORE ECB. */
     "xchg %3, %%ebx\n"    /* Restore GOT register.  */
     : /* No output */
     : "S" (a), "D" (b), "d" (cword), "r" (ctx->padlock_key)
     : "%ecx", "cc", "memory"
     );

  memcpy (bx, b, 16);

}
#endif /*USE_PADLOCK*/


static void
rijndael_encrypt (void *context, byte *b, const byte *a)
{
  RIJNDAEL_context *ctx = context;

#ifdef USE_PADLOCK
  if (ctx->use_padlock)
    {
      do_padlock (ctx, 0, b, a);
      _gcry_burn_stack (48 + 15 /* possible padding for alignment */);
    }
  else
#endif /*USE_PADLOCK*/
    {
      do_encrypt (ctx, b, a);
      _gcry_burn_stack (48 + 2*sizeof(int));
    }
}


/* Bulk encryption of complete blocks in CFB mode.  Caller needs to
   make sure that IV is aligned on an unsigned long boundary.  This
   function is only intended for the bulk encryption feature of
   cipher.c. */
void
_gcry_aes_cfb_enc (void *context, unsigned char *iv, 
                   void *outbuf_arg, const void *inbuf_arg,
                   unsigned int nblocks)
{
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  unsigned char *ivp;
  int i;

#ifdef USE_PADLOCK
  if (ctx->use_padlock)
    {
      /* Fixme: Let Padlock do the CFBing.  */
      for ( ;nblocks; nblocks-- )
        {
          /* Encrypt the IV. */
          do_padlock (ctx, 0, iv, iv);
          /* XOR the input with the IV and store input into IV.  */
          for (ivp=iv,i=0; i < BLOCKSIZE; i++ )
            *outbuf++ = (*ivp++ ^= *inbuf++);
        }
    }
  else
#endif /* USE_PADLOCK*/
    {
      for ( ;nblocks; nblocks-- )
        {
          /* Encrypt the IV. */
          do_encrypt_aligned (ctx, iv, iv);
          /* XOR the input with the IV and store input into IV.  */
          for (ivp=iv,i=0; i < BLOCKSIZE; i++ )
            *outbuf++ = (*ivp++ ^= *inbuf++);
        }
    }

  _gcry_burn_stack (48 + 2*sizeof(int));
}


/* Bulk encryption of complete blocks in CBC mode.  Caller needs to
   make sure that IV is aligned on an unsigned long boundary.  This
   function is only intended for the bulk encryption feature of
   cipher.c. */
void
_gcry_aes_cbc_enc (void *context, unsigned char *iv, 
                   void *outbuf_arg, const void *inbuf_arg,
                   unsigned int nblocks, int cbc_mac)
{
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  unsigned char *ivp;
  int i;

  for ( ;nblocks; nblocks-- )
    {
      for (ivp=iv, i=0; i < BLOCKSIZE; i++ )
        outbuf[i] = inbuf[i] ^ *ivp++;

#ifdef USE_PADLOCK
      if (ctx->use_padlock)
        do_padlock (ctx, 0, outbuf, outbuf);
      else
#endif /*USE_PADLOCK*/
        do_encrypt (ctx, outbuf, outbuf );

      memcpy (iv, outbuf, BLOCKSIZE);
      inbuf += BLOCKSIZE;
      if (!cbc_mac)
        outbuf += BLOCKSIZE;
    }

  _gcry_burn_stack (48 + 2*sizeof(int));
}



/* Decrypt one block.  A and B need to be aligned on a 4 byte boundary
   and the decryption must have been prepared.  A and B may be the
   same. */
static void
do_decrypt_aligned (RIJNDAEL_context *ctx, 
                    unsigned char *b, const unsigned char *a)
{
#define rk  (ctx->keySched2)
  int ROUNDS = ctx->ROUNDS; 
  int r;
  union 
  {
    u32  tempu32[4];  /* Force correct alignment. */
    byte temp[4][4];
  } u;


  *((u32*)u.temp[0]) = *((u32*)(a   )) ^ *((u32*)rk[ROUNDS][0]);
  *((u32*)u.temp[1]) = *((u32*)(a+ 4)) ^ *((u32*)rk[ROUNDS][1]);
  *((u32*)u.temp[2]) = *((u32*)(a+ 8)) ^ *((u32*)rk[ROUNDS][2]);
  *((u32*)u.temp[3]) = *((u32*)(a+12)) ^ *((u32*)rk[ROUNDS][3]);
  
  *((u32*)(b   ))    = (*((u32*)T5[u.temp[0][0]])
                        ^ *((u32*)T6[u.temp[3][1]])
                        ^ *((u32*)T7[u.temp[2][2]]) 
                        ^ *((u32*)T8[u.temp[1][3]]));
  *((u32*)(b+ 4))    = (*((u32*)T5[u.temp[1][0]])
                        ^ *((u32*)T6[u.temp[0][1]])
                        ^ *((u32*)T7[u.temp[3][2]]) 
                        ^ *((u32*)T8[u.temp[2][3]]));
  *((u32*)(b+ 8))    = (*((u32*)T5[u.temp[2][0]])
                        ^ *((u32*)T6[u.temp[1][1]])
                        ^ *((u32*)T7[u.temp[0][2]]) 
                        ^ *((u32*)T8[u.temp[3][3]]));
  *((u32*)(b+12))    = (*((u32*)T5[u.temp[3][0]])
                        ^ *((u32*)T6[u.temp[2][1]])
                        ^ *((u32*)T7[u.temp[1][2]]) 
                        ^ *((u32*)T8[u.temp[0][3]]));

  for (r = ROUNDS-1; r > 1; r--)
    {
      *((u32*)u.temp[0]) = *((u32*)(b   )) ^ *((u32*)rk[r][0]);
      *((u32*)u.temp[1]) = *((u32*)(b+ 4)) ^ *((u32*)rk[r][1]);
      *((u32*)u.temp[2]) = *((u32*)(b+ 8)) ^ *((u32*)rk[r][2]);
      *((u32*)u.temp[3]) = *((u32*)(b+12)) ^ *((u32*)rk[r][3]);
      *((u32*)(b   ))    = (*((u32*)T5[u.temp[0][0]])
                            ^ *((u32*)T6[u.temp[3][1]])
                            ^ *((u32*)T7[u.temp[2][2]]) 
                            ^ *((u32*)T8[u.temp[1][3]]));
      *((u32*)(b+ 4))    = (*((u32*)T5[u.temp[1][0]])
                            ^ *((u32*)T6[u.temp[0][1]])
                            ^ *((u32*)T7[u.temp[3][2]]) 
                            ^ *((u32*)T8[u.temp[2][3]]));
      *((u32*)(b+ 8))    = (*((u32*)T5[u.temp[2][0]])
                            ^ *((u32*)T6[u.temp[1][1]])
                            ^ *((u32*)T7[u.temp[0][2]]) 
                            ^ *((u32*)T8[u.temp[3][3]]));
      *((u32*)(b+12))    = (*((u32*)T5[u.temp[3][0]])
                            ^ *((u32*)T6[u.temp[2][1]])
                            ^ *((u32*)T7[u.temp[1][2]]) 
                            ^ *((u32*)T8[u.temp[0][3]]));
    }

  /* Last round is special. */   
  *((u32*)u.temp[0]) = *((u32*)(b   )) ^ *((u32*)rk[1][0]);
  *((u32*)u.temp[1]) = *((u32*)(b+ 4)) ^ *((u32*)rk[1][1]);
  *((u32*)u.temp[2]) = *((u32*)(b+ 8)) ^ *((u32*)rk[1][2]);
  *((u32*)u.temp[3]) = *((u32*)(b+12)) ^ *((u32*)rk[1][3]);
  b[ 0] = S5[u.temp[0][0]];
  b[ 1] = S5[u.temp[3][1]];
  b[ 2] = S5[u.temp[2][2]];
  b[ 3] = S5[u.temp[1][3]];
  b[ 4] = S5[u.temp[1][0]];
  b[ 5] = S5[u.temp[0][1]];
  b[ 6] = S5[u.temp[3][2]];
  b[ 7] = S5[u.temp[2][3]];
  b[ 8] = S5[u.temp[2][0]];
  b[ 9] = S5[u.temp[1][1]];
  b[10] = S5[u.temp[0][2]];
  b[11] = S5[u.temp[3][3]];
  b[12] = S5[u.temp[3][0]];
  b[13] = S5[u.temp[2][1]];
  b[14] = S5[u.temp[1][2]];
  b[15] = S5[u.temp[0][3]];
  *((u32*)(b   )) ^= *((u32*)rk[0][0]);
  *((u32*)(b+ 4)) ^= *((u32*)rk[0][1]);
  *((u32*)(b+ 8)) ^= *((u32*)rk[0][2]);
  *((u32*)(b+12)) ^= *((u32*)rk[0][3]);
#undef rk
}


/* Decrypt one block.  AX and BX may be the same. */
static void
do_decrypt (RIJNDAEL_context *ctx, byte *bx, const byte *ax)
{
  /* BX and AX are not necessary correctly aligned.  Thus we need to
     copy them here. */
  union
  {
    u32  dummy[4]; 
    byte a[16];
  } a;
  union
  {
    u32  dummy[4]; 
    byte b[16];
  } b;

  if ( !ctx->decryption_prepared )
    {
      prepare_decryption ( ctx );
      _gcry_burn_stack (64);
      ctx->decryption_prepared = 1;
    }

  memcpy (a.a, ax, 16);
  do_decrypt_aligned (ctx, b.b, a.a);
  memcpy (bx, b.b, 16);
#undef rk
}
    



static void
rijndael_decrypt (void *context, byte *b, const byte *a)
{
  RIJNDAEL_context *ctx = context;

#ifdef USE_PADLOCK
  if (ctx->use_padlock)
    {
      do_padlock (ctx, 1, b, a);
      _gcry_burn_stack (48 + 2*sizeof(int) /* FIXME */);
    }
  else
#endif /*USE_PADLOCK*/
    {
      do_decrypt (ctx, b, a);
      _gcry_burn_stack (48+2*sizeof(int));
    }
}


/* Bulk decryption of complete blocks in CFB mode.  Caller needs to
   make sure that IV is aligned on an unisgned lonhg boundary.  This
   function is only intended for the bulk encryption feature of
   cipher.c. */
void
_gcry_aes_cfb_dec (void *context, unsigned char *iv, 
                   void *outbuf_arg, const void *inbuf_arg,
                   unsigned int nblocks)
{
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  unsigned char *ivp;
  unsigned char temp;
  int i;

#ifdef USE_PADLOCK
  if (ctx->use_padlock)
    {
      /* Fixme:  Let Padlock do the CFBing.  */
      for ( ;nblocks; nblocks-- )
        {
          do_padlock (ctx, 0, iv, iv);
          for (ivp=iv,i=0; i < BLOCKSIZE; i++ )
            {
              temp = *inbuf++;
              *outbuf++ = *ivp ^ temp;
              *ivp++ = temp;
            }
        }
    }
  else
#endif /*USE_PADLOCK*/
    {
      for ( ;nblocks; nblocks-- )
        {
          do_encrypt_aligned (ctx, iv, iv);
          for (ivp=iv,i=0; i < BLOCKSIZE; i++ )
            {
              temp = *inbuf++;
              *outbuf++ = *ivp ^ temp;
              *ivp++ = temp;
            }
        }
    }

  _gcry_burn_stack (48 + 2*sizeof(int));
}


/* Bulk decryption of complete blocks in CBC mode.  Caller needs to
   make sure that IV is aligned on an unsigned long boundary.  This
   function is only intended for the bulk encryption feature of
   cipher.c. */
void
_gcry_aes_cbc_dec (void *context, unsigned char *iv, 
                   void *outbuf_arg, const void *inbuf_arg,
                   unsigned int nblocks)
{
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  unsigned char *ivp;
  int i;
  unsigned char savebuf[BLOCKSIZE];

  for ( ;nblocks; nblocks-- )
    {
      /* We need to save INBUF away because it may be identical to
         OUTBUF.  */
      memcpy (savebuf, inbuf, BLOCKSIZE);

#ifdef USE_PADLOCK
      if (ctx->use_padlock)
        do_padlock (ctx, 1, outbuf, inbuf);
      else
#endif /*USE_PADLOCK*/
        do_decrypt (ctx, outbuf, inbuf);

      for (ivp=iv, i=0; i < BLOCKSIZE; i++ )
        outbuf[i] ^= *ivp++;
      memcpy (iv, savebuf, BLOCKSIZE);
      inbuf += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

  _gcry_burn_stack (48 + 2*sizeof(int) + BLOCKSIZE + 4*sizeof (char*));
}




/* Test a single encryption and decryption with each key size. */
static const char*
selftest (void)
{
  RIJNDAEL_context ctx;
  byte scratch[16];	   

  /* The test vectors are from the AES supplied ones; more or less 
   * randomly taken from ecb_tbl.txt (I=42,81,14)
   */
  static byte plaintext[16] = {
    0x01,0x4B,0xAF,0x22,0x78,0xA6,0x9D,0x33,
    0x1D,0x51,0x80,0x10,0x36,0x43,0xE9,0x9A
  };
  static byte key[16] = {
    0xE8,0xE9,0xEA,0xEB,0xED,0xEE,0xEF,0xF0,
    0xF2,0xF3,0xF4,0xF5,0xF7,0xF8,0xF9,0xFA
  };
  static const byte ciphertext[16] = {
    0x67,0x43,0xC3,0xD1,0x51,0x9A,0xB4,0xF2,
    0xCD,0x9A,0x78,0xAB,0x09,0xA5,0x11,0xBD
  };

  static byte plaintext_192[16] = {
    0x76,0x77,0x74,0x75,0xF1,0xF2,0xF3,0xF4,
    0xF8,0xF9,0xE6,0xE7,0x77,0x70,0x71,0x72
  };
  static byte key_192[24] = {
    0x04,0x05,0x06,0x07,0x09,0x0A,0x0B,0x0C,
    0x0E,0x0F,0x10,0x11,0x13,0x14,0x15,0x16,
    0x18,0x19,0x1A,0x1B,0x1D,0x1E,0x1F,0x20
  };
  static const byte ciphertext_192[16] = {
    0x5D,0x1E,0xF2,0x0D,0xCE,0xD6,0xBC,0xBC,
    0x12,0x13,0x1A,0xC7,0xC5,0x47,0x88,0xAA
  };
    
  static byte plaintext_256[16] = {
    0x06,0x9A,0x00,0x7F,0xC7,0x6A,0x45,0x9F,
    0x98,0xBA,0xF9,0x17,0xFE,0xDF,0x95,0x21
  };
  static byte key_256[32] = {
    0x08,0x09,0x0A,0x0B,0x0D,0x0E,0x0F,0x10,
    0x12,0x13,0x14,0x15,0x17,0x18,0x19,0x1A,
    0x1C,0x1D,0x1E,0x1F,0x21,0x22,0x23,0x24,
    0x26,0x27,0x28,0x29,0x2B,0x2C,0x2D,0x2E
  };
  static const byte ciphertext_256[16] = {
    0x08,0x0E,0x95,0x17,0xEB,0x16,0x77,0x71,
    0x9A,0xCF,0x72,0x80,0x86,0x04,0x0A,0xE3
  };

  rijndael_setkey (&ctx, key, sizeof(key));
  rijndael_encrypt (&ctx, scratch, plaintext);
  if (memcmp (scratch, ciphertext, sizeof (ciphertext)))
    return "Rijndael-128 test encryption failed.";
  rijndael_decrypt (&ctx, scratch, scratch);
  if (memcmp (scratch, plaintext, sizeof (plaintext)))
    return "Rijndael-128 test decryption failed.";

  rijndael_setkey (&ctx, key_192, sizeof(key_192));
  rijndael_encrypt (&ctx, scratch, plaintext_192);
  if (memcmp (scratch, ciphertext_192, sizeof (ciphertext_192)))
    return "Rijndael-192 test encryption failed.";
  rijndael_decrypt (&ctx, scratch, scratch);
  if (memcmp (scratch, plaintext_192, sizeof (plaintext_192)))
    return "Rijndael-192 test decryption failed.";
    
  rijndael_setkey (&ctx, key_256, sizeof(key_256));
  rijndael_encrypt (&ctx, scratch, plaintext_256);
  if (memcmp (scratch, ciphertext_256, sizeof (ciphertext_256)))
    return "Rijndael-256 test encryption failed.";
  rijndael_decrypt (&ctx, scratch, scratch);
  if (memcmp (scratch, plaintext_256, sizeof (plaintext_256)))
    return "Rijndael-256 test decryption failed.";
    
  return NULL;
}



static const char *rijndael_names[] =
  {
    "RIJNDAEL",
    NULL
  };

static gcry_cipher_oid_spec_t rijndael_oids[] =
  {
    { "2.16.840.1.101.3.4.1.1", GCRY_CIPHER_MODE_ECB },
    { "2.16.840.1.101.3.4.1.2", GCRY_CIPHER_MODE_CBC },
    { "2.16.840.1.101.3.4.1.3", GCRY_CIPHER_MODE_OFB },
    { "2.16.840.1.101.3.4.1.4", GCRY_CIPHER_MODE_CFB },
    { NULL }
  };

gcry_cipher_spec_t _gcry_cipher_spec_aes =
  {
    "AES", rijndael_names, rijndael_oids, 16, 128, sizeof (RIJNDAEL_context),
    rijndael_setkey, rijndael_encrypt, rijndael_decrypt
  };

static const char *rijndael192_names[] =
  {
    "RIJNDAEL192",
    NULL
  };

static gcry_cipher_oid_spec_t rijndael192_oids[] =
  {
    { "2.16.840.1.101.3.4.1.21", GCRY_CIPHER_MODE_ECB },
    { "2.16.840.1.101.3.4.1.22", GCRY_CIPHER_MODE_CBC },
    { "2.16.840.1.101.3.4.1.23", GCRY_CIPHER_MODE_OFB },
    { "2.16.840.1.101.3.4.1.24", GCRY_CIPHER_MODE_CFB },
    { NULL }
  };

gcry_cipher_spec_t _gcry_cipher_spec_aes192 =
  {
    "AES192", rijndael192_names, rijndael192_oids, 16, 192, sizeof (RIJNDAEL_context),
    rijndael_setkey, rijndael_encrypt, rijndael_decrypt
  };

static const char *rijndael256_names[] =
  {
    "RIJNDAEL256",
    NULL
  };

static gcry_cipher_oid_spec_t rijndael256_oids[] =
  {
    { "2.16.840.1.101.3.4.1.41", GCRY_CIPHER_MODE_ECB },
    { "2.16.840.1.101.3.4.1.42", GCRY_CIPHER_MODE_CBC },
    { "2.16.840.1.101.3.4.1.43", GCRY_CIPHER_MODE_OFB },
    { "2.16.840.1.101.3.4.1.44", GCRY_CIPHER_MODE_CFB },
    { NULL }
  };

gcry_cipher_spec_t _gcry_cipher_spec_aes256 =
  {
    "AES256", rijndael256_names, rijndael256_oids, 16, 256,
    sizeof (RIJNDAEL_context),
    rijndael_setkey, rijndael_encrypt, rijndael_decrypt
  };
