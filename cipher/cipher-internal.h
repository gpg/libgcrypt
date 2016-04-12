/* cipher-internal.h  - Internal defs for cipher.c
 * Copyright (C) 2011 Free Software Foundation, Inc.
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G10_CIPHER_INTERNAL_H
#define G10_CIPHER_INTERNAL_H

#include "./poly1305-internal.h"


/* The maximum supported size of a block in bytes.  */
#define MAX_BLOCKSIZE 16

/* The length for an OCB block.  Although OCB supports any block
   length it does not make sense to use a 64 bit blocklen (and cipher)
   because this reduces the security margin to an unacceptable state.
   Thus we require a cipher with 128 bit blocklength.  */
#define OCB_BLOCK_LEN  (128/8)

/* The size of the pre-computed L table for OCB.  This takes the same
   size as the table used for GCM and thus we don't save anything by
   not using such a table.  */
#define OCB_L_TABLE_SIZE 16


/* Check the above constants.  */
#if OCB_BLOCK_LEN > MAX_BLOCKSIZE
# error OCB_BLOCKLEN > MAX_BLOCKSIZE
#endif



/* Magic values for the context structure.  */
#define CTX_MAGIC_NORMAL 0x24091964
#define CTX_MAGIC_SECURE 0x46919042

/* Try to use 16 byte aligned cipher context for better performance.
   We use the aligned attribute, thus it is only possible to implement
   this with gcc.  */
#undef NEED_16BYTE_ALIGNED_CONTEXT
#ifdef HAVE_GCC_ATTRIBUTE_ALIGNED
# define NEED_16BYTE_ALIGNED_CONTEXT 1
#endif

/* Undef this symbol to trade GCM speed for 256 bytes of memory per context */
#define GCM_USE_TABLES 1


/* GCM_USE_INTEL_PCLMUL indicates whether to compile GCM with Intel PCLMUL
   code.  */
#undef GCM_USE_INTEL_PCLMUL
#if defined(ENABLE_PCLMUL_SUPPORT) && defined(GCM_USE_TABLES)
# if ((defined(__i386__) && SIZEOF_UNSIGNED_LONG == 4) || defined(__x86_64__))
#  if __GNUC__ >= 4
#   define GCM_USE_INTEL_PCLMUL 1
#  endif
# endif
#endif /* GCM_USE_INTEL_PCLMUL */


typedef unsigned int (*ghash_fn_t) (gcry_cipher_hd_t c, byte *result,
                                    const byte *buf, size_t nblocks);


/* A VIA processor with the Padlock engine as well as the Intel AES_NI
   instructions require an alignment of most data on a 16 byte
   boundary.  Because we trick out the compiler while allocating the
   context, the align attribute as used in rijndael.c does not work on
   its own.  Thus we need to make sure that the entire context
   structure is a aligned on that boundary.  We achieve this by
   defining a new type and use that instead of our usual alignment
   type.  */
typedef union
{
  PROPERLY_ALIGNED_TYPE foo;
#ifdef NEED_16BYTE_ALIGNED_CONTEXT
  char bar[16] __attribute__ ((aligned (16)));
#endif
  char c[1];
} cipher_context_alignment_t;


/* The handle structure.  */
struct gcry_cipher_handle
{
  int magic;
  size_t actual_handle_size;     /* Allocated size of this handle. */
  size_t handle_offset;          /* Offset to the malloced block.  */
  gcry_cipher_spec_t *spec;

  /* The algorithm id.  This is a hack required because the module
     interface does not easily allow to retrieve this value. */
  int algo;

  /* A structure with function pointers for bulk operations.  Due to
     limitations of the module system (we don't want to change the
     API) we need to keep these function pointers here.  The cipher
     open function intializes them and the actual encryption routines
     use them if they are not NULL.  */
  struct {
    void (*cfb_enc)(void *context, unsigned char *iv,
                    void *outbuf_arg, const void *inbuf_arg,
                    size_t nblocks);
    void (*cfb_dec)(void *context, unsigned char *iv,
                    void *outbuf_arg, const void *inbuf_arg,
                    size_t nblocks);
    void (*cbc_enc)(void *context, unsigned char *iv,
                    void *outbuf_arg, const void *inbuf_arg,
                    size_t nblocks, int cbc_mac);
    void (*cbc_dec)(void *context, unsigned char *iv,
                    void *outbuf_arg, const void *inbuf_arg,
                    size_t nblocks);
    void (*ctr_enc)(void *context, unsigned char *iv,
                    void *outbuf_arg, const void *inbuf_arg,
                    size_t nblocks);
    size_t (*ocb_crypt)(gcry_cipher_hd_t c, void *outbuf_arg,
			const void *inbuf_arg, size_t nblocks, int encrypt);
    size_t (*ocb_auth)(gcry_cipher_hd_t c, const void *abuf_arg,
		       size_t nblocks);
  } bulk;


  int mode;
  unsigned int flags;

  struct {
    unsigned int key:1; /* Set to 1 if a key has been set.  */
    unsigned int iv:1;  /* Set to 1 if a IV has been set.  */
    unsigned int tag:1; /* Set to 1 if a tag is finalized. */
    unsigned int finalize:1; /* Next encrypt/decrypt has the final data.  */
  } marks;

  /* The initialization vector.  For best performance we make sure
     that it is properly aligned.  In particular some implementations
     of bulk operations expect an 16 byte aligned IV.  IV is also used
     to store CBC-MAC in CCM mode; counter IV is stored in U_CTR.  For
     OCB mode it is used for the offset value.  */
  union {
    cipher_context_alignment_t iv_align;
    unsigned char iv[MAX_BLOCKSIZE];
  } u_iv;

  /* The counter for CTR mode.  This field is also used by AESWRAP and
     thus we can't use the U_IV union.  For OCB mode it is used for
     the checksum.  */
  union {
    cipher_context_alignment_t iv_align;
    unsigned char ctr[MAX_BLOCKSIZE];
  } u_ctr;

  /* Space to save an IV or CTR for chaining operations.  */
  unsigned char lastiv[MAX_BLOCKSIZE];
  int unused;  /* Number of unused bytes in LASTIV. */

  union {
    /* Mode specific storage for CCM mode. */
    struct {
      u64 encryptlen;
      u64 aadlen;
      unsigned int authlen;

      /* Space to save partial input lengths for MAC. */
      unsigned char macbuf[GCRY_CCM_BLOCK_LEN];
      int mac_unused;  /* Number of unprocessed bytes in MACBUF. */

      unsigned char s0[GCRY_CCM_BLOCK_LEN];

      unsigned int nonce:1;/* Set to 1 if nonce has been set.  */
      unsigned int lengths:1; /* Set to 1 if CCM length parameters has been
                                 processed.  */
    } ccm;

    /* Mode specific storage for Poly1305 mode. */
    struct {
      /* byte counter for AAD. */
      u32 aadcount[2];

      /* byte counter for data. */
      u32 datacount[2];

      unsigned int aad_finalized:1;
      unsigned int bytecount_over_limits:1;

      poly1305_context_t ctx;
    } poly1305;

    /* Mode specific storage for CMAC mode. */
    struct {
      unsigned int tag:1; /* Set to 1 if tag has been finalized.  */

      /* Subkeys for tag creation, not cleared by gcry_cipher_reset. */
      unsigned char subkeys[2][MAX_BLOCKSIZE];
    } cmac;

    /* Mode specific storage for GCM mode. */
    struct {
      /* The interim tag for GCM mode.  */
      union {
        cipher_context_alignment_t iv_align;
        unsigned char tag[MAX_BLOCKSIZE];
      } u_tag;

      /* Space to save partial input lengths for MAC. */
      unsigned char macbuf[GCRY_CCM_BLOCK_LEN];
      int mac_unused;  /* Number of unprocessed bytes in MACBUF. */


      /* byte counters for GCM */
      u32 aadlen[2];
      u32 datalen[2];

      /* encrypted tag counter */
      unsigned char tagiv[MAX_BLOCKSIZE];

      unsigned int ghash_data_finalized:1;
      unsigned int ghash_aad_finalized:1;

      unsigned int datalen_over_limits:1;
      unsigned int disallow_encryption_because_of_setiv_in_fips_mode:1;

      /* --- Following members are not cleared in gcry_cipher_reset --- */

      /* GHASH multiplier from key.  */
      union {
        cipher_context_alignment_t iv_align;
        unsigned char key[MAX_BLOCKSIZE];
      } u_ghash_key;

      /* GHASH implementation in use. */
      ghash_fn_t ghash_fn;

      /* Pre-calculated table for GCM. */
#ifdef GCM_USE_TABLES
 #if (SIZEOF_UNSIGNED_LONG == 8 || defined(__x86_64__))
      #define GCM_TABLES_USE_U64 1
      u64 gcm_table[2 * 16];
 #else
      #undef GCM_TABLES_USE_U64
      u32 gcm_table[4 * 16];
 #endif
#endif
    } gcm;

    /* Mode specific storage for OCB mode. */
    struct {
      /* Helper variables and pre-computed table of L values.  */
      unsigned char L_star[OCB_BLOCK_LEN];
      unsigned char L_dollar[OCB_BLOCK_LEN];
      unsigned char L[OCB_BLOCK_LEN][OCB_L_TABLE_SIZE];

      /* The tag is valid if marks.tag has been set.  */
      unsigned char tag[OCB_BLOCK_LEN];

      /* A buffer to hold the offset for the AAD processing.  */
      unsigned char aad_offset[OCB_BLOCK_LEN];

      /* A buffer to hold the current sum of AAD processing.  We can't
         use tag here because tag may already hold the preprocessed
         checksum of the data.  */
      unsigned char aad_sum[OCB_BLOCK_LEN];

      /* A buffer to store AAD data not yet processed.  */
      unsigned char aad_leftover[OCB_BLOCK_LEN];

      /* Number of data/aad blocks processed so far.  */
      u64 data_nblocks;
      u64 aad_nblocks;

      /* Number of valid bytes in AAD_LEFTOVER.  */
      unsigned char aad_nleftover;

      /* Length of the tag.  Fixed for now but may eventually be
         specified using a set of gcry_cipher_flags.  */
      unsigned char taglen;

      /* Flags indicating that the final data/aad block has been
         processed.  */
      unsigned int data_finalized:1;
      unsigned int aad_finalized:1;

    } ocb;

  } u_mode;

  /* What follows are two contexts of the cipher in use.  The first
     one needs to be aligned well enough for the cipher operation
     whereas the second one is a copy created by cipher_setkey and
     used by cipher_reset.  That second copy has no need for proper
     aligment because it is only accessed by memcpy.  */
  cipher_context_alignment_t context;
};


/*-- cipher-cbc.c --*/
gcry_err_code_t _gcry_cipher_cbc_encrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, size_t outbuflen,
                 const unsigned char *inbuf, size_t inbuflen);
gcry_err_code_t _gcry_cipher_cbc_decrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, size_t outbuflen,
                 const unsigned char *inbuf, size_t inbuflen);

/*-- cipher-cfb.c --*/
gcry_err_code_t _gcry_cipher_cfb_encrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, size_t outbuflen,
                 const unsigned char *inbuf, size_t inbuflen);
gcry_err_code_t _gcry_cipher_cfb_decrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, size_t outbuflen,
                 const unsigned char *inbuf, size_t inbuflen);


/*-- cipher-ofb.c --*/
gcry_err_code_t _gcry_cipher_ofb_encrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, size_t outbuflen,
                 const unsigned char *inbuf, size_t inbuflen);

/*-- cipher-ctr.c --*/
gcry_err_code_t _gcry_cipher_ctr_encrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, size_t outbuflen,
                 const unsigned char *inbuf, size_t inbuflen);


/*-- cipher-aeswrap.c --*/
gcry_err_code_t _gcry_cipher_aeswrap_encrypt
/*           */   (gcry_cipher_hd_t c,
                   byte *outbuf, size_t outbuflen,
                   const byte *inbuf, size_t inbuflen);
gcry_err_code_t _gcry_cipher_aeswrap_decrypt
/*           */   (gcry_cipher_hd_t c,
                   byte *outbuf, size_t outbuflen,
                   const byte *inbuf, size_t inbuflen);


/*-- cipher-ccm.c --*/
gcry_err_code_t _gcry_cipher_ccm_encrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, size_t outbuflen,
                 const unsigned char *inbuf, size_t inbuflen);
gcry_err_code_t _gcry_cipher_ccm_decrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, size_t outbuflen,
                 const unsigned char *inbuf, size_t inbuflen);
gcry_err_code_t _gcry_cipher_ccm_set_nonce
/*           */ (gcry_cipher_hd_t c, const unsigned char *nonce,
                 size_t noncelen);
gcry_err_code_t _gcry_cipher_ccm_authenticate
/*           */ (gcry_cipher_hd_t c, const unsigned char *abuf, size_t abuflen);
gcry_err_code_t _gcry_cipher_ccm_set_lengths
/*           */ (gcry_cipher_hd_t c, u64 encryptedlen, u64 aadlen, u64 taglen);
gcry_err_code_t _gcry_cipher_ccm_get_tag
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outtag, size_t taglen);
gcry_err_code_t _gcry_cipher_ccm_check_tag
/*           */ (gcry_cipher_hd_t c,
                 const unsigned char *intag, size_t taglen);


/*-- cipher-gcm.c --*/
gcry_err_code_t _gcry_cipher_gcm_encrypt
/*           */   (gcry_cipher_hd_t c,
                   unsigned char *outbuf, size_t outbuflen,
                   const unsigned char *inbuf, size_t inbuflen);
gcry_err_code_t _gcry_cipher_gcm_decrypt
/*           */   (gcry_cipher_hd_t c,
                   unsigned char *outbuf, size_t outbuflen,
                   const unsigned char *inbuf, size_t inbuflen);
gcry_err_code_t _gcry_cipher_gcm_setiv
/*           */   (gcry_cipher_hd_t c,
                   const unsigned char *iv, size_t ivlen);
gcry_err_code_t _gcry_cipher_gcm_authenticate
/*           */   (gcry_cipher_hd_t c,
                   const unsigned char *aadbuf, size_t aadbuflen);
gcry_err_code_t _gcry_cipher_gcm_get_tag
/*           */   (gcry_cipher_hd_t c,
                   unsigned char *outtag, size_t taglen);
gcry_err_code_t _gcry_cipher_gcm_check_tag
/*           */   (gcry_cipher_hd_t c,
                   const unsigned char *intag, size_t taglen);
void _gcry_cipher_gcm_setkey
/*           */   (gcry_cipher_hd_t c);


/*-- cipher-poly1305.c --*/
gcry_err_code_t _gcry_cipher_poly1305_encrypt
/*           */   (gcry_cipher_hd_t c,
                   unsigned char *outbuf, size_t outbuflen,
                   const unsigned char *inbuf, size_t inbuflen);
gcry_err_code_t _gcry_cipher_poly1305_decrypt
/*           */   (gcry_cipher_hd_t c,
                   unsigned char *outbuf, size_t outbuflen,
                   const unsigned char *inbuf, size_t inbuflen);
gcry_err_code_t _gcry_cipher_poly1305_setiv
/*           */   (gcry_cipher_hd_t c,
                   const unsigned char *iv, size_t ivlen);
gcry_err_code_t _gcry_cipher_poly1305_authenticate
/*           */   (gcry_cipher_hd_t c,
                   const unsigned char *aadbuf, size_t aadbuflen);
gcry_err_code_t _gcry_cipher_poly1305_get_tag
/*           */   (gcry_cipher_hd_t c,
                   unsigned char *outtag, size_t taglen);
gcry_err_code_t _gcry_cipher_poly1305_check_tag
/*           */   (gcry_cipher_hd_t c,
                   const unsigned char *intag, size_t taglen);
void _gcry_cipher_poly1305_setkey
/*           */   (gcry_cipher_hd_t c);


/*-- cipher-ocb.c --*/
gcry_err_code_t _gcry_cipher_ocb_encrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, size_t outbuflen,
                 const unsigned char *inbuf, size_t inbuflen);
gcry_err_code_t _gcry_cipher_ocb_decrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, size_t outbuflen,
                 const unsigned char *inbuf, size_t inbuflen);
gcry_err_code_t _gcry_cipher_ocb_set_nonce
/*           */ (gcry_cipher_hd_t c, const unsigned char *nonce,
                 size_t noncelen);
gcry_err_code_t _gcry_cipher_ocb_authenticate
/*           */ (gcry_cipher_hd_t c, const unsigned char *abuf, size_t abuflen);
gcry_err_code_t _gcry_cipher_ocb_get_tag
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outtag, size_t taglen);
gcry_err_code_t _gcry_cipher_ocb_check_tag
/*           */ (gcry_cipher_hd_t c,
                 const unsigned char *intag, size_t taglen);
const unsigned char *_gcry_cipher_ocb_get_l
/*           */ (gcry_cipher_hd_t c, unsigned char *l_tmp, u64 n);


/* Inline version of _gcry_cipher_ocb_get_l, with hard-coded fast paths for
   most common cases.  */
static inline const unsigned char *
ocb_get_l (gcry_cipher_hd_t c, unsigned char *l_tmp, u64 n)
{
  if (n & 1)
    return c->u_mode.ocb.L[0];
  else if (n & 2)
    return c->u_mode.ocb.L[1];
  else
    {
      unsigned int ntz = _gcry_ctz64 (n);

      if (ntz < OCB_L_TABLE_SIZE)
	return c->u_mode.ocb.L[ntz];
      else
	return _gcry_cipher_ocb_get_l (c, l_tmp, n);
    }
}

#endif /*G10_CIPHER_INTERNAL_H*/
