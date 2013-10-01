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

/* The maximum supported size of a block in bytes.  */
#define MAX_BLOCKSIZE 16

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
  gcry_module_t module;

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
                    unsigned int nblocks);
    void (*cfb_dec)(void *context, unsigned char *iv,
                    void *outbuf_arg, const void *inbuf_arg,
                    unsigned int nblocks);
    void (*cbc_enc)(void *context, unsigned char *iv,
                    void *outbuf_arg, const void *inbuf_arg,
                    unsigned int nblocks, int cbc_mac);
    void (*cbc_dec)(void *context, unsigned char *iv,
                    void *outbuf_arg, const void *inbuf_arg,
                    unsigned int nblocks);
    void (*ctr_enc)(void *context, unsigned char *iv,
                    void *outbuf_arg, const void *inbuf_arg,
                    unsigned int nblocks);
  } bulk;


  int mode;
  unsigned int flags;

  struct {
    unsigned int key:1; /* Set to 1 if a key has been set.  */
    unsigned int iv:1;  /* Set to 1 if a IV has been set.  */
  } marks;

  /* The initialization vector.  For best performance we make sure
     that it is properly aligned.  In particular some implementations
     of bulk operations expect an 16 byte aligned IV.  */
  union {
    cipher_context_alignment_t iv_align;
    unsigned char iv[MAX_BLOCKSIZE];
  } u_iv;

  /* The counter for CTR mode.  This field is also used by AESWRAP and
     thus we can't use the U_IV union.  */
  union {
    cipher_context_alignment_t iv_align;
    unsigned char ctr[MAX_BLOCKSIZE];
  } u_ctr;

  /* Space to save an IV or CTR for chaining operations.  */
  unsigned char lastiv[MAX_BLOCKSIZE];
  int unused;  /* Number of unused bytes in LASTIV. */

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
                 unsigned char *outbuf, unsigned int outbuflen,
                 const unsigned char *inbuf, unsigned int inbuflen);
gcry_err_code_t _gcry_cipher_cbc_decrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, unsigned int outbuflen,
                 const unsigned char *inbuf, unsigned int inbuflen);

/*-- cipher-cfb.c --*/
gcry_err_code_t _gcry_cipher_cfb_encrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, unsigned int outbuflen,
                 const unsigned char *inbuf, unsigned int inbuflen);
gcry_err_code_t _gcry_cipher_cfb_decrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, unsigned int outbuflen,
                 const unsigned char *inbuf, unsigned int inbuflen);


/*-- cipher-ofb.c --*/
gcry_err_code_t _gcry_cipher_ofb_encrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, unsigned int outbuflen,
                 const unsigned char *inbuf, unsigned int inbuflen);
gcry_err_code_t _gcry_cipher_ofb_decrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, unsigned int outbuflen,
                 const unsigned char *inbuf, unsigned int inbuflen);

/*-- cipher-ctr.c --*/
gcry_err_code_t _gcry_cipher_ctr_encrypt
/*           */ (gcry_cipher_hd_t c,
                 unsigned char *outbuf, unsigned int outbuflen,
                 const unsigned char *inbuf, unsigned int inbuflen);


/*-- cipher-aeswrap.c --*/
gcry_err_code_t _gcry_cipher_aeswrap_encrypt
/*           */   (gcry_cipher_hd_t c,
                   byte *outbuf, unsigned int outbuflen,
                   const byte *inbuf, unsigned int inbuflen);
gcry_err_code_t _gcry_cipher_aeswrap_decrypt
/*           */   (gcry_cipher_hd_t c,
                   byte *outbuf, unsigned int outbuflen,
                   const byte *inbuf, unsigned int inbuflen);



#endif /*G10_CIPHER_INTERNAL_H*/
