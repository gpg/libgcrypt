#ifndef _GCRYPT_CIPHER_COMMON_H
#define _GCRYPT_CIPHER_COMMON_H

/* The supported encryption modes.  Note that not all of them are
   supported for each algorithm. */
enum gcry_cipher_modes 
  {
    GCRY_CIPHER_MODE_NONE   = 0,  /* Not yet specified. */
    GCRY_CIPHER_MODE_ECB    = 1,  /* Electronic codebook. */
    GCRY_CIPHER_MODE_CFB    = 2,  /* Cipher feedback. */
    GCRY_CIPHER_MODE_CBC    = 3,  /* Cipher block chaining. */
    GCRY_CIPHER_MODE_STREAM = 4,  /* Used with stream ciphers. */
    GCRY_CIPHER_MODE_OFB    = 5,  /* Outer feedback. */
    GCRY_CIPHER_MODE_CTR    = 6   /* Counter. */
  };



/* Flags used with the open function. */ 
enum gcry_cipher_flags
  {
    GCRY_CIPHER_SECURE      = 1,  /* Allocate in secure memory. */
    GCRY_CIPHER_ENABLE_SYNC = 2,  /* Enable CFB sync mode. */
    GCRY_CIPHER_CBC_CTS     = 4,  /* Enable CBC cipher text stealing (CTS). */
    GCRY_CIPHER_CBC_MAC     = 8   /* Enable CBC message auth. code (MAC). */
  };



/* The data object used to hold a handle to an encryption object.  */
struct gcry_cipher_handle;
typedef struct gcry_cipher_handle *gcry_core_cipher_hd_t;



/* Type for the cipher_setkey function.  */
typedef gcry_err_code_t (*gcry_core_cipher_setkey_t) (gcry_core_context_t ctx,
						      void *c,
						      const unsigned char *key,
						      unsigned keylen);

/* Type for the cipher_encrypt function.  */
typedef void (*gcry_core_cipher_encrypt_t) (gcry_core_context_t ctx,
					    void *c,
					    unsigned char *outbuf,
					    const unsigned char *inbuf);

/* Type for the cipher_decrypt function.  */
typedef void (*gcry_core_cipher_decrypt_t) (gcry_core_context_t ctx,
					    void *c,
					    unsigned char *outbuf,
					    const unsigned char *inbuf);

/* Type for the cipher_stencrypt function.  */
typedef void (*gcry_core_cipher_stencrypt_t) (gcry_core_context_t ctx,
					      void *c,
					      unsigned char *outbuf,
					      const unsigned char *inbuf,
					      unsigned int n);

/* Type for the cipher_stdecrypt function.  */
typedef void (*gcry_core_cipher_stdecrypt_t) (gcry_core_context_t ctx,
					      void *c,
					      unsigned char *outbuf,
					      const unsigned char *inbuf,
					      unsigned int n);

typedef struct gcry_core_cipher_oid_spec
{
  const char *oid;
  int mode;
} gcry_core_cipher_oid_spec_t;

/* Module specification structure for ciphers.  */
typedef struct gcry_core_cipher_spec
{
  const char *name;
  const char **aliases;
  gcry_core_cipher_oid_spec_t *oids;
  size_t blocksize;
  size_t keylen;
  size_t contextsize;
  gcry_core_cipher_setkey_t setkey;
  gcry_core_cipher_encrypt_t encrypt;
  gcry_core_cipher_decrypt_t decrypt;
  gcry_core_cipher_stencrypt_t stencrypt;
  gcry_core_cipher_stdecrypt_t stdecrypt;
} *gcry_core_cipher_spec_t;



/* Callback mechanism.  */

typedef enum
  {
    GCRY_CORE_CIPHER_CB_SETKEY,
    GCRY_CORE_CIPHER_CB_ENCRYPT,
    GCRY_CORE_CIPHER_CB_DECRYPT,
    GCRY_CORE_CIPHER_CB_STENCRYPT,
    GCRY_CORE_CIPHER_CB_STDECRYPT
  }
gcry_core_cipher_cb_type_t;

typedef struct gcry_core_cipher_cb_setkey
{
  void *c;
  const unsigned char *key;
  unsigned int keylen;
} gcry_core_cipher_cb_setkey_t;

typedef struct gcry_core_cipher_cb_encrypt
{
  void *c;
  unsigned char *outbuf;
  const unsigned char *inbuf;
} gcry_core_cipher_cb_encrypt_t;

typedef struct gcry_core_cipher_cb_decrypt
{
  void *c;
  unsigned char *outbuf;
  const unsigned char *inbuf;
} gcry_core_cipher_cb_decrypt_t;

typedef struct gcry_core_cipher_cb_stencrypt
{
  void *c;
  unsigned char *outbuf;
  const unsigned char *inbuf;
  unsigned int n;
} gcry_core_cipher_cb_stencrypt_t;

typedef struct gcry_core_cipher_cb_stdecrypt
{
  void *c;
  unsigned char *outbuf;
  const unsigned char *inbuf;
  unsigned int n;
} gcry_core_cipher_cb_stdecrypt_t;

typedef gcry_error_t (*gcry_core_cipher_cb_t) (gcry_core_context_t ctx,
					       void *opaque,
					       gcry_core_cipher_cb_type_t type,
					       void *args);



typedef gcry_error_t (*gcry_subsystem_cipher_open_t) (gcry_core_context_t ctx,
						      gcry_core_cipher_hd_t *handle,
						      gcry_core_cipher_spec_t algo,
						      int mode, unsigned int flags);
typedef void (*gcry_subsystem_cipher_set_cb_t) (gcry_core_context_t ctx,
						gcry_core_cipher_hd_t handle,
						gcry_core_cipher_cb_t cb,
						void *opaque);
typedef gcry_core_cipher_spec_t (*gcry_subsystem_cipher_spec_t) (gcry_core_context_t ctx,
								 gcry_core_cipher_hd_t handle);
typedef void (*gcry_subsystem_cipher_close_t) (gcry_core_context_t ctx, gcry_core_cipher_hd_t h);
typedef gcry_error_t (*gcry_subsystem_cipher_setkey_t) (gcry_core_context_t ctx,
							gcry_core_cipher_hd_t handle,
							const char *key,
							size_t length);
typedef gcry_error_t (*gcry_subsystem_cipher_setiv_t) (gcry_core_context_t ctx,
						       gcry_core_cipher_hd_t handle,
						       const char *iv,
						       size_t length);
typedef gcry_error_t (*gcry_subsystem_cipher_reset_t) (gcry_core_context_t ctx,
						       gcry_core_cipher_hd_t handle);
typedef gcry_error_t (*gcry_subsystem_cipher_sync_t) (gcry_core_context_t ctx,
						      gcry_core_cipher_hd_t handle);
typedef gcry_error_t (*gcry_subsystem_cipher_cts_t) (gcry_core_context_t ctx,
						     gcry_core_cipher_hd_t handle,
						     unsigned int onoff);
typedef gcry_error_t (*gcry_subsystem_cipher_setctr_t) (gcry_core_context_t ctx,
							gcry_core_cipher_hd_t handle,
							const char *k,
							size_t l);
typedef gcry_error_t (*gcry_subsystem_cipher_set_cbc_mac_t) (gcry_core_context_t ctx,
							     gcry_core_cipher_hd_t handle,
							     unsigned int onoff);
typedef gcry_error_t (*gcry_subsystem_cipher_encrypt_t) (gcry_core_context_t ctx,
							 gcry_core_cipher_hd_t h,
							 unsigned char *out, size_t outsize,
							 const unsigned char *in, size_t inlen);
typedef gcry_error_t (*gcry_subsystem_cipher_decrypt_t) (gcry_core_context_t ctx,
							 gcry_core_cipher_hd_t h,
							 unsigned char *out, size_t outsize,
							 const unsigned char *in, size_t inlen);


typedef struct gcry_core_subsystem_cipher
{
  gcry_subsystem_cipher_open_t open;
  gcry_subsystem_cipher_set_cb_t set_cb;
  gcry_subsystem_cipher_close_t close;
  gcry_subsystem_cipher_setkey_t setkey;
  gcry_subsystem_cipher_setiv_t setiv;
  gcry_subsystem_cipher_reset_t reset;
  gcry_subsystem_cipher_sync_t sync;
  gcry_subsystem_cipher_cts_t cts;
  gcry_subsystem_cipher_setctr_t setctr;
  gcry_subsystem_cipher_set_cbc_mac_t set_cbc_mac;
  gcry_subsystem_cipher_encrypt_t encrypt;
  gcry_subsystem_cipher_decrypt_t decrypt;
} *gcry_core_subsystem_cipher_t;

/* Create a handle for algorithm ALGO to be used in MODE.  FLAGS may
   be given as an bitwise OR of the gcry_cipher_flags values. */
gcry_error_t gcry_core_cipher_open (gcry_core_context_t ctx,
				    gcry_core_cipher_hd_t *handle,
				    gcry_core_cipher_spec_t algo,
				    int mode, unsigned int flags);

void gcry_core_cipher_set_cb (gcry_core_context_t ctx,
			      gcry_core_cipher_hd_t handle,
			      gcry_core_cipher_cb_t cb,
			      void *opaque);

gcry_core_cipher_spec_t gcry_core_cipher_spec (gcry_core_context_t ctx,
					       gcry_core_cipher_hd_t handle);

/* Close the cioher handle H and release all resource. */
void gcry_core_cipher_close (gcry_core_context_t ctx, gcry_core_cipher_hd_t h);

/* Set key KEY of length LENGTH for the cipher handle HANDLE.  */
gcry_error_t gcry_core_cipher_setkey (gcry_core_context_t ctx,
				      gcry_core_cipher_hd_t handle,
				      const char *key,
				      size_t length);

/* Set initialization vector IV of length LENGTH for the cipher handle
   HANDLE. */
gcry_error_t gcry_core_cipher_setiv (gcry_core_context_t ctx,
				     gcry_core_cipher_hd_t handle,
				     const char *iv,
				     size_t length);

/* Reset the handle to the state after open.  */
gcry_error_t gcry_core_cipher_reset (gcry_core_context_t ctx,
				     gcry_core_cipher_hd_t handle);

/* Perform the the OpenPGP sync operation if this is enabled for the
   cipher handle HANDLE. */
gcry_error_t gcry_core_cipher_sync (gcry_core_context_t ctx,
				    gcry_core_cipher_hd_t handle);

/* Enable or disable CTS in future calls to gcry_encrypt(). CBC mode only. */
gcry_error_t gcry_core_cipher_cts (gcry_core_context_t ctx,
				   gcry_core_cipher_hd_t handle,
				   unsigned int onoff);

/* Set counter for CTR mode.  (K,L) must denote a buffer of block size
   length, or (NULL,0) to set the CTR to the all-zero block. */
gcry_error_t gcry_core_cipher_setctr (gcry_core_context_t ctx,
				      gcry_core_cipher_hd_t handle,
				      const char *k,
				      size_t l);

gcry_error_t gcry_core_cipher_set_cbc_mac (gcry_core_context_t ctx,
					   gcry_core_cipher_hd_t handle,
					   unsigned int onoff);

/* Encrypt the plaintext of size INLEN in IN using the cipher handle H
   into the buffer OUT which has an allocated length of OUTSIZE.  For
   most algorithms it is possible to pass NULL for in and 0 for INLEN
   and do a in-place decryption of the data provided in OUT.  */
gcry_error_t gcry_core_cipher_encrypt (gcry_core_context_t ctx,
				       gcry_core_cipher_hd_t h,
				       unsigned char *out, size_t outsize,
				       const unsigned char *in, size_t inlen);

/* The counterpart to gcry_cipher_encrypt.  */
gcry_error_t gcry_core_cipher_decrypt (gcry_core_context_t ctx,
				       gcry_core_cipher_hd_t h,
				       unsigned char *out, size_t outsize,
				       const unsigned char *in, size_t inlen);

extern gcry_core_subsystem_cipher_t gcry_core_subsystem_cipher;
void gcry_core_set_subsystem_cipher (gcry_core_context_t ctx, gcry_core_subsystem_cipher_t cipher);



#endif
