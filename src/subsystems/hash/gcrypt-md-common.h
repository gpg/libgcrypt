#ifndef _GCRYPT_MD_COMMON_H
#define _GCRYPT_MD_COMMON_H



/* Flags used with the open function.  */
enum gcry_md_flags
  {
    GCRY_MD_FLAG_SECURE = 1,  /* Allocate all buffers in "secure"
                                 memory.  */
    GCRY_MD_FLAG_HMAC   = 2   /* Make an HMAC out of this
                                 algorithm.  */
  };



/* Type for the md_init function.  */
typedef void (*gcry_core_md_init_t) (gcry_core_context_t ctx, void *c);

/* Type for the md_write function.  */
typedef void (*gcry_core_md_write_t) (gcry_core_context_t ctx,
				      void *c, unsigned char *buf, size_t nbytes);

/* Type for the md_final function.  */
typedef void (*gcry_core_md_final_t) (gcry_core_context_t ctx,
				      void *c);

/* Type for the md_read function.  */
typedef unsigned char *(*gcry_core_md_read_t) (gcry_core_context_t ctx,
					       void *c);

/* FIXME? */
typedef gcry_error_t (*gcry_core_md_hash_t) (gcry_core_context_t ctx,
					     char *digest,
					     const char *buffer, size_t length);

typedef struct gcry_core_md_oid_spec
{
  const char *oidstring;
} gcry_core_md_oid_spec_t;

/* Module specification structure for message digests.  */
typedef struct gcry_core_md_spec
{
  const char *name;
  unsigned char *asnoid;
  int asnlen;
  gcry_core_md_oid_spec_t *oids;
  int mdlen;
  gcry_core_md_init_t init;
  gcry_core_md_write_t write;
  gcry_core_md_final_t final;
  gcry_core_md_read_t read;
  gcry_core_md_hash_t hash;
  size_t contextsize; /* allocate this amount of context */
} *gcry_core_md_spec_t;



/* Callback mechanism.  */

typedef enum
  {
    GCRY_CORE_MD_CB_INIT,
    GCRY_CORE_MD_CB_WRITE,
    GCRY_CORE_MD_CB_FINAL,
    GCRY_CORE_MD_CB_READ,
    GCRY_CORE_MD_CB_HASH
  }
gcry_core_md_cb_type_t;

typedef struct gcry_core_md_cb_init
{
  void *c;
} gcry_core_md_cb_init_t;

typedef struct gcry_core_md_cb_write
{
  void *c;
  unsigned char *buf;
  size_t nbytes;
} gcry_core_md_cb_write_t;

typedef struct gcry_core_md_cb_final
{
  void *c;
} gcry_core_md_cb_final_t;

typedef struct gcry_core_md_cb_read
{
  void *c;
  unsigned char **result;
} gcry_core_md_cb_read_t;

typedef struct gcry_core_md_cb_hash
{
  char *digest;
  const char *buffer;
  size_t length;
} gcry_core_md_cb_hash_t;

typedef gcry_error_t (*gcry_core_md_cb_t) (gcry_core_context_t ctx,
					   void *opaque,
					   gcry_core_md_cb_type_t type,
					   void *args);



/* Forward declaration.  */
struct gcry_md_context;

/* This object is used to hold a handle to a message digest object.
   This structure is private - only to be used by the public gcry_md_*
   macros.  */
typedef struct gcry_md_handle 
{
  /* Actual context.  */
  struct gcry_md_context *ctx;
  
  /* Buffer management.  */
  int  bufpos;
  int  bufsize;
  unsigned char buf[1];
} *gcry_core_md_hd_t;



typedef gcry_error_t (*gcry_subsystem_md_open_t) (gcry_core_context_t ctx,
						  gcry_core_md_hd_t *handle,
						  gcry_core_md_spec_t algorithm,
						  unsigned int flags);

typedef void (*gcry_subsystem_md_set_cb_t) (gcry_core_context_t ctx,
					    gcry_core_md_hd_t handle,
					    gcry_core_md_spec_t algo,
					    gcry_core_md_cb_t cb,
					    void *opaque);

typedef void (*gcry_subsystem_md_close_t) (gcry_core_context_t ctx,
					   gcry_core_md_hd_t handle);

typedef gcry_error_t (*gcry_subsystem_md_enable_t) (gcry_core_context_t ctx,
						    gcry_core_md_hd_t handle,
						    gcry_core_md_spec_t algorithm);

typedef gcry_error_t (*gcry_subsystem_md_copy_t) (gcry_core_context_t ctx,
						  gcry_core_md_hd_t *handle_b,
						  gcry_core_md_hd_t handle_a);

typedef void (*gcry_subsystem_md_reset_t) (gcry_core_context_t ctx,
					   gcry_core_md_hd_t handle);

typedef gcry_error_t (*gcry_subsystem_md_write_t) (gcry_core_context_t ctx,
						   gcry_core_md_hd_t handle,
						   const void *buffer,
						   size_t length);

typedef unsigned char *(*gcry_subsystem_md_read_t) (gcry_core_context_t ctx,
						    gcry_core_md_hd_t handle,
						    gcry_core_md_spec_t algorithm);

typedef gcry_error_t (*gcry_subsystem_md_hash_buffer_t) (gcry_core_context_t ctx,
							 gcry_core_md_spec_t algo,
							 void *digest,
							 const void *buffer,
							 size_t length);

typedef gcry_core_md_spec_t (*gcry_subsystem_md_get_algo_t) (gcry_core_context_t ctx,
							     gcry_core_md_hd_t handle,
							     unsigned int nth);

typedef int (*gcry_subsystem_md_is_enabled_t) (gcry_core_context_t ctx,
					       gcry_core_md_hd_t handle,
					       gcry_core_md_spec_t algorithm);

typedef int (*gcry_subsystem_md_is_secure_t) (gcry_core_context_t ctx,
					      gcry_core_md_hd_t handle);

typedef gcry_error_t (*gcry_subsystem_md_setkey_t) (gcry_core_context_t ctx,
						    gcry_core_md_hd_t handle,
						    const void *key,
						    size_t keylen);

typedef gcry_error_t (*gcry_subsystem_md_final_t) (gcry_core_context_t ctx,
						   gcry_core_md_hd_t handle);

typedef void (*gcry_subsystem_md_debug_start_t) (gcry_core_context_t ctx,
							 gcry_core_md_hd_t handle,
							 const char *suffix);

typedef void (*gcry_subsystem_md_debug_stop_t) (gcry_core_context_t ctx,
						gcry_core_md_hd_t handle);



/* Create a message digest object for algorithm ALGO.  FLAGS may be
   given as an bitwise OR of the gcry_md_flags values.  ALGO may be
   given as 0 if the algorithms to be used are later set using
   gcry_md_enable.  */
gcry_error_t gcry_core_md_open (gcry_core_context_t ctx, gcry_core_md_hd_t *h,
				gcry_core_md_spec_t algo, unsigned int flags);

void gcry_core_md_set_cb (gcry_core_context_t ctx,
			  gcry_core_md_hd_t handle,
			  gcry_core_md_spec_t algo,
			  gcry_core_md_cb_t cb,
			  void *opaque);

/* Release the message digest object HD.  */
void gcry_core_md_close (gcry_core_context_t ctx,
			 gcry_core_md_hd_t hd);

/* Add the message digest algorithm ALGO to the digest object HD.  */
gcry_error_t gcry_core_md_enable (gcry_core_context_t ctx,
				  gcry_core_md_hd_t hd, gcry_core_md_spec_t algo);

/* Create a new digest object as an exact copy of the object HD.  */
gcry_error_t gcry_core_md_copy (gcry_core_context_t ctx,
				gcry_core_md_hd_t *bhd, gcry_core_md_hd_t ahd);

/* Reset the digest object HD to its initial state.  */
void gcry_core_md_reset (gcry_core_context_t ctx,
			 gcry_core_md_hd_t hd);

/* Pass LENGTH bytes of data in BUFFER to the digest object HD so that
   it can update the digest values.  This is the actual hash
   function. */
void gcry_core_md_write (gcry_core_context_t ctx,
			 gcry_core_md_hd_t hd, const void *buffer, size_t length);

/* Read out the final digest from HD return the digest value for
   algorithm ALGO. */
unsigned char *gcry_core_md_read (gcry_core_context_t ctx,
				  gcry_core_md_hd_t hd, gcry_core_md_spec_t algo);

/* Convenience function to calculate the hash from the data in BUFFER
   of size LENGTH using the algorithm ALGO avoiding the creating of a
   hash object.  The hash is returned in the caller provided buffer
   DIGEST which must be large enough to hold the digest of the given
   algorithm. */
gcry_error_t gcry_core_md_hash_buffer (gcry_core_context_t ctx,
				       gcry_core_md_spec_t algo, void *digest,
				       const void *buffer, size_t length);

/* Retrieve the algorithm used with HD.  This does not work reliable
   if more than one algorithm is enabled in HD. */
gcry_core_md_spec_t gcry_core_md_get_algo (gcry_core_context_t ctx,
					   gcry_core_md_hd_t hd,
					   unsigned int nth);

/* Return true if the the algorithm ALGO is enabled in the digest
   object A. */
int gcry_core_md_is_enabled (gcry_core_context_t ctx,
			     gcry_core_md_hd_t a, gcry_core_md_spec_t algo);

/* Return true if the digest object A is allocated in "secure" memory. */
int gcry_core_md_is_secure (gcry_core_context_t ctx, gcry_core_md_hd_t handle);

/* For use with the HMAC feature, the set MAC key to the KEY of
   KEYLEN. */
gcry_error_t gcry_core_md_setkey (gcry_core_context_t ctx,
				  gcry_core_md_hd_t hd, const void *key, size_t keylen);

/* Update the hash(s) of H with the character C.  This is a buffered
   version of the gcry_md_write function. */
#define gcry_core_md_putc(ctx,h,c)  \
            do {                                          \
                gcry_core_md_hd_t h__ = (h);                   \
                if( (h__)->bufpos == (h__)->bufsize )     \
                    gcry_core_md_write((ctx), (h__), NULL, 0 );      \
                (h__)->buf[(h__)->bufpos++] = (c) & 0xff; \
            } while(0)

gcry_error_t gcry_core_md_final (gcry_core_context_t ctx, gcry_core_md_hd_t handle);

void gcry_core_md_debug_start (gcry_core_context_t ctx,
			       gcry_core_md_hd_t handle, const char *suffix);

void gcry_core_md_debug_stop (gcry_core_context_t ctx,
			      gcry_core_md_hd_t handle);



typedef struct gcry_core_subsystem_md
{
  gcry_subsystem_md_open_t open;
  gcry_subsystem_md_set_cb_t set_cb;
  gcry_subsystem_md_close_t close;
  gcry_subsystem_md_enable_t enable;
  gcry_subsystem_md_copy_t copy;
  gcry_subsystem_md_reset_t reset;
  gcry_subsystem_md_write_t write;
  gcry_subsystem_md_read_t read;
  gcry_subsystem_md_hash_buffer_t hash_buffer;
  gcry_subsystem_md_get_algo_t get_algo;
  gcry_subsystem_md_is_enabled_t is_enabled;
  gcry_subsystem_md_is_secure_t is_secure;
  gcry_subsystem_md_setkey_t setkey;
  gcry_subsystem_md_final_t final;
  gcry_subsystem_md_debug_start_t debug_start;
  gcry_subsystem_md_debug_stop_t debug_stop;
} *gcry_core_subsystem_md_t;

extern gcry_core_subsystem_md_t gcry_core_subsystem_md;

void gcry_core_set_subsystem_md (gcry_core_context_t ctx, gcry_core_subsystem_md_t md);



#endif
