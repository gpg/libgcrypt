#ifndef _RMD160_H
#define _RMD160_H

/* we need this here because random.c must have direct access */
typedef struct {
    u32  h0,h1,h2,h3,h4;
    u32  nblocks;
    byte buf[64];
    int  count;
} RMD160_CONTEXT;

extern gcry_core_md_spec_t gcry_core_digest_rmd160;

void _gcry_rmd160_init (gcry_core_context_t ctx,
			void *c);

void _gcry_rmd160_mixblock(gcry_core_context_t ctx,
			   RMD160_CONTEXT *hd, char *buffer );

gcry_error_t _gcry_rmd160_hash_buffer(gcry_core_context_t ctx,
				      char *outbuf, const char *buffer, size_t length );

#endif
