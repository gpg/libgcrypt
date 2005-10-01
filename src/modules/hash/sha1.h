#ifndef _SHA1_H
#define _SHA1_H

extern gcry_core_md_spec_t gcry_core_digest_sha1;

gcry_error_t _gcry_sha1_hash_buffer (gcry_core_context_t ctx,
				     char *outbuf, const char *buffer, size_t length);

#endif
