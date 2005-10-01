#include <compat/gcrypt-internal.h>

#include <gcrypt-random-internal.h>

void
gcry_randomize (unsigned char *buffer, size_t length,
		enum gcry_random_level level)
{
  _gcry_init ();
  gcry_core_random_randomize (context, buffer, length, level);
}

gcry_error_t
gcry_random_add_bytes (const void *buffer, size_t length,
		       int quality)
{
  _gcry_init ();
  return gcry_core_random_add_bytes (context, buffer, length, quality);
}

void *
gcry_random_bytes (size_t nbytes, enum gcry_random_level level)
{
  _gcry_init ();
  return gcry_core_random_bytes (context, nbytes, level);
}

void *
gcry_random_bytes_secure (size_t nbytes, enum gcry_random_level level)
{
  _gcry_init ();
  return gcry_core_random_bytes_secure (context, nbytes, level);
}

void
gcry_create_nonce (unsigned char *buffer, size_t length)
{
  _gcry_init ();
  gcry_core_random_create_nonce (context, buffer, length);
}
