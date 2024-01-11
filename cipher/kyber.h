#ifndef KYBER_H
#define KYBER_H

#ifdef _GCRYPT_IN_LIBGCRYPT
/**** Start of the glue code to libgcrypt ****/
#define kyber_keypair   _gcry_mlkem_keypair
#define kyber_encap     _gcry_mlkem_encap
#define kyber_decap     _gcry_mlkem_decap
/**** End of the glue code ****/

void kyber_keypair (int algo, uint8_t *pk, uint8_t *sk);
void kyber_encap (int algo, uint8_t *ct, uint8_t *ss, const uint8_t *pk);
void kyber_decap (int algo, uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#elif defined(KYBER_K)
int crypto_kem_keypair (uint8_t *pk, uint8_t *sk);
int crypto_kem_enc (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int crypto_kem_dec (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
# if KYBER_K == 2
#  define CRYPTO_SECRETKEYBYTES   (2*384+2*384+32+2*32)
#  define CRYPTO_PUBLICKEYBYTES   (2*384+32)
#  define CRYPTO_CIPHERTEXTBYTES  (128+2*320)
#  define CRYPTO_BYTES            32
# elif KYBER_K == 3
#  define CRYPTO_SECRETKEYBYTES   (3*384+3*384+32+2*32)
#  define CRYPTO_PUBLICKEYBYTES   (3*384+32)
#  define CRYPTO_CIPHERTEXTBYTES  (128+3*320)
#  define CRYPTO_BYTES            32
# elif KYBER_K == 4
#  define CRYPTO_SECRETKEYBYTES   (4*384+2*384+32+2*32)
#  define CRYPTO_PUBLICKEYBYTES   (4*384+32)
#  define CRYPTO_CIPHERTEXTBYTES  (160+2*352)
#  define CRYPTO_BYTES            32
# else
#  define CRYPTO_SECRETKEYBYTES_512   (2*384+2*384+32+2*32)
#  define CRYPTO_PUBLICKEYBYTES_512   (2*384+32)
#  define CRYPTO_CIPHERTEXTBYTES_512  (128+2*320)
#  define CRYPTO_BYTES_512            32

#  define CRYPTO_SECRETKEYBYTES_768   (3*384+3*384+32+2*32)
#  define CRYPTO_PUBLICKEYBYTES_768   (3*384+32)
#  define CRYPTO_CIPHERTEXTBYTES_768  (128+3*320)
#  define CRYPTO_BYTES_768            32

#  define CRYPTO_SECRETKEYBYTES_1024  (4*384+2*384+32+2*32)
#  define CRYPTO_PUBLICKEYBYTES_1024  (4*384+32)
#  define CRYPTO_CIPHERTEXTBYTES_1024 (160+2*352)
#  define CRYPTO_BYTES_1024           32

#  deinfe crypto_kem_keypair_2 crypto_kem_keypair_512
#  deinfe crypto_kem_keypair_3 crypto_kem_keypair_768
#  deinfe crypto_kem_keypair_4 crypto_kem_keypair_1024

int crypto_kem_keypair_2 (uint8_t *pk, uint8_t *sk);
int crypto_kem_keypair_3 (uint8_t *pk, uint8_t *sk);
int crypto_kem_keypair_4 (uint8_t *pk, uint8_t *sk);

#  define crypto_kem_enc_2 crypto_kem_enc_512
#  define crypto_kem_enc_3 crypto_kem_enc_768
#  define crypto_kem_enc_4 crypto_kem_enc_1024
int crypto_kem_enc_2 (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int crypto_kem_enc_3 (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int crypto_kem_enc_4 (uint8_t *ct, uint8_t *ss, const uint8_t *pk);

#  define crypto_kem_dec_2 crypto_kem_dec_512
#  define crypto_kem_dec_3 crypto_kem_dec_768
#  define crypto_kem_dec_4 crypto_kem_dec_1024
int crypto_kem_dec_2 (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int crypto_kem_dec_3 (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int crypto_kem_dec_4 (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
# endif
#endif

#endif /* KYBER_H */
