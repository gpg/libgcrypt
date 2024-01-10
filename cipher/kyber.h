#ifndef KYBER_H
#define KYBER_H

#ifdef _GCRYPT_IN_LIBGCRYPT
/**** Start of the glue code to libgcrypt ****/
#define kyber_keypair   _gcry_mlkem_keypair
#define kyber_encap     _gcry_mlkem_encap
#define kyber_decap     _gcry_mlkem_decap
/**** End of the glue code ****/
#else
#define CRYPTO_SECRETKEYBYTES512   (2*384+2*384+32+2*32)
#define CRYPTO_PUBLICKEYBYTES512   (2*384+32)
#define CRYPTO_CIPHERTEXTBYTES512  (128+2*320)
#define CRYPTO_BYTES512            32

#define CRYPTO_SECRETKEYBYTES768   (3*384+3*384+32+2*32)
#define CRYPTO_PUBLICKEYBYTES768   (3*384+32)
#define CRYPTO_CIPHERTEXTBYTES768  (128+3*320)
#define CRYPTO_BYTES768            32

#define CRYPTO_SECRETKEYBYTES1024  (4*384+2*384+32+2*32)
#define CRYPTO_PUBLICKEYBYTES1024  (4*384+32)
#define CRYPTO_CIPHERTEXTBYTES1024 (160+2*352)
#define CRYPTO_BYTES1024           32
#endif

void kyber_keypair (int algo, uint8_t *pk, uint8_t *sk);
void kyber_encap (int algo, uint8_t *ct, uint8_t *ss, const uint8_t *pk);
void kyber_decap (int algo, uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif /* KYBER_H */
