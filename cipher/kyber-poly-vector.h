/* Experiment for AVX2 */
#include <immintrin.h>
#define ALIGNED_UINT8(N)        \
    union {                     \
        uint8_t coeffs[N];      \
        __m256i vec[(N+31)/32]; \
    }

#define ALIGNED_INT16(N)        \
    union {                     \
        int16_t coeffs[N];      \
        __m256i vec[(N+15)/16]; \
    }

typedef ALIGNED_INT16(KYBER_N) poly;
typedef ALIGNED_INT16(640) qdata_t;

/* Those are internally defined by asm, but use "extern" here.  */
extern void ntttobytes_avx(uint8_t *r, const __m256i *a, const __m256i *qdata);
extern void nttfrombytes_avx(__m256i *r, const uint8_t *a, const __m256i *qdata);
extern void ntt_avx(__m256i *r, const __m256i *qdata);
extern void invntt_avx(__m256i *r, const __m256i *qdata);
extern void nttunpack_avx(__m256i *r, const __m256i *qdata);
extern void basemul_avx(__m256i *r,
          const __m256i *a,
          const __m256i *b,
          const __m256i *qdata);
extern void tomont_avx(__m256i *r, const __m256i *qdata);
extern void reduce_avx(__m256i *r, const __m256i *qdata);

#define SHAKE256_RATE 136
