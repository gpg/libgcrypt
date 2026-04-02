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
static const qdata_t qdata;

#define _16XQ            0
#define _16XQINV        16
#define _16XV           32
#define _16XFLO         48
#define _16XFHI         64
#define _16XMONTSQLO    80
#define _16XMONTSQHI    96
#define _16XMASK       112
#define _REVIDXB       128
#define _REVIDXD       144
#define _ZETAS_EXP     160
#define	_16XSHIFT      624

static void ntt_avx(__m256i *r, const __m256i *qdata);
static void invntt_avx(__m256i *r, const __m256i *qdata);
static void nttpack_avx(__m256i *r, const __m256i *qdata);
static void nttunpack_avx(__m256i *r, const __m256i *qdata);
static void basemul_avx(__m256i *r,
                 const __m256i *a,
                 const __m256i *b,
                 const __m256i *qdata);
static void ntttobytes_avx(uint8_t *r, const __m256i *a, const __m256i *qdata);
static void nttfrombytes_avx(__m256i *r, const uint8_t *a, const __m256i *qdata);
static void reduce_avx(__m256i *r, const __m256i *qdata);
static void tomont_avx(__m256i *r, const __m256i *qdata);

#define SHAKE256_RATE 136
