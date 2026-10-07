/*************** dilithium/ref/polyvec.h */
/* Vectors of polynomials of length L */
typedef struct {
  poly vec[L];
} polyvecl;

/* Vectors of polynomials of length K */
typedef struct {
  poly vec[K];
} polyveck;

/*************** dilithium/ref/packing.c */
static void unpack_sk(uint8_t rho[SEEDBYTES],
                      uint8_t tr[TRBYTES],
                      uint8_t key[SEEDBYTES],
                      polyveck *t0,
                      polyvecl *s1,
                      polyveck *s2,
                      const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

/*************** dilithium/avx2/poly.c */

/*************************************************
* Name:        challenge
*
* Description: Implementation of H. Samples polynomial with TAU nonzero
*              coefficients in {-1,1} using the output stream of
*              SHAKE256(seed).
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const uint8_t mu[]: byte array containing seed of length CTILDEBYTES
**************************************************/
void poly_challenge(poly * restrict c, const uint8_t seed[CTILDEBYTES]) {
  unsigned int i, b, pos;
  uint64_t signs;
  ALIGNED_UINT8(SHAKE256_RATE) buf;
  keccak_state state;

  shake256_init(&state);
  shake256_absorb(&state, seed, CTILDEBYTES);
  shake256_finalize(&state);
  shake256_squeezeblocks(buf.coeffs, 1, &state);

  memcpy(&signs, buf.coeffs, 8);
  pos = 8;

  memset(c->vec, 0, sizeof(poly));
  for(i = N-TAU; i < N; ++i) {
    do {
      if(pos >= SHAKE256_RATE) {
        shake256_squeezeblocks(buf.coeffs, 1, &state);
        pos = 0;
      }

      b = buf.coeffs[pos++];
    } while(b > i);

    c->coeffs[i] = c->coeffs[b];
    c->coeffs[b] = 1 - 2*(signs & 1);
    signs >>= 1;
  }
}

/*************** dilithium/avx2/polyvec.c */
static void polyvecl_ntt(polyvecl *v);
static void polyveck_ntt(polyveck *v);
static void polyveck_caddq(polyveck *v);
static void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v);
static void polyveck_invntt_tomont(polyveck *v);
static void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
static void polyveck_pack_w1(uint8_t r[K*POLYW1_PACKEDBYTES], const polyveck *w1);

/*************************************************
* Name:        expand_mat
*
* Description: Implementation of ExpandA. Generates matrix A with uniformly
*              random coefficients a_{i,j} by performing rejection
*              sampling on the output stream of SHAKE128(rho|j|i)
*
* Arguments:   - polyvecl mat[K]: output matrix
*              - const uint8_t rho[]: byte array containing seed rho
**************************************************/
#if K == 4 && L == 4
static void polyvec_matrix_expand_row0_2(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row1_2(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row2_2(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row3_2(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
#endif
#if K == 6 && L == 5
static void polyvec_matrix_expand_row0_3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row1_3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row2_3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row3_3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row4_3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row5_3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
#endif
#if K == 8 && L == 7
static void polyvec_matrix_expand_row0_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row1_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row2_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row3_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row4_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row5_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row6_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
static void polyvec_matrix_expand_row7_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]);
#endif

#if K == 4 && L == 4
void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]) {
  polyvec_matrix_expand_row0_2(&mat[0], NULL, rho);
  polyvec_matrix_expand_row1_2(&mat[1], NULL, rho);
  polyvec_matrix_expand_row2_2(&mat[2], NULL, rho);
  polyvec_matrix_expand_row3_2(&mat[3], NULL, rho);
}

static
void polyvec_matrix_expand_row0_2(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  (void)rowb;
  poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 0, 1, 2, 3);
  poly_nttunpack(&rowa->vec[0]);
  poly_nttunpack(&rowa->vec[1]);
  poly_nttunpack(&rowa->vec[2]);
  poly_nttunpack(&rowa->vec[3]);
}

void polyvec_matrix_expand_row1_2(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  (void)rowb;
  poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 256, 257, 258, 259);
  poly_nttunpack(&rowa->vec[0]);
  poly_nttunpack(&rowa->vec[1]);
  poly_nttunpack(&rowa->vec[2]);
  poly_nttunpack(&rowa->vec[3]);
}

void polyvec_matrix_expand_row2_2(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  (void)rowb;
  poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 512, 513, 514, 515);
  poly_nttunpack(&rowa->vec[0]);
  poly_nttunpack(&rowa->vec[1]);
  poly_nttunpack(&rowa->vec[2]);
  poly_nttunpack(&rowa->vec[3]);
}

void polyvec_matrix_expand_row3_2(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  (void)rowb;
  poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 768, 769, 770, 771);
  poly_nttunpack(&rowa->vec[0]);
  poly_nttunpack(&rowa->vec[1]);
  poly_nttunpack(&rowa->vec[2]);
  poly_nttunpack(&rowa->vec[3]);
}

#elif K == 6 && L == 5
void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]) {
  polyvecl tmp;
  polyvec_matrix_expand_row0_3(&mat[0], &mat[1], rho);
  polyvec_matrix_expand_row1_3(&mat[1], &mat[2], rho);
  polyvec_matrix_expand_row2_3(&mat[2], &mat[3], rho);
  polyvec_matrix_expand_row3_3(&mat[3], NULL, rho);
  polyvec_matrix_expand_row4_3(&mat[4], &mat[5], rho);
  polyvec_matrix_expand_row5_3(&mat[5], &tmp, rho);
}

void polyvec_matrix_expand_row0_3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 0, 1, 2, 3);
  poly_uniform_4x(&rowa->vec[4], &rowb->vec[0], &rowb->vec[1], &rowb->vec[2], rho, 4, 256, 257, 258);
  poly_nttunpack(&rowa->vec[0]);
  poly_nttunpack(&rowa->vec[1]);
  poly_nttunpack(&rowa->vec[2]);
  poly_nttunpack(&rowa->vec[3]);
  poly_nttunpack(&rowa->vec[4]);
  poly_nttunpack(&rowb->vec[0]);
  poly_nttunpack(&rowb->vec[1]);
  poly_nttunpack(&rowb->vec[2]);
}

void polyvec_matrix_expand_row1_3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  poly_uniform_4x(&rowa->vec[3], &rowa->vec[4], &rowb->vec[0], &rowb->vec[1], rho, 259, 260, 512, 513);
  poly_nttunpack(&rowa->vec[3]);
  poly_nttunpack(&rowa->vec[4]);
  poly_nttunpack(&rowb->vec[0]);
  poly_nttunpack(&rowb->vec[1]);
}

void polyvec_matrix_expand_row2_3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  poly_uniform_4x(&rowa->vec[2], &rowa->vec[3], &rowa->vec[4], &rowb->vec[0], rho, 514, 515, 516, 768);
  poly_nttunpack(&rowa->vec[2]);
  poly_nttunpack(&rowa->vec[3]);
  poly_nttunpack(&rowa->vec[4]);
  poly_nttunpack(&rowb->vec[0]);
}

void polyvec_matrix_expand_row3_3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  (void)rowb;
  poly_uniform_4x(&rowa->vec[1], &rowa->vec[2], &rowa->vec[3], &rowa->vec[4], rho, 769, 770, 771, 772);
  poly_nttunpack(&rowa->vec[1]);
  poly_nttunpack(&rowa->vec[2]);
  poly_nttunpack(&rowa->vec[3]);
  poly_nttunpack(&rowa->vec[4]);
}

void polyvec_matrix_expand_row4_3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 1024, 1025, 1026, 1027);
  poly_uniform_4x(&rowa->vec[4], &rowb->vec[0], &rowb->vec[1], &rowb->vec[2], rho, 1028, 1280, 1281, 1282);
  poly_nttunpack(&rowa->vec[0]);
  poly_nttunpack(&rowa->vec[1]);
  poly_nttunpack(&rowa->vec[2]);
  poly_nttunpack(&rowa->vec[3]);
  poly_nttunpack(&rowa->vec[4]);
  poly_nttunpack(&rowb->vec[0]);
  poly_nttunpack(&rowb->vec[1]);
  poly_nttunpack(&rowb->vec[2]);
}

void polyvec_matrix_expand_row5_3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  poly_uniform_4x(&rowa->vec[3], &rowa->vec[4], &rowb->vec[0], &rowb->vec[1], rho, 1283, 1284, 1536, 1537);
  poly_nttunpack(&rowa->vec[3]);
  poly_nttunpack(&rowa->vec[4]);
}

#elif K == 8 && L == 7
void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]) {
  polyvec_matrix_expand_row0_5(&mat[0], &mat[1], rho);
  polyvec_matrix_expand_row1_5(&mat[1], &mat[2], rho);
  polyvec_matrix_expand_row2_5(&mat[2], &mat[3], rho);
  polyvec_matrix_expand_row3_5(&mat[3], NULL, rho);
  polyvec_matrix_expand_row4_5(&mat[4], &mat[5], rho);
  polyvec_matrix_expand_row5_5(&mat[5], &mat[6], rho);
  polyvec_matrix_expand_row6_5(&mat[6], &mat[7], rho);
  polyvec_matrix_expand_row7_5(&mat[7], NULL, rho);
}

void polyvec_matrix_expand_row0_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 0, 1, 2, 3);
  poly_uniform_4x(&rowa->vec[4], &rowa->vec[5], &rowa->vec[6], &rowb->vec[0], rho, 4, 5, 6, 256);
  poly_nttunpack(&rowa->vec[0]);
  poly_nttunpack(&rowa->vec[1]);
  poly_nttunpack(&rowa->vec[2]);
  poly_nttunpack(&rowa->vec[3]);
  poly_nttunpack(&rowa->vec[4]);
  poly_nttunpack(&rowa->vec[5]);
  poly_nttunpack(&rowa->vec[6]);
  poly_nttunpack(&rowb->vec[0]);
}

void polyvec_matrix_expand_row1_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  poly_uniform_4x(&rowa->vec[1], &rowa->vec[2], &rowa->vec[3], &rowa->vec[4], rho, 257, 258, 259, 260);
  poly_uniform_4x(&rowa->vec[5], &rowa->vec[6], &rowb->vec[0], &rowb->vec[1], rho, 261, 262, 512, 513);
  poly_nttunpack(&rowa->vec[1]);
  poly_nttunpack(&rowa->vec[2]);
  poly_nttunpack(&rowa->vec[3]);
  poly_nttunpack(&rowa->vec[4]);
  poly_nttunpack(&rowa->vec[5]);
  poly_nttunpack(&rowa->vec[6]);
  poly_nttunpack(&rowb->vec[0]);
  poly_nttunpack(&rowb->vec[1]);
}

void polyvec_matrix_expand_row2_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  poly_uniform_4x(&rowa->vec[2], &rowa->vec[3], &rowa->vec[4], &rowa->vec[5], rho, 514, 515, 516, 517);
  poly_uniform_4x(&rowa->vec[6], &rowb->vec[0], &rowb->vec[1], &rowb->vec[2], rho, 518, 768, 769, 770);
  poly_nttunpack(&rowa->vec[2]);
  poly_nttunpack(&rowa->vec[3]);
  poly_nttunpack(&rowa->vec[4]);
  poly_nttunpack(&rowa->vec[5]);
  poly_nttunpack(&rowa->vec[6]);
  poly_nttunpack(&rowb->vec[0]);
  poly_nttunpack(&rowb->vec[1]);
  poly_nttunpack(&rowb->vec[2]);
}

void polyvec_matrix_expand_row3_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  (void)rowb;
  poly_uniform_4x(&rowa->vec[3], &rowa->vec[4], &rowa->vec[5], &rowa->vec[6], rho, 771, 772, 773, 774);
  poly_nttunpack(&rowa->vec[3]);
  poly_nttunpack(&rowa->vec[4]);
  poly_nttunpack(&rowa->vec[5]);
  poly_nttunpack(&rowa->vec[6]);
}

void polyvec_matrix_expand_row4_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 1024, 1025, 1026, 1027);
  poly_uniform_4x(&rowa->vec[4], &rowa->vec[5], &rowa->vec[6], &rowb->vec[0], rho, 1028, 1029, 1030, 1280);
  poly_nttunpack(&rowa->vec[0]);
  poly_nttunpack(&rowa->vec[1]);
  poly_nttunpack(&rowa->vec[2]);
  poly_nttunpack(&rowa->vec[3]);
  poly_nttunpack(&rowa->vec[4]);
  poly_nttunpack(&rowa->vec[5]);
  poly_nttunpack(&rowa->vec[6]);
  poly_nttunpack(&rowb->vec[0]);
}

void polyvec_matrix_expand_row5_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  poly_uniform_4x(&rowa->vec[1], &rowa->vec[2], &rowa->vec[3], &rowa->vec[4], rho, 1281, 1282, 1283, 1284);
  poly_uniform_4x(&rowa->vec[5], &rowa->vec[6], &rowb->vec[0], &rowb->vec[1], rho, 1285, 1286, 1536, 1537);
  poly_nttunpack(&rowa->vec[1]);
  poly_nttunpack(&rowa->vec[2]);
  poly_nttunpack(&rowa->vec[3]);
  poly_nttunpack(&rowa->vec[4]);
  poly_nttunpack(&rowa->vec[5]);
  poly_nttunpack(&rowa->vec[6]);
  poly_nttunpack(&rowb->vec[0]);
  poly_nttunpack(&rowb->vec[1]);
}

void polyvec_matrix_expand_row6_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  poly_uniform_4x(&rowa->vec[2], &rowa->vec[3], &rowa->vec[4], &rowa->vec[5], rho, 1538, 1539, 1540, 1541);
  poly_uniform_4x(&rowa->vec[6], &rowb->vec[0], &rowb->vec[1], &rowb->vec[2], rho, 1542, 1792, 1793, 1794);
  poly_nttunpack(&rowa->vec[2]);
  poly_nttunpack(&rowa->vec[3]);
  poly_nttunpack(&rowa->vec[4]);
  poly_nttunpack(&rowa->vec[5]);
  poly_nttunpack(&rowa->vec[6]);
  poly_nttunpack(&rowb->vec[0]);
  poly_nttunpack(&rowb->vec[1]);
  poly_nttunpack(&rowb->vec[2]);
}

void polyvec_matrix_expand_row7_5(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
  (void)rowb;
  poly_uniform_4x(&rowa->vec[3], &rowa->vec[4], &rowa->vec[5], &rowa->vec[6], rho, 1795, 1796, 1797, 1798);
  poly_nttunpack(&rowa->vec[3]);
  poly_nttunpack(&rowa->vec[4]);
  poly_nttunpack(&rowa->vec[5]);
  poly_nttunpack(&rowa->vec[6]);
}

#else
#error
#endif


/*************************************************
* Name:        polyvecl_pointwise_acc_montgomery
*
* Description: Pointwise multiply vectors of polynomials of length L, multiply
*              resulting vector by 2^{-32} and add (accumulate) polynomials
*              in it. Input/output vectors are in NTT domain representation.
*
* Arguments:   - poly *w: output polynomial
*              - const polyvecl *u: pointer to first input vector
*              - const polyvecl *v: pointer to second input vector
**************************************************/
static
void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u, const polyvecl *v) {
  pointwise_acc_avx(w->vec, u->vec->vec, v->vec->vec, qdata.vec);
}

/*************************************************
* Name:        polyveck_make_hint
*
* Description: Compute hint vector.
*
* Arguments:   - uint8_t *hint: pointer to output hint array
*              - const polyveck *v0: pointer to low part of input vector
*              - const polyveck *v1: pointer to high part of input vector
*
* Returns number of 1 bits.
**************************************************/
unsigned int polyveck_make_hint(uint8_t *hint, const polyveck *v0, const polyveck *v1)
{
  unsigned int i, n = 0;

  for(i = 0; i < K; ++i)
    n += poly_make_hint(&hint[n], &v0->vec[i], &v1->vec[i]);

  return n;
}

/*************** dilithium/avx2/sign.c */

#if K == 4 && L == 4
static inline void polyvec_matrix_expand_row_2(polyvecl **row, polyvecl buf[2], const uint8_t rho[SEEDBYTES], unsigned int i) {
  switch(i) {
    case 0:
      polyvec_matrix_expand_row0_2(buf, buf + 1, rho);
      *row = buf;
      break;
    case 1:
      polyvec_matrix_expand_row1_2(buf + 1, buf, rho);
      *row = buf + 1;
      break;
    case 2:
      polyvec_matrix_expand_row2_2(buf, buf + 1, rho);
      *row = buf;
      break;
    case 3:
      polyvec_matrix_expand_row3_2(buf + 1, buf, rho);
      *row = buf + 1;
      break;
  }
}
#endif
#if K == 6 && L == 5
static inline void polyvec_matrix_expand_row_3(polyvecl **row, polyvecl buf[2], const uint8_t rho[SEEDBYTES], unsigned int i) {
  switch(i) {
    case 0:
      polyvec_matrix_expand_row0_3(buf, buf + 1, rho);
      *row = buf;
      break;
    case 1:
      polyvec_matrix_expand_row1_3(buf + 1, buf, rho);
      *row = buf + 1;
      break;
    case 2:
      polyvec_matrix_expand_row2_3(buf, buf + 1, rho);
      *row = buf;
      break;
    case 3:
      polyvec_matrix_expand_row3_3(buf + 1, buf, rho);
      *row = buf + 1;
      break;
    case 4:
      polyvec_matrix_expand_row4_3(buf, buf + 1, rho);
      *row = buf;
      break;
    case 5:
      polyvec_matrix_expand_row5_3(buf + 1, buf, rho);
      *row = buf + 1;
      break;
  }
}
#endif
#if K == 8 && L == 7
static inline void polyvec_matrix_expand_row_5(polyvecl **row, polyvecl buf[2], const uint8_t rho[SEEDBYTES], unsigned int i) {
  switch(i) {
    case 0:
      polyvec_matrix_expand_row0_5(buf, buf + 1, rho);
      *row = buf;
      break;
    case 1:
      polyvec_matrix_expand_row1_5(buf + 1, buf, rho);
      *row = buf + 1;
      break;
    case 2:
      polyvec_matrix_expand_row2_5(buf, buf + 1, rho);
      *row = buf;
      break;
    case 3:
      polyvec_matrix_expand_row3_5(buf + 1, buf, rho);
      *row = buf + 1;
      break;
    case 4:
      polyvec_matrix_expand_row4_5(buf, buf + 1, rho);
      *row = buf;
      break;
    case 5:
      polyvec_matrix_expand_row5_5(buf + 1, buf, rho);
      *row = buf + 1;
      break;
    case 6:
      polyvec_matrix_expand_row6_5(buf, buf + 1, rho);
      *row = buf;
      break;
    case 7:
      polyvec_matrix_expand_row7_5(buf + 1, buf, rho);
      *row = buf + 1;
      break;
  }
}
#endif

/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
#ifndef DILITHIUM_INTERNAL_API_ONLY
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
  unsigned int i;
  uint8_t seedbuf[2*SEEDBYTES + CRHBYTES];
  const uint8_t *rho, *rhoprime, *key;
  polyvecl rowbuf[2];
  polyvecl s1, *row = rowbuf;
  polyveck s2;
  poly t1, t0;
  size_t i;

  /* Get randomness for rho, rhoprime and key */
  randombytes(seedbuf, SEEDBYTES);
  seedbuf[SEEDBYTES+0] = K;
  seedbuf[SEEDBYTES+1] = L;
  shake256(seedbuf, 2*SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES+2);
  rho = seedbuf;
  rhoprime = rho + SEEDBYTES;
  key = rhoprime + CRHBYTES;

  /* Store rho, key */
  memcpy(pk, rho, SEEDBYTES);
  memcpy(sk, rho, SEEDBYTES);
  memcpy(sk + SEEDBYTES, key, SEEDBYTES);

  /* Sample short vectors s1 and s2 */
#if K == 4 && L == 4
  poly_uniform_eta_4x(&s1.vec[0], &s1.vec[1], &s1.vec[2], &s1.vec[3], rhoprime, 0, 1, 2, 3);
  poly_uniform_eta_4x(&s2.vec[0], &s2.vec[1], &s2.vec[2], &s2.vec[3], rhoprime, 4, 5, 6, 7);
#elif K == 6 && L == 5
  poly_uniform_eta_4x(&s1.vec[0], &s1.vec[1], &s1.vec[2], &s1.vec[3], rhoprime, 0, 1, 2, 3);
  poly_uniform_eta_4x(&s1.vec[4], &s2.vec[0], &s2.vec[1], &s2.vec[2], rhoprime, 4, 5, 6, 7);
  poly_uniform_eta_4x(&s2.vec[3], &s2.vec[4], &s2.vec[5], &t0, rhoprime, 8, 9, 10, 11);
#elif K == 8 && L == 7
  poly_uniform_eta_4x(&s1.vec[0], &s1.vec[1], &s1.vec[2], &s1.vec[3], rhoprime, 0, 1, 2, 3);
  poly_uniform_eta_4x(&s1.vec[4], &s1.vec[5], &s1.vec[6], &s2.vec[0], rhoprime, 4, 5, 6, 7);
  poly_uniform_eta_4x(&s2.vec[1], &s2.vec[2], &s2.vec[3], &s2.vec[4], rhoprime, 8, 9, 10, 11);
  poly_uniform_eta_4x(&s2.vec[5], &s2.vec[6], &s2.vec[7], &t0, rhoprime, 12, 13, 14, 15);
#else
#error
#endif

  /* Pack secret vectors */
  for(i = 0; i < L; i++)
    polyeta_pack(sk + 2*SEEDBYTES + TRBYTES + i*POLYETA_PACKEDBYTES, &s1.vec[i]);
  for(i = 0; i < K; i++)
    polyeta_pack(sk + 2*SEEDBYTES + TRBYTES + (L + i)*POLYETA_PACKEDBYTES, &s2.vec[i]);

  /* Transform s1 */
  polyvecl_ntt(&s1);

  for(i = 0; i < K; i++) {
    /* Expand matrix row */
    polyvec_matrix_expand_row(&row, rowbuf, rho, i);

    /* Compute inner-product */
    polyvecl_pointwise_acc_montgomery(&t1, row, &s1);
    poly_invntt_tomont(&t1);

    /* Add error polynomial */
    poly_add(&t1, &t1, &s2.vec[i]);

    /* Round t and pack t1, t0 */
    poly_caddq(&t1);
    poly_power2round(&t1, &t0, &t1);
    polyt1_pack(pk + SEEDBYTES + i*POLYT1_PACKEDBYTES, &t1);
    polyt0_pack(sk + 2*SEEDBYTES + TRBYTES + (L+K)*POLYETA_PACKEDBYTES + i*POLYT0_PACKEDBYTES, &t0);
  }

  /* Compute H(rho, t1) and store in secret key */
  shake256(sk + 2*SEEDBYTES, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);

  return 0;
}
#else
int crypto_sign_keypair_internal(uint8_t *pk, uint8_t *sk,
                                 const uint8_t seed[SEEDBYTES])
{
  unsigned int i;
  uint8_t seedbuf[2*SEEDBYTES + CRHBYTES];
  const uint8_t *rho, *rhoprime, *key;
  polyvecl rowbuf[2];
  polyvecl s1, *row = rowbuf;
  polyveck s2;
  poly t1, t0;

  /* Get randomness for rho, rhoprime and key */
  for (i = 0; i < SEEDBYTES; i++)
    seedbuf[i] = seed[i];
  seedbuf[SEEDBYTES+0] = K;
  seedbuf[SEEDBYTES+1] = L;
  shake256(seedbuf, 2*SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES+2);
  rho = seedbuf;
  rhoprime = rho + SEEDBYTES;
  key = rhoprime + CRHBYTES;

  /* Store rho, key */
  memcpy(pk, rho, SEEDBYTES);
  memcpy(sk, rho, SEEDBYTES);
  memcpy(sk + SEEDBYTES, key, SEEDBYTES);

  /* Sample short vectors s1 and s2 */
#if K == 4 && L == 4
  poly_uniform_eta_4x_2(&s1.vec[0], &s1.vec[1], &s1.vec[2], &s1.vec[3], rhoprime, 0, 1, 2, 3);
  poly_uniform_eta_4x_2(&s2.vec[0], &s2.vec[1], &s2.vec[2], &s2.vec[3], rhoprime, 4, 5, 6, 7);
#elif K == 6 && L == 5
  poly_uniform_eta_4x_4(&s1.vec[0], &s1.vec[1], &s1.vec[2], &s1.vec[3], rhoprime, 0, 1, 2, 3);
  poly_uniform_eta_4x_4(&s1.vec[4], &s2.vec[0], &s2.vec[1], &s2.vec[2], rhoprime, 4, 5, 6, 7);
  poly_uniform_eta_4x_4(&s2.vec[3], &s2.vec[4], &s2.vec[5], &t0, rhoprime, 8, 9, 10, 11);
#elif K == 8 && L == 7
  poly_uniform_eta_4x_2(&s1.vec[0], &s1.vec[1], &s1.vec[2], &s1.vec[3], rhoprime, 0, 1, 2, 3);
  poly_uniform_eta_4x_2(&s1.vec[4], &s1.vec[5], &s1.vec[6], &s2.vec[0], rhoprime, 4, 5, 6, 7);
  poly_uniform_eta_4x_2(&s2.vec[1], &s2.vec[2], &s2.vec[3], &s2.vec[4], rhoprime, 8, 9, 10, 11);
  poly_uniform_eta_4x_2(&s2.vec[5], &s2.vec[6], &s2.vec[7], &t0, rhoprime, 12, 13, 14, 15);
#else
#error
#endif

  /* Pack secret vectors */
  for(i = 0; i < L; i++)
    polyeta_pack(sk + 2*SEEDBYTES + TRBYTES + i*POLYETA_PACKEDBYTES, &s1.vec[i]);
  for(i = 0; i < K; i++)
    polyeta_pack(sk + 2*SEEDBYTES + TRBYTES + (L + i)*POLYETA_PACKEDBYTES, &s2.vec[i]);

  /* Transform s1 */
  polyvecl_ntt(&s1);

  for(i = 0; i < K; i++) {
    /* Expand matrix row */
    polyvec_matrix_expand_row(&row, rowbuf, rho, i);

    /* Compute inner-product */
    polyvecl_pointwise_acc_montgomery(&t1, row, &s1);
    poly_invntt_tomont(&t1);

    /* Add error polynomial */
    poly_add(&t1, &t1, &s2.vec[i]);

    /* Round t and pack t1, t0 */
    poly_caddq(&t1);
    poly_power2round(&t1, &t0, &t1);
    polyt1_pack(pk + SEEDBYTES + i*POLYT1_PACKEDBYTES, &t1);
    polyt0_pack(sk + 2*SEEDBYTES + TRBYTES + (L+K)*POLYETA_PACKEDBYTES + i*POLYT0_PACKEDBYTES, &t0);
  }

  /* Compute H(rho, t1) and store in secret key */
  shake256(sk + 2*SEEDBYTES, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);

  return 0;
}

#endif

/*************************************************
* Name:        crypto_sign_signature_internal
*
* Description: Computes signature. Internal API.
*
* Arguments:   - uint8_t *sig: pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - uint8_t *pre: pointer to prefix string
*              - size_t prelen: length of prefix string
*              - uint8_t *rnd: pointer to random seed
*              - uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign_signature_internal(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                   const uint8_t *pre, size_t prelen, const uint8_t rnd[RNDBYTES], const uint8_t *sk)
{
  unsigned int i, n, pos;
  uint8_t seedbuf[2*SEEDBYTES + TRBYTES + 2*CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint8_t hintbuf[N];
  uint8_t *hint = sig + CTILDEBYTES + L*POLYZ_PACKEDBYTES;
  uint64_t nonce = 0;
  polyvecl mat[K], s1, z;
  polyveck t0, s2, w1;
  poly c, tmp;
  union {
    polyvecl y;
    polyveck w0;
  } tmpv;
  keccak_state state;

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + TRBYTES;
  mu = key + SEEDBYTES;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute mu = CRH(tr, pre, msg) */
  shake256_init(&state);
  shake256_absorb(&state, tr, TRBYTES);
  shake256_absorb(&state, pre, prelen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Compute rhoprime = CRH(key, rnd, mu) */
  shake256_init(&state);
  shake256_absorb(&state, key, SEEDBYTES);
  shake256_absorb(&state, rnd, RNDBYTES);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_finalize(&state);
  shake256_squeeze(rhoprime, CRHBYTES, &state);

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

rej:
  /* Sample intermediate vector y */
#if L == 4
  poly_uniform_gamma1_4x_17(&z.vec[0], &z.vec[1], &z.vec[2], &z.vec[3],
                            rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3);
  nonce += 4;
#elif L == 5
  poly_uniform_gamma1_4x_19(&z.vec[0], &z.vec[1], &z.vec[2], &z.vec[3],
                            rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3);
  poly_uniform_gamma1_19(&z.vec[4], rhoprime, nonce + 4);
  nonce += 5;
#elif L == 7
  poly_uniform_gamma1_4x_19(&z.vec[0], &z.vec[1], &z.vec[2], &z.vec[3],
                            rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3);
  poly_uniform_gamma1_4x_19(&z.vec[4], &z.vec[5], &z.vec[6], &tmp,
                            rhoprime, nonce + 4, nonce + 5, nonce + 6, 0);
  nonce += 7;
#else
#error
#endif

  /* Matrix-vector product */
  tmpv.y = z;
  polyvecl_ntt(&tmpv.y);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &tmpv.y);
  polyveck_invntt_tomont(&w1);

  /* Decompose w and call the random oracle */
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &tmpv.w0, &w1);
  polyveck_pack_w1(sig, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, CTILDEBYTES, &state);
  poly_challenge(&c, sig);
  poly_ntt(&c);

  /* Compute z, reject if it reveals secret */
  for(i = 0; i < L; i++) {
    poly_pointwise_montgomery(&tmp, &c, &s1.vec[i]);
    poly_invntt_tomont(&tmp);
    poly_add(&z.vec[i], &z.vec[i], &tmp);
    poly_reduce(&z.vec[i]);
    if(poly_chknorm(&z.vec[i], GAMMA1 - BETA))
      goto rej;
  }

  /* Zero hint vector in signature */
  pos = 0;
  memset(hint, 0, OMEGA);

  for(i = 0; i < K; i++) {
    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    poly_pointwise_montgomery(&tmp, &c, &s2.vec[i]);
    poly_invntt_tomont(&tmp);
    poly_sub(&tmpv.w0.vec[i], &tmpv.w0.vec[i], &tmp);
    poly_reduce(&tmpv.w0.vec[i]);
    if(poly_chknorm(&tmpv.w0.vec[i], GAMMA2 - BETA))
      goto rej;

    /* Compute hints */
    poly_pointwise_montgomery(&tmp, &c, &t0.vec[i]);
    poly_invntt_tomont(&tmp);
    poly_reduce(&tmp);
    if(poly_chknorm(&tmp, GAMMA2))
      goto rej;

    poly_add(&tmpv.w0.vec[i], &tmpv.w0.vec[i], &tmp);
    n = poly_make_hint(hintbuf, &tmpv.w0.vec[i], &w1.vec[i]);
    if(pos + n > OMEGA)
      goto rej;

    /* Store hints in signature */
    memcpy(&hint[pos], hintbuf, n);
    hint[OMEGA + i] = pos = pos + n;
  }

  /* Pack z into signature */
  for(i = 0; i < L; i++)
    polyz_pack(sig + CTILDEBYTES + i*POLYZ_PACKEDBYTES, &z.vec[i]);

  *siglen = CRYPTO_BYTES;
  return 0;
}

/*************************************************
* Name:        crypto_sign_verify_internal
*
* Description: Verifies signature. Internal API.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pre: pointer to prefix string
*              - size_t prelen: length of prefix string
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_verify_internal(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                const uint8_t *pre, size_t prelen, const uint8_t *pk) {
  unsigned int i, j, pos = 0;
  /* polyw1_pack writes additional 14 bytes */
  ALIGNED_UINT8(K*POLYW1_PACKEDBYTES+14) buf;
  uint8_t mu[CRHBYTES];
  const uint8_t *hint = sig + CTILDEBYTES + L*POLYZ_PACKEDBYTES;
  polyvecl rowbuf[2];
  polyvecl *row = rowbuf;
  polyvecl z;
  poly c, w1, h;
  keccak_state state;

  if(siglen != CRYPTO_BYTES)
    return -1;

  /* Compute CRH(H(rho, t1), pre, msg) */
  shake256(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, pre, prelen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Expand challenge */
  poly_challenge(&c, sig);
  poly_ntt(&c);

  /* Unpack z; shortness follows from unpacking */
  for(i = 0; i < L; i++) {
    polyz_unpack(&z.vec[i], sig + CTILDEBYTES + i*POLYZ_PACKEDBYTES);
    poly_ntt(&z.vec[i]);
  }

  for(i = 0; i < K; i++) {
    /* Expand matrix row */
    polyvec_matrix_expand_row(&row, rowbuf, pk, i);

    /* Compute i-th row of Az - c2^Dt1 */
    polyvecl_pointwise_acc_montgomery(&w1, row, &z);

    polyt1_unpack(&h, pk + SEEDBYTES + i*POLYT1_PACKEDBYTES);
    poly_shiftl(&h);
    poly_ntt(&h);
    poly_pointwise_montgomery(&h, &c, &h);

    poly_sub(&w1, &w1, &h);
    poly_reduce(&w1);
    poly_invntt_tomont(&w1);

    /* Get hint polynomial and reconstruct w1 */
    memset(h.vec, 0, sizeof(poly));
    if(hint[OMEGA + i] < pos || hint[OMEGA + i] > OMEGA)
      return -1;

    for(j = pos; j < hint[OMEGA + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if(j > pos && hint[j] <= hint[j-1]) return -1;
      h.coeffs[hint[j]] = 1;
    }
    pos = hint[OMEGA + i];

    poly_caddq(&w1);
    poly_use_hint(&w1, &w1, &h);
    polyw1_pack(buf.coeffs + i*POLYW1_PACKEDBYTES, &w1);
  }

  /* Extra indices are zero for strong unforgeability */
  for(j = pos; j < OMEGA; ++j)
    if(hint[j]) return -1;

  /* Call random oracle and verify challenge */
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, buf.coeffs, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(buf.coeffs, CTILDEBYTES, &state);
  for(i = 0; i < CTILDEBYTES; ++i)
    if(buf.coeffs[i] != sig[i])
      return -1;

  return 0;
}

# undef polyvec_matrix_expand_row
