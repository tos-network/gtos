#ifndef HEADER_at_src_crypto_ed25519_avx2_at_r2526x10_h
#define HEADER_at_src_crypto_ed25519_avx2_at_r2526x10_h

/* AVX2 field arithmetic for GF(2^255-19) using radix-2^25.5 representation.

   This implementation processes 4 field elements in parallel using AVX2
   SIMD instructions. The representation uses 10 limbs with alternating
   26/25 bit sizes (radix 2^25.5).

   Limb layout: [26, 25, 26, 25, 26, 25, 26, 25, 26, 25] bits
   Total: 26*5 + 25*5 = 130 + 125 = 255 bits

   Each __m256i vector holds 4 corresponding limbs from 4 different field
   elements. This enables SIMD parallelism across 4 elements.

   Memory layout:
     limb[0]: [elem0_limb0, elem1_limb0, elem2_limb0, elem3_limb0]
     limb[1]: [elem0_limb1, elem1_limb1, elem2_limb1, elem3_limb1]
     ...
     limb[9]: [elem0_limb9, elem1_limb9, elem2_limb9, elem3_limb9] */

#if AT_HAS_AVX

#include "at/infra/simd/at_avx.h"
#include "at/crypto/at_crypto_base.h"

/* Constants for the reduced radix representation */
#define AT_R2526X10_BASE0 26  /* Limbs 0, 2, 4, 6, 8 have 26 bits */
#define AT_R2526X10_BASE1 25  /* Limbs 1, 3, 5, 7, 9 have 25 bits */
#define AT_R2526X10_NUM_LIMBS 10

/* Masks for the limb sizes */
#define AT_R2526X10_MASK26 ((1UL << 26) - 1)  /* 0x3FFFFFF */
#define AT_R2526X10_MASK25 ((1UL << 25) - 1)  /* 0x1FFFFFF */

/* Reduction factor: 2^255 mod p = 19 */
#define AT_R2526X10_TIMES19 19UL

/* A at_r2526x10_t represents 4 GF(p) elements in parallel, where p = 2^255-19,
   using a reduced radix representation with alternating 26/25 bit limbs.

   Each limb[i] holds 4 corresponding limbs from 4 different field elements.
   This is the "interleaved" or "zipped" representation for SIMD processing. */
typedef struct at_r2526x10 {
  wv_t limb[AT_R2526X10_NUM_LIMBS];  /* 10 __m256i vectors */
} at_r2526x10_t;

AT_PROTOTYPES_BEGIN

/* ========================================================================
   Constants
   ======================================================================== */

/* 2P constants for subtraction bias (to avoid negative numbers).
   Pattern: even limbs are 26-bit, odd limbs are 25-bit.
   limb[0]: 2*(2^26 - 19) = 0x7FFFFDA (special for -19)
   limb[even]: 2*(2^26 - 1) = 0x7FFFFFE for 26-bit limbs
   limb[odd]:  2*(2^25 - 1) = 0x3FFFFFE for 25-bit limbs */
static const ulong AT_R2526X10_2P[AT_R2526X10_NUM_LIMBS] = {
  0x7FFFFDA,  /* limb 0: 26-bit, -19 adjust */
  0x3FFFFFE,  /* limb 1: 25-bit */
  0x7FFFFFE,  /* limb 2: 26-bit */
  0x3FFFFFE,  /* limb 3: 25-bit */
  0x7FFFFFE,  /* limb 4: 26-bit */
  0x3FFFFFE,  /* limb 5: 25-bit */
  0x7FFFFFE,  /* limb 6: 26-bit */
  0x3FFFFFE,  /* limb 7: 25-bit */
  0x7FFFFFE,  /* limb 8: 26-bit */
  0x3FFFFFE   /* limb 9: 25-bit */
};

/* ========================================================================
   Basic Operations
   ======================================================================== */

/* at_r2526x10_zero returns a vector of 4 zero field elements. */
static inline at_r2526x10_t
at_r2526x10_zero( void ) {
  at_r2526x10_t r;
  wv_t z = wv_zero();
  for( int i = 0; i < AT_R2526X10_NUM_LIMBS; i++ ) {
    r.limb[i] = z;
  }
  return r;
}

/* at_r2526x10_copy copies src to dst. */
static inline void
at_r2526x10_copy( at_r2526x10_t *       dst,
                  at_r2526x10_t const * src ) {
  for( int i = 0; i < AT_R2526X10_NUM_LIMBS; i++ ) {
    dst->limb[i] = src->limb[i];
  }
}

/* ========================================================================
   Addition and Subtraction
   ======================================================================== */

/* at_r2526x10_add computes c = a + b (element-wise for 4 elements).
   Does NOT reduce the result. */
static inline at_r2526x10_t
at_r2526x10_add( at_r2526x10_t const * a,
                 at_r2526x10_t const * b ) {
  at_r2526x10_t c;
  for( int i = 0; i < AT_R2526X10_NUM_LIMBS; i++ ) {
    c.limb[i] = wv_add( a->limb[i], b->limb[i] );
  }
  return c;
}

/* at_r2526x10_sub computes c = a - b (element-wise for 4 elements).
   Uses 2P bias to avoid negative numbers. Does NOT reduce the result. */
static inline at_r2526x10_t
at_r2526x10_sub( at_r2526x10_t const * a,
                 at_r2526x10_t const * b ) {
  at_r2526x10_t c;
  for( int i = 0; i < AT_R2526X10_NUM_LIMBS; i++ ) {
    wv_t p2 = wv_bcast( AT_R2526X10_2P[i] );
    c.limb[i] = wv_add( a->limb[i], wv_sub( p2, b->limb[i] ) );
  }
  return c;
}

/* at_r2526x10_neg computes c = -a (element-wise for 4 elements).
   Uses 2P bias. */
static inline at_r2526x10_t
at_r2526x10_neg( at_r2526x10_t const * a ) {
  at_r2526x10_t c;
  for( int i = 0; i < AT_R2526X10_NUM_LIMBS; i++ ) {
    wv_t p2 = wv_bcast( AT_R2526X10_2P[i] );
    c.limb[i] = wv_sub( p2, a->limb[i] );
  }
  return c;
}

/* ========================================================================
   Carry Propagation / Compression
   ======================================================================== */

/* at_r2526x10_compress performs carry propagation to reduce limbs back
   to their proper bit ranges. This is needed after multiplication.

   After compression:
     - Even limbs (0,2,4,6,8) are in [0, 2^26)
     - Odd limbs (1,3,5,7,9) are in [0, 2^25)
   with possible overflow into the next limb. */
static inline at_r2526x10_t
at_r2526x10_compress( at_r2526x10_t const * a ) {
  wv_t const mask26 = wv_bcast( AT_R2526X10_MASK26 );
  wv_t const mask25 = wv_bcast( AT_R2526X10_MASK25 );

  /* Load limbs */
  wv_t c0 = a->limb[0];
  wv_t c1 = a->limb[1];
  wv_t c2 = a->limb[2];
  wv_t c3 = a->limb[3];
  wv_t c4 = a->limb[4];
  wv_t c5 = a->limb[5];
  wv_t c6 = a->limb[6];
  wv_t c7 = a->limb[7];
  wv_t c8 = a->limb[8];
  wv_t c9 = a->limb[9];

  wv_t h;

  /* Carry propagation: c0 -> c1 -> c2 -> ... -> c9 -> c0 */
  h = wv_shr( c0, AT_R2526X10_BASE0 );
  c0 = wv_and( c0, mask26 );
  c1 = wv_add( c1, h );

  h = wv_shr( c1, AT_R2526X10_BASE1 );
  c1 = wv_and( c1, mask25 );
  c2 = wv_add( c2, h );

  h = wv_shr( c2, AT_R2526X10_BASE0 );
  c2 = wv_and( c2, mask26 );
  c3 = wv_add( c3, h );

  h = wv_shr( c3, AT_R2526X10_BASE1 );
  c3 = wv_and( c3, mask25 );
  c4 = wv_add( c4, h );

  h = wv_shr( c4, AT_R2526X10_BASE0 );
  c4 = wv_and( c4, mask26 );
  c5 = wv_add( c5, h );

  h = wv_shr( c5, AT_R2526X10_BASE1 );
  c5 = wv_and( c5, mask25 );
  c6 = wv_add( c6, h );

  h = wv_shr( c6, AT_R2526X10_BASE0 );
  c6 = wv_and( c6, mask26 );
  c7 = wv_add( c7, h );

  h = wv_shr( c7, AT_R2526X10_BASE1 );
  c7 = wv_and( c7, mask25 );
  c8 = wv_add( c8, h );

  h = wv_shr( c8, AT_R2526X10_BASE0 );
  c8 = wv_and( c8, mask26 );
  c9 = wv_add( c9, h );

  /* Final carry from c9 wraps around to c0 with factor 19 */
  h = wv_shr( c9, AT_R2526X10_BASE1 );
  c9 = wv_and( c9, mask25 );
  /* c0 += 19 * h using shift-and-add: 19 = 16 + 2 + 1 */
  c0 = wv_add( c0, wv_add( wv_add( wv_shl( h, 4 ), wv_shl( h, 1 ) ), h ) );

  /* One more carry from c0 to c1 */
  h = wv_shr( c0, AT_R2526X10_BASE0 );
  c0 = wv_and( c0, mask26 );
  c1 = wv_add( c1, h );

  /* Store results */
  at_r2526x10_t r;
  r.limb[0] = c0;
  r.limb[1] = c1;
  r.limb[2] = c2;
  r.limb[3] = c3;
  r.limb[4] = c4;
  r.limb[5] = c5;
  r.limb[6] = c6;
  r.limb[7] = c7;
  r.limb[8] = c8;
  r.limb[9] = c9;
  return r;
}

/* ========================================================================
   Multiplication (Schoolbook)
   ======================================================================== */

/* at_r2526x10_intmul computes c = a * b using schoolbook multiplication.
   Result is NOT reduced - use compress() after. */
void
at_r2526x10_intmul( at_r2526x10_t *       c,
                    at_r2526x10_t const * a,
                    at_r2526x10_t const * b );

/* at_r2526x10_mul computes c = a * b with compression. */
static inline at_r2526x10_t
at_r2526x10_mul( at_r2526x10_t const * a,
                 at_r2526x10_t const * b ) {
  at_r2526x10_t c;
  at_r2526x10_intmul( &c, a, b );
  return at_r2526x10_compress( &c );
}

/* ========================================================================
   Squaring
   ======================================================================== */

/* at_r2526x10_intsqr computes c = a^2 using optimized squaring.
   Result is NOT reduced - use compress() after. */
void
at_r2526x10_intsqr( at_r2526x10_t *       c,
                    at_r2526x10_t const * a );

/* at_r2526x10_sqr computes c = a^2 with compression. */
static inline at_r2526x10_t
at_r2526x10_sqr( at_r2526x10_t const * a ) {
  at_r2526x10_t c;
  at_r2526x10_intsqr( &c, a );
  return at_r2526x10_compress( &c );
}

/* ========================================================================
   Pack/Unpack (Zip/Unzip) Operations
   ======================================================================== */

/* Forward declarations for scalar type - defined in at_f25519.h */
struct at_f25519;
typedef struct at_f25519 at_f25519_scalar_t;

/* at_r2526x10_zip packs 4 scalar field elements into SIMD form. */
void
at_r2526x10_zip( at_r2526x10_t *             out,
                 at_f25519_scalar_t const *  a,
                 at_f25519_scalar_t const *  b,
                 at_f25519_scalar_t const *  c,
                 at_f25519_scalar_t const *  d );

/* at_r2526x10_unzip unpacks SIMD form back to 4 scalar field elements. */
void
at_r2526x10_unzip( at_f25519_scalar_t *       a,
                   at_f25519_scalar_t *       b,
                   at_f25519_scalar_t *       c,
                   at_f25519_scalar_t *       d,
                   at_r2526x10_t const *      in );

AT_PROTOTYPES_END

#endif /* AT_HAS_AVX2 */

#endif /* HEADER_at_src_crypto_ed25519_avx2_at_r2526x10_h */
