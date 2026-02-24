/* AVX-512F field arithmetic implementation for GF(2^255-19).

   This implements 8-way parallel field multiplication and squaring using
   the schoolbook algorithm with radix-2^25.5 representation.

   This is the AVX-512F (non-IFMA) implementation that scales up the AVX2
   algorithm from 4-way to 8-way parallelism using wwl_t (__m512i) instead
   of wv_t (__m256i).

   Target CPUs: Skylake-X, Cascade Lake (AVX-512F without IFMA) */

#include "at/crypto/at_crypto_base.h"
#include <stdint.h>

#if AT_HAS_AVX512_GENERAL

#include "at_f25519.h"  /* For at_f25519_t */
#include "at_r2526x8.h"

/* Field constant storage (initialized by at_ed25519_avx512_general_init_constants) */
at_f25519_t at_f25519_d_storage[1] = {{0}};
at_f25519_t at_f25519_sqrtm1_storage[1] = {{0}};
at_f25519_t at_f25519_k_storage[1] = {{0}};
at_f25519_t at_f25519_minus_k_storage[1] = {{0}};
at_f25519_t at_f25519_nine_storage[1] = {{0}};

/* Ristretto constant storage */
at_f25519_t at_f25519_invsqrt_a_minus_d_storage[1] = {{0}};
at_f25519_t at_f25519_one_minus_d_sq_storage[1] = {{0}};
at_f25519_t at_f25519_d_minus_one_sq_storage[1] = {{0}};
at_f25519_t at_f25519_sqrt_ad_minus_one_storage[1] = {{0}};

/* Initialization flag */
int at_ed25519_avx512_general_constants_initialized = 0;

/* Curve constant storage (initialized by at_ed25519_avx512_general_init_curve_constants).
   Must be defined here (not in header) to ensure single instance across TUs. */
struct at_curve25519_edwards {
  at_f25519_t X[1];
  at_f25519_t Y[1];
  at_f25519_t T[1];
  at_f25519_t Z[1];
};
typedef struct at_curve25519_edwards at_ed25519_point_t;

at_ed25519_point_t at_ed25519_base_point_storage[1];
at_f25519_t at_ed25519_order8_point_y0_storage[1];
at_f25519_t at_ed25519_order8_point_y1_storage[1];
int at_ed25519_avx512_general_curve_constants_initialized = 0;

/* ========================================================================
   Schoolbook Multiplication
   ========================================================================

   For multiplication a * b where both have 10 limbs:
   - Each product a[i] * b[j] contributes to limb (i+j) mod 10
   - Products where i+j >= 10 are multiplied by 19 (reduction factor)
   - For alternating radix, we need to double coefficients when both
     limbs are odd-indexed (25-bit) to compensate for the radix difference

   The multiplication follows the pattern:
     c[k] = sum over all (i,j) where (i+j) mod 10 == k of:
            coefficient * a[i] * b[j]
   where coefficient is:
     - 19 if (i+j) >= 10
     - 2 if both i and j are odd (compensating for 25-bit limbs)
     - 1 otherwise

   Key difference from AVX2: Uses wwl_mul_ll (_mm512_mul_epu32) for
   8-way parallel 32x32->64 bit multiplication. */

void
at_r2526x8_intmul( at_r2526x8_t *       c,
                    at_r2526x8_t const * a,
                    at_r2526x8_t const * b ) {
  wwl_t const times19 = wwl_bcast( (long)AT_R2526X8_TIMES19 );

  /* Load b limbs */
  wwl_t b0 = b->limb[0];
  wwl_t b1 = b->limb[1];
  wwl_t b2 = b->limb[2];
  wwl_t b3 = b->limb[3];
  wwl_t b4 = b->limb[4];
  wwl_t b5 = b->limb[5];
  wwl_t b6 = b->limb[6];
  wwl_t b7 = b->limb[7];
  wwl_t b8 = b->limb[8];
  wwl_t b9 = b->limb[9];

  /* Pre-compute 19 * b[j] for reduction */
  wwl_t d1 = wwl_mul_ll( b1, times19 );
  wwl_t d2 = wwl_mul_ll( b2, times19 );
  wwl_t d3 = wwl_mul_ll( b3, times19 );
  wwl_t d4 = wwl_mul_ll( b4, times19 );
  wwl_t d5 = wwl_mul_ll( b5, times19 );
  wwl_t d6 = wwl_mul_ll( b6, times19 );
  wwl_t d7 = wwl_mul_ll( b7, times19 );
  wwl_t d8 = wwl_mul_ll( b8, times19 );
  wwl_t d9 = wwl_mul_ll( b9, times19 );

  /* Accumulators for result limbs */
  wwl_t c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;

  wwl_t ai, a2i;

  /* a[0] contributions (even limb) */
  ai = a->limb[0];
  c0 = wwl_mul_ll( ai, b0 );
  c1 = wwl_mul_ll( ai, b1 );
  c2 = wwl_mul_ll( ai, b2 );
  c3 = wwl_mul_ll( ai, b3 );
  c4 = wwl_mul_ll( ai, b4 );
  c5 = wwl_mul_ll( ai, b5 );
  c6 = wwl_mul_ll( ai, b6 );
  c7 = wwl_mul_ll( ai, b7 );
  c8 = wwl_mul_ll( ai, b8 );
  c9 = wwl_mul_ll( ai, b9 );

  /* a[1] contributions (odd limb - double when paired with odd b) */
  ai = a->limb[1];
  a2i = wwl_add( ai, ai );  /* 2 * a[1] for pairing with odd b indices */
  c1 = wwl_add( c1, wwl_mul_ll( ai, b0 ) );   /* 1+0=1 */
  c2 = wwl_add( c2, wwl_mul_ll( a2i, b1 ) );  /* 1+1=2, doubled (odd+odd) */
  c3 = wwl_add( c3, wwl_mul_ll( ai, b2 ) );   /* 1+2=3 */
  c4 = wwl_add( c4, wwl_mul_ll( a2i, b3 ) );  /* 1+3=4, doubled */
  c5 = wwl_add( c5, wwl_mul_ll( ai, b4 ) );   /* 1+4=5 */
  c6 = wwl_add( c6, wwl_mul_ll( a2i, b5 ) );  /* 1+5=6, doubled */
  c7 = wwl_add( c7, wwl_mul_ll( ai, b6 ) );   /* 1+6=7 */
  c8 = wwl_add( c8, wwl_mul_ll( a2i, b7 ) );  /* 1+7=8, doubled */
  c9 = wwl_add( c9, wwl_mul_ll( ai, b8 ) );   /* 1+8=9 */
  c0 = wwl_add( c0, wwl_mul_ll( a2i, d9 ) );  /* 1+9=10 mod 10=0, *19, doubled */

  /* a[2] contributions (even limb) */
  ai = a->limb[2];
  c2 = wwl_add( c2, wwl_mul_ll( ai, b0 ) );
  c3 = wwl_add( c3, wwl_mul_ll( ai, b1 ) );
  c4 = wwl_add( c4, wwl_mul_ll( ai, b2 ) );
  c5 = wwl_add( c5, wwl_mul_ll( ai, b3 ) );
  c6 = wwl_add( c6, wwl_mul_ll( ai, b4 ) );
  c7 = wwl_add( c7, wwl_mul_ll( ai, b5 ) );
  c8 = wwl_add( c8, wwl_mul_ll( ai, b6 ) );
  c9 = wwl_add( c9, wwl_mul_ll( ai, b7 ) );
  c0 = wwl_add( c0, wwl_mul_ll( ai, d8 ) );   /* 2+8=10, *19 */
  c1 = wwl_add( c1, wwl_mul_ll( ai, d9 ) );   /* 2+9=11, *19 */

  /* a[3] contributions (odd limb) */
  ai = a->limb[3];
  a2i = wwl_add( ai, ai );
  c3 = wwl_add( c3, wwl_mul_ll( ai, b0 ) );
  c4 = wwl_add( c4, wwl_mul_ll( a2i, b1 ) );  /* both odd */
  c5 = wwl_add( c5, wwl_mul_ll( ai, b2 ) );
  c6 = wwl_add( c6, wwl_mul_ll( a2i, b3 ) );  /* both odd */
  c7 = wwl_add( c7, wwl_mul_ll( ai, b4 ) );
  c8 = wwl_add( c8, wwl_mul_ll( a2i, b5 ) );  /* both odd */
  c9 = wwl_add( c9, wwl_mul_ll( ai, b6 ) );
  c0 = wwl_add( c0, wwl_mul_ll( a2i, d7 ) );  /* 3+7=10, *19, both odd */
  c1 = wwl_add( c1, wwl_mul_ll( ai, d8 ) );
  c2 = wwl_add( c2, wwl_mul_ll( a2i, d9 ) );  /* both odd */

  /* a[4] contributions (even limb) */
  ai = a->limb[4];
  c4 = wwl_add( c4, wwl_mul_ll( ai, b0 ) );
  c5 = wwl_add( c5, wwl_mul_ll( ai, b1 ) );
  c6 = wwl_add( c6, wwl_mul_ll( ai, b2 ) );
  c7 = wwl_add( c7, wwl_mul_ll( ai, b3 ) );
  c8 = wwl_add( c8, wwl_mul_ll( ai, b4 ) );
  c9 = wwl_add( c9, wwl_mul_ll( ai, b5 ) );
  c0 = wwl_add( c0, wwl_mul_ll( ai, d6 ) );   /* 4+6=10, *19 */
  c1 = wwl_add( c1, wwl_mul_ll( ai, d7 ) );
  c2 = wwl_add( c2, wwl_mul_ll( ai, d8 ) );
  c3 = wwl_add( c3, wwl_mul_ll( ai, d9 ) );

  /* a[5] contributions (odd limb) */
  ai = a->limb[5];
  a2i = wwl_add( ai, ai );
  c5 = wwl_add( c5, wwl_mul_ll( ai, b0 ) );
  c6 = wwl_add( c6, wwl_mul_ll( a2i, b1 ) );  /* both odd */
  c7 = wwl_add( c7, wwl_mul_ll( ai, b2 ) );
  c8 = wwl_add( c8, wwl_mul_ll( a2i, b3 ) );  /* both odd */
  c9 = wwl_add( c9, wwl_mul_ll( ai, b4 ) );
  c0 = wwl_add( c0, wwl_mul_ll( a2i, d5 ) );  /* 5+5=10, *19, both odd */
  c1 = wwl_add( c1, wwl_mul_ll( ai, d6 ) );
  c2 = wwl_add( c2, wwl_mul_ll( a2i, d7 ) );  /* both odd */
  c3 = wwl_add( c3, wwl_mul_ll( ai, d8 ) );
  c4 = wwl_add( c4, wwl_mul_ll( a2i, d9 ) );  /* both odd */

  /* a[6] contributions (even limb) */
  ai = a->limb[6];
  c6 = wwl_add( c6, wwl_mul_ll( ai, b0 ) );
  c7 = wwl_add( c7, wwl_mul_ll( ai, b1 ) );
  c8 = wwl_add( c8, wwl_mul_ll( ai, b2 ) );
  c9 = wwl_add( c9, wwl_mul_ll( ai, b3 ) );
  c0 = wwl_add( c0, wwl_mul_ll( ai, d4 ) );   /* 6+4=10, *19 */
  c1 = wwl_add( c1, wwl_mul_ll( ai, d5 ) );
  c2 = wwl_add( c2, wwl_mul_ll( ai, d6 ) );
  c3 = wwl_add( c3, wwl_mul_ll( ai, d7 ) );
  c4 = wwl_add( c4, wwl_mul_ll( ai, d8 ) );
  c5 = wwl_add( c5, wwl_mul_ll( ai, d9 ) );

  /* a[7] contributions (odd limb) */
  ai = a->limb[7];
  a2i = wwl_add( ai, ai );
  c7 = wwl_add( c7, wwl_mul_ll( ai, b0 ) );
  c8 = wwl_add( c8, wwl_mul_ll( a2i, b1 ) );  /* both odd */
  c9 = wwl_add( c9, wwl_mul_ll( ai, b2 ) );
  c0 = wwl_add( c0, wwl_mul_ll( a2i, d3 ) );  /* 7+3=10, *19, both odd */
  c1 = wwl_add( c1, wwl_mul_ll( ai, d4 ) );
  c2 = wwl_add( c2, wwl_mul_ll( a2i, d5 ) );  /* both odd */
  c3 = wwl_add( c3, wwl_mul_ll( ai, d6 ) );
  c4 = wwl_add( c4, wwl_mul_ll( a2i, d7 ) );  /* both odd */
  c5 = wwl_add( c5, wwl_mul_ll( ai, d8 ) );
  c6 = wwl_add( c6, wwl_mul_ll( a2i, d9 ) );  /* both odd */

  /* a[8] contributions (even limb) */
  ai = a->limb[8];
  c8 = wwl_add( c8, wwl_mul_ll( ai, b0 ) );
  c9 = wwl_add( c9, wwl_mul_ll( ai, b1 ) );
  c0 = wwl_add( c0, wwl_mul_ll( ai, d2 ) );   /* 8+2=10, *19 */
  c1 = wwl_add( c1, wwl_mul_ll( ai, d3 ) );
  c2 = wwl_add( c2, wwl_mul_ll( ai, d4 ) );
  c3 = wwl_add( c3, wwl_mul_ll( ai, d5 ) );
  c4 = wwl_add( c4, wwl_mul_ll( ai, d6 ) );
  c5 = wwl_add( c5, wwl_mul_ll( ai, d7 ) );
  c6 = wwl_add( c6, wwl_mul_ll( ai, d8 ) );
  c7 = wwl_add( c7, wwl_mul_ll( ai, d9 ) );

  /* a[9] contributions (odd limb) */
  ai = a->limb[9];
  a2i = wwl_add( ai, ai );
  c9 = wwl_add( c9, wwl_mul_ll( ai, b0 ) );
  c0 = wwl_add( c0, wwl_mul_ll( a2i, d1 ) );  /* 9+1=10, *19, both odd */
  c1 = wwl_add( c1, wwl_mul_ll( ai, d2 ) );
  c2 = wwl_add( c2, wwl_mul_ll( a2i, d3 ) );  /* both odd */
  c3 = wwl_add( c3, wwl_mul_ll( ai, d4 ) );
  c4 = wwl_add( c4, wwl_mul_ll( a2i, d5 ) );  /* both odd */
  c5 = wwl_add( c5, wwl_mul_ll( ai, d6 ) );
  c6 = wwl_add( c6, wwl_mul_ll( a2i, d7 ) );  /* both odd */
  c7 = wwl_add( c7, wwl_mul_ll( ai, d8 ) );
  c8 = wwl_add( c8, wwl_mul_ll( a2i, d9 ) );  /* both odd */

  /* Store result */
  c->limb[0] = c0;
  c->limb[1] = c1;
  c->limb[2] = c2;
  c->limb[3] = c3;
  c->limb[4] = c4;
  c->limb[5] = c5;
  c->limb[6] = c6;
  c->limb[7] = c7;
  c->limb[8] = c8;
  c->limb[9] = c9;
}

/* ========================================================================
   Optimized Squaring
   ========================================================================

   Squaring exploits symmetry: a[i]*a[j] = a[j]*a[i], so off-diagonal terms
   only need to be computed once and doubled.

   Coefficients:
   - Diagonal (a[i]^2): multiply by 2 if i is odd (radix compensation)
   - Off-diagonal (2*a[i]*a[j]): multiply by 4 if both i,j are odd
   - Reduction: multiply by 19 when i+j >= 10

   This reduces multiplications from 100 to ~55. */

void
at_r2526x8_intsqr( at_r2526x8_t *       c,
                    at_r2526x8_t const * a ) {
  wwl_t const times19 = wwl_bcast( (long)AT_R2526X8_TIMES19 );

  /* Load a limbs */
  wwl_t b0 = a->limb[0];
  wwl_t b1 = a->limb[1];
  wwl_t b2 = a->limb[2];
  wwl_t b3 = a->limb[3];
  wwl_t b4 = a->limb[4];
  wwl_t b5 = a->limb[5];
  wwl_t b6 = a->limb[6];
  wwl_t b7 = a->limb[7];
  wwl_t b8 = a->limb[8];
  wwl_t b9 = a->limb[9];

  /* Pre-compute 19 * a[j] for reduction */
  wwl_t d3 = wwl_mul_ll( b3, times19 );
  wwl_t d4 = wwl_mul_ll( b4, times19 );
  wwl_t d5 = wwl_mul_ll( b5, times19 );
  wwl_t d6 = wwl_mul_ll( b6, times19 );
  wwl_t d7 = wwl_mul_ll( b7, times19 );
  wwl_t d8 = wwl_mul_ll( b8, times19 );
  wwl_t d9 = wwl_mul_ll( b9, times19 );

  wwl_t c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;
  wwl_t ai, aj, ak;

  /* a[0] contributions: even limb
     - diagonal: a0*a0 -> c0
     - off-diagonal: 2*a0*a[j] for j>0 */
  ai = b0;
  aj = wwl_add( ai, ai );  /* 2*a0 */
  c0 = wwl_mul_ll( ai, b0 );        /* a0^2 -> c0 */
  c1 = wwl_mul_ll( aj, b1 );        /* 2*a0*a1 -> c1 */
  c2 = wwl_mul_ll( aj, b2 );        /* 2*a0*a2 -> c2 */
  c3 = wwl_mul_ll( aj, b3 );        /* 2*a0*a3 -> c3 */
  c4 = wwl_mul_ll( aj, b4 );        /* 2*a0*a4 -> c4 */
  c5 = wwl_mul_ll( aj, b5 );        /* 2*a0*a5 -> c5 */
  c6 = wwl_mul_ll( aj, b6 );        /* 2*a0*a6 -> c6 */
  c7 = wwl_mul_ll( aj, b7 );        /* 2*a0*a7 -> c7 */
  c8 = wwl_mul_ll( aj, b8 );        /* 2*a0*a8 -> c8 */
  c9 = wwl_mul_ll( aj, b9 );        /* 2*a0*a9 -> c9 */

  /* a[1] contributions: odd limb */
  ai = b1;
  aj = wwl_add( ai, ai );   /* 2*a1 */
  ak = wwl_add( aj, aj );   /* 4*a1 for odd-odd off-diag */
  c2 = wwl_add( c2, wwl_mul_ll( aj, b1 ) );   /* 2*a1^2 -> c2 (diag, odd) */
  c3 = wwl_add( c3, wwl_mul_ll( aj, b2 ) );   /* 2*a1*a2 -> c3 */
  c4 = wwl_add( c4, wwl_mul_ll( ak, b3 ) );   /* 4*a1*a3 -> c4 (odd-odd) */
  c5 = wwl_add( c5, wwl_mul_ll( aj, b4 ) );   /* 2*a1*a4 -> c5 */
  c6 = wwl_add( c6, wwl_mul_ll( ak, b5 ) );   /* 4*a1*a5 -> c6 (odd-odd) */
  c7 = wwl_add( c7, wwl_mul_ll( aj, b6 ) );   /* 2*a1*a6 -> c7 */
  c8 = wwl_add( c8, wwl_mul_ll( ak, b7 ) );   /* 4*a1*a7 -> c8 (odd-odd) */
  c9 = wwl_add( c9, wwl_mul_ll( aj, b8 ) );   /* 2*a1*a8 -> c9 */
  c0 = wwl_add( c0, wwl_mul_ll( ak, d9 ) );   /* 4*19*a1*a9 -> c0 (odd-odd, wrap) */

  /* a[2] contributions: even limb */
  ai = b2;
  aj = wwl_add( ai, ai );   /* 2*a2 */
  c4 = wwl_add( c4, wwl_mul_ll( ai, b2 ) );   /* a2^2 -> c4 (diag, even) */
  c5 = wwl_add( c5, wwl_mul_ll( aj, b3 ) );   /* 2*a2*a3 -> c5 */
  c6 = wwl_add( c6, wwl_mul_ll( aj, b4 ) );   /* 2*a2*a4 -> c6 */
  c7 = wwl_add( c7, wwl_mul_ll( aj, b5 ) );   /* 2*a2*a5 -> c7 */
  c8 = wwl_add( c8, wwl_mul_ll( aj, b6 ) );   /* 2*a2*a6 -> c8 */
  c9 = wwl_add( c9, wwl_mul_ll( aj, b7 ) );   /* 2*a2*a7 -> c9 */
  c0 = wwl_add( c0, wwl_mul_ll( aj, d8 ) );   /* 2*19*a2*a8 -> c0 (wrap) */
  c1 = wwl_add( c1, wwl_mul_ll( aj, d9 ) );   /* 2*19*a2*a9 -> c1 (wrap) */

  /* a[3] contributions: odd limb */
  ai = b3;
  aj = wwl_add( ai, ai );   /* 2*a3 */
  ak = wwl_add( aj, aj );   /* 4*a3 */
  c6 = wwl_add( c6, wwl_mul_ll( aj, b3 ) );   /* 2*a3^2 -> c6 (diag, odd) */
  c7 = wwl_add( c7, wwl_mul_ll( aj, b4 ) );   /* 2*a3*a4 -> c7 */
  c8 = wwl_add( c8, wwl_mul_ll( ak, b5 ) );   /* 4*a3*a5 -> c8 (odd-odd) */
  c9 = wwl_add( c9, wwl_mul_ll( aj, b6 ) );   /* 2*a3*a6 -> c9 */
  c0 = wwl_add( c0, wwl_mul_ll( ak, d7 ) );   /* 4*19*a3*a7 -> c0 (odd-odd, wrap) */
  c1 = wwl_add( c1, wwl_mul_ll( aj, d8 ) );   /* 2*19*a3*a8 -> c1 */
  c2 = wwl_add( c2, wwl_mul_ll( ak, d9 ) );   /* 4*19*a3*a9 -> c2 (odd-odd) */

  /* a[4] contributions: even limb */
  ai = b4;
  aj = wwl_add( ai, ai );   /* 2*a4 */
  c8 = wwl_add( c8, wwl_mul_ll( ai, b4 ) );   /* a4^2 -> c8 (diag, even) */
  c9 = wwl_add( c9, wwl_mul_ll( aj, b5 ) );   /* 2*a4*a5 -> c9 */
  c0 = wwl_add( c0, wwl_mul_ll( aj, d6 ) );   /* 2*19*a4*a6 -> c0 (wrap) */
  c1 = wwl_add( c1, wwl_mul_ll( aj, d7 ) );   /* 2*19*a4*a7 -> c1 */
  c2 = wwl_add( c2, wwl_mul_ll( aj, d8 ) );   /* 2*19*a4*a8 -> c2 */
  c3 = wwl_add( c3, wwl_mul_ll( aj, d9 ) );   /* 2*19*a4*a9 -> c3 */

  /* a[5] contributions: odd limb */
  ai = b5;
  aj = wwl_add( ai, ai );   /* 2*a5 */
  ak = wwl_add( aj, aj );   /* 4*a5 */
  c0 = wwl_add( c0, wwl_mul_ll( aj, d5 ) );   /* 2*19*a5^2 -> c0 (diag, odd, wrap) */
  c1 = wwl_add( c1, wwl_mul_ll( aj, d6 ) );   /* 2*19*a5*a6 -> c1 */
  c2 = wwl_add( c2, wwl_mul_ll( ak, d7 ) );   /* 4*19*a5*a7 -> c2 (odd-odd) */
  c3 = wwl_add( c3, wwl_mul_ll( aj, d8 ) );   /* 2*19*a5*a8 -> c3 */
  c4 = wwl_add( c4, wwl_mul_ll( ak, d9 ) );   /* 4*19*a5*a9 -> c4 (odd-odd) */

  /* a[6] contributions: even limb */
  ai = b6;
  aj = wwl_add( ai, ai );   /* 2*a6 */
  c2 = wwl_add( c2, wwl_mul_ll( ai, d6 ) );   /* 19*a6^2 -> c2 (diag, even, wrap) */
  c3 = wwl_add( c3, wwl_mul_ll( aj, d7 ) );   /* 2*19*a6*a7 -> c3 */
  c4 = wwl_add( c4, wwl_mul_ll( aj, d8 ) );   /* 2*19*a6*a8 -> c4 */
  c5 = wwl_add( c5, wwl_mul_ll( aj, d9 ) );   /* 2*19*a6*a9 -> c5 */

  /* a[7] contributions: odd limb */
  ai = b7;
  aj = wwl_add( ai, ai );   /* 2*a7 */
  ak = wwl_add( aj, aj );   /* 4*a7 */
  c4 = wwl_add( c4, wwl_mul_ll( aj, d7 ) );   /* 2*19*a7^2 -> c4 (diag, odd, wrap) */
  c5 = wwl_add( c5, wwl_mul_ll( aj, d8 ) );   /* 2*19*a7*a8 -> c5 */
  c6 = wwl_add( c6, wwl_mul_ll( ak, d9 ) );   /* 4*19*a7*a9 -> c6 (odd-odd) */

  /* a[8] contributions: even limb */
  ai = b8;
  aj = wwl_add( ai, ai );   /* 2*a8 */
  c6 = wwl_add( c6, wwl_mul_ll( ai, d8 ) );   /* 19*a8^2 -> c6 (diag, even, wrap) */
  c7 = wwl_add( c7, wwl_mul_ll( aj, d9 ) );   /* 2*19*a8*a9 -> c7 */

  /* a[9] contributions: odd limb */
  ai = b9;
  aj = wwl_add( ai, ai );   /* 2*a9 */
  c8 = wwl_add( c8, wwl_mul_ll( aj, d9 ) );   /* 2*19*a9^2 -> c8 (diag, odd, wrap) */

  /* Store result */
  c->limb[0] = c0;
  c->limb[1] = c1;
  c->limb[2] = c2;
  c->limb[3] = c3;
  c->limb[4] = c4;
  c->limb[5] = c5;
  c->limb[6] = c6;
  c->limb[7] = c7;
  c->limb[8] = c8;
  c->limb[9] = c9;
}

/* ========================================================================
   Pack/Unpack (Zip/Unzip) Operations
   ========================================================================

   The zip operation takes 8 scalar field elements (each with 10 limbs)
   and interleaves them into a single at_r2526x8_t where each __m512i
   vector holds the corresponding limb from all 8 elements.

   Memory layout after zip:
     out->limb[i] = [e0->el[i], e1->el[i], ..., e7->el[i]]

   The unzip operation reverses this, extracting 8 scalar elements. */

void
at_r2526x8_zip( at_r2526x8_t *             out,
                 at_f25519_scalar_t const *  e0,
                 at_f25519_scalar_t const *  e1,
                 at_f25519_scalar_t const *  e2,
                 at_f25519_scalar_t const *  e3,
                 at_f25519_scalar_t const *  e4,
                 at_f25519_scalar_t const *  e5,
                 at_f25519_scalar_t const *  e6,
                 at_f25519_scalar_t const *  e7 ) {
  /* Access the scalar elements as uint64_t arrays.
     at_f25519_scalar_t is at_f25519_t which has el[12] (10 limbs + padding). */
  uint64_t const * ae0 = (uint64_t const *)e0;
  uint64_t const * ae1 = (uint64_t const *)e1;
  uint64_t const * ae2 = (uint64_t const *)e2;
  uint64_t const * ae3 = (uint64_t const *)e3;
  uint64_t const * ae4 = (uint64_t const *)e4;
  uint64_t const * ae5 = (uint64_t const *)e5;
  uint64_t const * ae6 = (uint64_t const *)e6;
  uint64_t const * ae7 = (uint64_t const *)e7;

  /* For each limb, create a vector with the 8 corresponding values.
     wwl_t holds 8 int64_t values in a __m512i. */
  for( int i = 0; i < AT_R2526X8_NUM_LIMBS; i++ ) {
    out->limb[i] = wwl( (long)ae0[i], (long)ae1[i], (long)ae2[i], (long)ae3[i],
                        (long)ae4[i], (long)ae5[i], (long)ae6[i], (long)ae7[i] );
  }
}

void
at_r2526x8_unzip( at_f25519_scalar_t *       e0,
                   at_f25519_scalar_t *       e1,
                   at_f25519_scalar_t *       e2,
                   at_f25519_scalar_t *       e3,
                   at_f25519_scalar_t *       e4,
                   at_f25519_scalar_t *       e5,
                   at_f25519_scalar_t *       e6,
                   at_f25519_scalar_t *       e7,
                   at_r2526x8_t const *      in ) {
  /* Access the scalar elements as uint64_t arrays */
  uint64_t * ae0 = (uint64_t *)e0;
  uint64_t * ae1 = (uint64_t *)e1;
  uint64_t * ae2 = (uint64_t *)e2;
  uint64_t * ae3 = (uint64_t *)e3;
  uint64_t * ae4 = (uint64_t *)e4;
  uint64_t * ae5 = (uint64_t *)e5;
  uint64_t * ae6 = (uint64_t *)e6;
  uint64_t * ae7 = (uint64_t *)e7;

  /* Extract each element's limb from the SIMD vector.
     wwl_unpack extracts all 8 elements at once. */
  for( int i = 0; i < AT_R2526X8_NUM_LIMBS; i++ ) {
    long l0, l1, l2, l3, l4, l5, l6, l7;
    wwl_unpack( in->limb[i], l0, l1, l2, l3, l4, l5, l6, l7 );
    ae0[i] = (uint64_t)l0;
    ae1[i] = (uint64_t)l1;
    ae2[i] = (uint64_t)l2;
    ae3[i] = (uint64_t)l3;
    ae4[i] = (uint64_t)l4;
    ae5[i] = (uint64_t)l5;
    ae6[i] = (uint64_t)l6;
    ae7[i] = (uint64_t)l7;
  }

  /* Clear padding limbs (10 and 11) */
  ae0[10] = 0; ae0[11] = 0;
  ae1[10] = 0; ae1[11] = 0;
  ae2[10] = 0; ae2[11] = 0;
  ae3[10] = 0; ae3[11] = 0;
  ae4[10] = 0; ae4[11] = 0;
  ae5[10] = 0; ae5[11] = 0;
  ae6[10] = 0; ae6[11] = 0;
  ae7[10] = 0; ae7[11] = 0;
}

#endif /* AT_HAS_AVX512_GENERAL */
