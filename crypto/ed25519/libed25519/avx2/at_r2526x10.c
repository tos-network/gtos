/* AVX2 field arithmetic implementation for GF(2^255-19).

   This implements 4-way parallel field multiplication and squaring using
   the schoolbook algorithm with radix-2^25.5 representation. */

#include "at/crypto/at_crypto_base.h"
#include <stdint.h>

#if AT_HAS_AVX

#include "at_r2526x10.h"

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
*/

void
at_r2526x10_intmul( at_r2526x10_t *       c,
                    at_r2526x10_t const * a,
                    at_r2526x10_t const * b ) {
  wv_t const times19 = wv_bcast( AT_R2526X10_TIMES19 );

  /* Load b limbs */
  wv_t b0 = b->limb[0];
  wv_t b1 = b->limb[1];
  wv_t b2 = b->limb[2];
  wv_t b3 = b->limb[3];
  wv_t b4 = b->limb[4];
  wv_t b5 = b->limb[5];
  wv_t b6 = b->limb[6];
  wv_t b7 = b->limb[7];
  wv_t b8 = b->limb[8];
  wv_t b9 = b->limb[9];

  /* Pre-compute 19 * b[j] for reduction */
  wv_t d1 = wv_mul_ll( b1, times19 );
  wv_t d2 = wv_mul_ll( b2, times19 );
  wv_t d3 = wv_mul_ll( b3, times19 );
  wv_t d4 = wv_mul_ll( b4, times19 );
  wv_t d5 = wv_mul_ll( b5, times19 );
  wv_t d6 = wv_mul_ll( b6, times19 );
  wv_t d7 = wv_mul_ll( b7, times19 );
  wv_t d8 = wv_mul_ll( b8, times19 );
  wv_t d9 = wv_mul_ll( b9, times19 );

  /* Accumulators for result limbs */
  wv_t c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;

  wv_t ai, a2i;

  /* a[0] contributions (even limb) */
  ai = a->limb[0];
  c0 = wv_mul_ll( ai, b0 );
  c1 = wv_mul_ll( ai, b1 );
  c2 = wv_mul_ll( ai, b2 );
  c3 = wv_mul_ll( ai, b3 );
  c4 = wv_mul_ll( ai, b4 );
  c5 = wv_mul_ll( ai, b5 );
  c6 = wv_mul_ll( ai, b6 );
  c7 = wv_mul_ll( ai, b7 );
  c8 = wv_mul_ll( ai, b8 );
  c9 = wv_mul_ll( ai, b9 );

  /* a[1] contributions (odd limb - double when paired with odd b) */
  ai = a->limb[1];
  a2i = wv_add( ai, ai );  /* 2 * a[1] for pairing with odd b indices */
  c1 = wv_add( c1, wv_mul_ll( ai, b0 ) );   /* 1+0=1 */
  c2 = wv_add( c2, wv_mul_ll( a2i, b1 ) );  /* 1+1=2, doubled (odd+odd) */
  c3 = wv_add( c3, wv_mul_ll( ai, b2 ) );   /* 1+2=3 */
  c4 = wv_add( c4, wv_mul_ll( a2i, b3 ) );  /* 1+3=4, doubled */
  c5 = wv_add( c5, wv_mul_ll( ai, b4 ) );   /* 1+4=5 */
  c6 = wv_add( c6, wv_mul_ll( a2i, b5 ) );  /* 1+5=6, doubled */
  c7 = wv_add( c7, wv_mul_ll( ai, b6 ) );   /* 1+6=7 */
  c8 = wv_add( c8, wv_mul_ll( a2i, b7 ) );  /* 1+7=8, doubled */
  c9 = wv_add( c9, wv_mul_ll( ai, b8 ) );   /* 1+8=9 */
  c0 = wv_add( c0, wv_mul_ll( a2i, d9 ) );  /* 1+9=10 mod 10=0, *19, doubled */

  /* a[2] contributions (even limb) */
  ai = a->limb[2];
  c2 = wv_add( c2, wv_mul_ll( ai, b0 ) );
  c3 = wv_add( c3, wv_mul_ll( ai, b1 ) );
  c4 = wv_add( c4, wv_mul_ll( ai, b2 ) );
  c5 = wv_add( c5, wv_mul_ll( ai, b3 ) );
  c6 = wv_add( c6, wv_mul_ll( ai, b4 ) );
  c7 = wv_add( c7, wv_mul_ll( ai, b5 ) );
  c8 = wv_add( c8, wv_mul_ll( ai, b6 ) );
  c9 = wv_add( c9, wv_mul_ll( ai, b7 ) );
  c0 = wv_add( c0, wv_mul_ll( ai, d8 ) );   /* 2+8=10, *19 */
  c1 = wv_add( c1, wv_mul_ll( ai, d9 ) );   /* 2+9=11, *19 */

  /* a[3] contributions (odd limb) */
  ai = a->limb[3];
  a2i = wv_add( ai, ai );
  c3 = wv_add( c3, wv_mul_ll( ai, b0 ) );
  c4 = wv_add( c4, wv_mul_ll( a2i, b1 ) );  /* both odd */
  c5 = wv_add( c5, wv_mul_ll( ai, b2 ) );
  c6 = wv_add( c6, wv_mul_ll( a2i, b3 ) );  /* both odd */
  c7 = wv_add( c7, wv_mul_ll( ai, b4 ) );
  c8 = wv_add( c8, wv_mul_ll( a2i, b5 ) );  /* both odd */
  c9 = wv_add( c9, wv_mul_ll( ai, b6 ) );
  c0 = wv_add( c0, wv_mul_ll( a2i, d7 ) );  /* 3+7=10, *19, both odd */
  c1 = wv_add( c1, wv_mul_ll( ai, d8 ) );
  c2 = wv_add( c2, wv_mul_ll( a2i, d9 ) );  /* both odd */

  /* a[4] contributions (even limb) */
  ai = a->limb[4];
  c4 = wv_add( c4, wv_mul_ll( ai, b0 ) );
  c5 = wv_add( c5, wv_mul_ll( ai, b1 ) );
  c6 = wv_add( c6, wv_mul_ll( ai, b2 ) );
  c7 = wv_add( c7, wv_mul_ll( ai, b3 ) );
  c8 = wv_add( c8, wv_mul_ll( ai, b4 ) );
  c9 = wv_add( c9, wv_mul_ll( ai, b5 ) );
  c0 = wv_add( c0, wv_mul_ll( ai, d6 ) );   /* 4+6=10, *19 */
  c1 = wv_add( c1, wv_mul_ll( ai, d7 ) );
  c2 = wv_add( c2, wv_mul_ll( ai, d8 ) );
  c3 = wv_add( c3, wv_mul_ll( ai, d9 ) );

  /* a[5] contributions (odd limb) */
  ai = a->limb[5];
  a2i = wv_add( ai, ai );
  c5 = wv_add( c5, wv_mul_ll( ai, b0 ) );
  c6 = wv_add( c6, wv_mul_ll( a2i, b1 ) );  /* both odd */
  c7 = wv_add( c7, wv_mul_ll( ai, b2 ) );
  c8 = wv_add( c8, wv_mul_ll( a2i, b3 ) );  /* both odd */
  c9 = wv_add( c9, wv_mul_ll( ai, b4 ) );
  c0 = wv_add( c0, wv_mul_ll( a2i, d5 ) );  /* 5+5=10, *19, both odd */
  c1 = wv_add( c1, wv_mul_ll( ai, d6 ) );
  c2 = wv_add( c2, wv_mul_ll( a2i, d7 ) );  /* both odd */
  c3 = wv_add( c3, wv_mul_ll( ai, d8 ) );
  c4 = wv_add( c4, wv_mul_ll( a2i, d9 ) );  /* both odd */

  /* a[6] contributions (even limb) */
  ai = a->limb[6];
  c6 = wv_add( c6, wv_mul_ll( ai, b0 ) );
  c7 = wv_add( c7, wv_mul_ll( ai, b1 ) );
  c8 = wv_add( c8, wv_mul_ll( ai, b2 ) );
  c9 = wv_add( c9, wv_mul_ll( ai, b3 ) );
  c0 = wv_add( c0, wv_mul_ll( ai, d4 ) );   /* 6+4=10, *19 */
  c1 = wv_add( c1, wv_mul_ll( ai, d5 ) );
  c2 = wv_add( c2, wv_mul_ll( ai, d6 ) );
  c3 = wv_add( c3, wv_mul_ll( ai, d7 ) );
  c4 = wv_add( c4, wv_mul_ll( ai, d8 ) );
  c5 = wv_add( c5, wv_mul_ll( ai, d9 ) );

  /* a[7] contributions (odd limb) */
  ai = a->limb[7];
  a2i = wv_add( ai, ai );
  c7 = wv_add( c7, wv_mul_ll( ai, b0 ) );
  c8 = wv_add( c8, wv_mul_ll( a2i, b1 ) );  /* both odd */
  c9 = wv_add( c9, wv_mul_ll( ai, b2 ) );
  c0 = wv_add( c0, wv_mul_ll( a2i, d3 ) );  /* 7+3=10, *19, both odd */
  c1 = wv_add( c1, wv_mul_ll( ai, d4 ) );
  c2 = wv_add( c2, wv_mul_ll( a2i, d5 ) );  /* both odd */
  c3 = wv_add( c3, wv_mul_ll( ai, d6 ) );
  c4 = wv_add( c4, wv_mul_ll( a2i, d7 ) );  /* both odd */
  c5 = wv_add( c5, wv_mul_ll( ai, d8 ) );
  c6 = wv_add( c6, wv_mul_ll( a2i, d9 ) );  /* both odd */

  /* a[8] contributions (even limb) */
  ai = a->limb[8];
  c8 = wv_add( c8, wv_mul_ll( ai, b0 ) );
  c9 = wv_add( c9, wv_mul_ll( ai, b1 ) );
  c0 = wv_add( c0, wv_mul_ll( ai, d2 ) );   /* 8+2=10, *19 */
  c1 = wv_add( c1, wv_mul_ll( ai, d3 ) );
  c2 = wv_add( c2, wv_mul_ll( ai, d4 ) );
  c3 = wv_add( c3, wv_mul_ll( ai, d5 ) );
  c4 = wv_add( c4, wv_mul_ll( ai, d6 ) );
  c5 = wv_add( c5, wv_mul_ll( ai, d7 ) );
  c6 = wv_add( c6, wv_mul_ll( ai, d8 ) );
  c7 = wv_add( c7, wv_mul_ll( ai, d9 ) );

  /* a[9] contributions (odd limb) */
  ai = a->limb[9];
  a2i = wv_add( ai, ai );
  c9 = wv_add( c9, wv_mul_ll( ai, b0 ) );
  c0 = wv_add( c0, wv_mul_ll( a2i, d1 ) );  /* 9+1=10, *19, both odd */
  c1 = wv_add( c1, wv_mul_ll( ai, d2 ) );
  c2 = wv_add( c2, wv_mul_ll( a2i, d3 ) );  /* both odd */
  c3 = wv_add( c3, wv_mul_ll( ai, d4 ) );
  c4 = wv_add( c4, wv_mul_ll( a2i, d5 ) );  /* both odd */
  c5 = wv_add( c5, wv_mul_ll( ai, d6 ) );
  c6 = wv_add( c6, wv_mul_ll( a2i, d7 ) );  /* both odd */
  c7 = wv_add( c7, wv_mul_ll( ai, d8 ) );
  c8 = wv_add( c8, wv_mul_ll( a2i, d9 ) );  /* both odd */

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
at_r2526x10_intsqr( at_r2526x10_t *       c,
                    at_r2526x10_t const * a ) {
  wv_t const times19 = wv_bcast( AT_R2526X10_TIMES19 );

  /* Load a limbs */
  wv_t b0 = a->limb[0];
  wv_t b1 = a->limb[1];
  wv_t b2 = a->limb[2];
  wv_t b3 = a->limb[3];
  wv_t b4 = a->limb[4];
  wv_t b5 = a->limb[5];
  wv_t b6 = a->limb[6];
  wv_t b7 = a->limb[7];
  wv_t b8 = a->limb[8];
  wv_t b9 = a->limb[9];

  /* Pre-compute 19 * a[j] for reduction */
  wv_t d3 = wv_mul_ll( b3, times19 );
  wv_t d4 = wv_mul_ll( b4, times19 );
  wv_t d5 = wv_mul_ll( b5, times19 );
  wv_t d6 = wv_mul_ll( b6, times19 );
  wv_t d7 = wv_mul_ll( b7, times19 );
  wv_t d8 = wv_mul_ll( b8, times19 );
  wv_t d9 = wv_mul_ll( b9, times19 );

  wv_t c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;
  wv_t ai, aj, ak;

  /* a[0] contributions: even limb
     - diagonal: a0*a0 -> c0
     - off-diagonal: 2*a0*a[j] for j>0 */
  ai = b0;
  aj = wv_add( ai, ai );  /* 2*a0 */
  c0 = wv_mul_ll( ai, b0 );        /* a0^2 -> c0 */
  c1 = wv_mul_ll( aj, b1 );        /* 2*a0*a1 -> c1 */
  c2 = wv_mul_ll( aj, b2 );        /* 2*a0*a2 -> c2 */
  c3 = wv_mul_ll( aj, b3 );        /* 2*a0*a3 -> c3 */
  c4 = wv_mul_ll( aj, b4 );        /* 2*a0*a4 -> c4 */
  c5 = wv_mul_ll( aj, b5 );        /* 2*a0*a5 -> c5 */
  c6 = wv_mul_ll( aj, b6 );        /* 2*a0*a6 -> c6 */
  c7 = wv_mul_ll( aj, b7 );        /* 2*a0*a7 -> c7 */
  c8 = wv_mul_ll( aj, b8 );        /* 2*a0*a8 -> c8 */
  c9 = wv_mul_ll( aj, b9 );        /* 2*a0*a9 -> c9 */

  /* a[1] contributions: odd limb */
  ai = b1;
  aj = wv_add( ai, ai );   /* 2*a1 */
  ak = wv_add( aj, aj );   /* 4*a1 for odd-odd off-diag */
  c2 = wv_add( c2, wv_mul_ll( aj, b1 ) );   /* 2*a1^2 -> c2 (diag, odd) */
  c3 = wv_add( c3, wv_mul_ll( aj, b2 ) );   /* 2*a1*a2 -> c3 */
  c4 = wv_add( c4, wv_mul_ll( ak, b3 ) );   /* 4*a1*a3 -> c4 (odd-odd) */
  c5 = wv_add( c5, wv_mul_ll( aj, b4 ) );   /* 2*a1*a4 -> c5 */
  c6 = wv_add( c6, wv_mul_ll( ak, b5 ) );   /* 4*a1*a5 -> c6 (odd-odd) */
  c7 = wv_add( c7, wv_mul_ll( aj, b6 ) );   /* 2*a1*a6 -> c7 */
  c8 = wv_add( c8, wv_mul_ll( ak, b7 ) );   /* 4*a1*a7 -> c8 (odd-odd) */
  c9 = wv_add( c9, wv_mul_ll( aj, b8 ) );   /* 2*a1*a8 -> c9 */
  c0 = wv_add( c0, wv_mul_ll( ak, d9 ) );   /* 4*19*a1*a9 -> c0 (odd-odd, wrap) */

  /* a[2] contributions: even limb */
  ai = b2;
  aj = wv_add( ai, ai );   /* 2*a2 */
  c4 = wv_add( c4, wv_mul_ll( ai, b2 ) );   /* a2^2 -> c4 (diag, even) */
  c5 = wv_add( c5, wv_mul_ll( aj, b3 ) );   /* 2*a2*a3 -> c5 */
  c6 = wv_add( c6, wv_mul_ll( aj, b4 ) );   /* 2*a2*a4 -> c6 */
  c7 = wv_add( c7, wv_mul_ll( aj, b5 ) );   /* 2*a2*a5 -> c7 */
  c8 = wv_add( c8, wv_mul_ll( aj, b6 ) );   /* 2*a2*a6 -> c8 */
  c9 = wv_add( c9, wv_mul_ll( aj, b7 ) );   /* 2*a2*a7 -> c9 */
  c0 = wv_add( c0, wv_mul_ll( aj, d8 ) );   /* 2*19*a2*a8 -> c0 (wrap) */
  c1 = wv_add( c1, wv_mul_ll( aj, d9 ) );   /* 2*19*a2*a9 -> c1 (wrap) */

  /* a[3] contributions: odd limb */
  ai = b3;
  aj = wv_add( ai, ai );   /* 2*a3 */
  ak = wv_add( aj, aj );   /* 4*a3 */
  c6 = wv_add( c6, wv_mul_ll( aj, b3 ) );   /* 2*a3^2 -> c6 (diag, odd) */
  c7 = wv_add( c7, wv_mul_ll( aj, b4 ) );   /* 2*a3*a4 -> c7 */
  c8 = wv_add( c8, wv_mul_ll( ak, b5 ) );   /* 4*a3*a5 -> c8 (odd-odd) */
  c9 = wv_add( c9, wv_mul_ll( aj, b6 ) );   /* 2*a3*a6 -> c9 */
  c0 = wv_add( c0, wv_mul_ll( ak, d7 ) );   /* 4*19*a3*a7 -> c0 (odd-odd, wrap) */
  c1 = wv_add( c1, wv_mul_ll( aj, d8 ) );   /* 2*19*a3*a8 -> c1 */
  c2 = wv_add( c2, wv_mul_ll( ak, d9 ) );   /* 4*19*a3*a9 -> c2 (odd-odd) */

  /* a[4] contributions: even limb */
  ai = b4;
  aj = wv_add( ai, ai );   /* 2*a4 */
  c8 = wv_add( c8, wv_mul_ll( ai, b4 ) );   /* a4^2 -> c8 (diag, even) */
  c9 = wv_add( c9, wv_mul_ll( aj, b5 ) );   /* 2*a4*a5 -> c9 */
  c0 = wv_add( c0, wv_mul_ll( aj, d6 ) );   /* 2*19*a4*a6 -> c0 (wrap) */
  c1 = wv_add( c1, wv_mul_ll( aj, d7 ) );   /* 2*19*a4*a7 -> c1 */
  c2 = wv_add( c2, wv_mul_ll( aj, d8 ) );   /* 2*19*a4*a8 -> c2 */
  c3 = wv_add( c3, wv_mul_ll( aj, d9 ) );   /* 2*19*a4*a9 -> c3 */

  /* a[5] contributions: odd limb */
  ai = b5;
  aj = wv_add( ai, ai );   /* 2*a5 */
  ak = wv_add( aj, aj );   /* 4*a5 */
  c0 = wv_add( c0, wv_mul_ll( aj, d5 ) );   /* 2*19*a5^2 -> c0 (diag, odd, wrap) */
  c1 = wv_add( c1, wv_mul_ll( aj, d6 ) );   /* 2*19*a5*a6 -> c1 */
  c2 = wv_add( c2, wv_mul_ll( ak, d7 ) );   /* 4*19*a5*a7 -> c2 (odd-odd) */
  c3 = wv_add( c3, wv_mul_ll( aj, d8 ) );   /* 2*19*a5*a8 -> c3 */
  c4 = wv_add( c4, wv_mul_ll( ak, d9 ) );   /* 4*19*a5*a9 -> c4 (odd-odd) */

  /* a[6] contributions: even limb */
  ai = b6;
  aj = wv_add( ai, ai );   /* 2*a6 */
  c2 = wv_add( c2, wv_mul_ll( ai, d6 ) );   /* 19*a6^2 -> c2 (diag, even, wrap) */
  c3 = wv_add( c3, wv_mul_ll( aj, d7 ) );   /* 2*19*a6*a7 -> c3 */
  c4 = wv_add( c4, wv_mul_ll( aj, d8 ) );   /* 2*19*a6*a8 -> c4 */
  c5 = wv_add( c5, wv_mul_ll( aj, d9 ) );   /* 2*19*a6*a9 -> c5 */

  /* a[7] contributions: odd limb */
  ai = b7;
  aj = wv_add( ai, ai );   /* 2*a7 */
  ak = wv_add( aj, aj );   /* 4*a7 */
  c4 = wv_add( c4, wv_mul_ll( aj, d7 ) );   /* 2*19*a7^2 -> c4 (diag, odd, wrap) */
  c5 = wv_add( c5, wv_mul_ll( aj, d8 ) );   /* 2*19*a7*a8 -> c5 */
  c6 = wv_add( c6, wv_mul_ll( ak, d9 ) );   /* 4*19*a7*a9 -> c6 (odd-odd) */

  /* a[8] contributions: even limb */
  ai = b8;
  aj = wv_add( ai, ai );   /* 2*a8 */
  c6 = wv_add( c6, wv_mul_ll( ai, d8 ) );   /* 19*a8^2 -> c6 (diag, even, wrap) */
  c7 = wv_add( c7, wv_mul_ll( aj, d9 ) );   /* 2*19*a8*a9 -> c7 */

  /* a[9] contributions: odd limb */
  ai = b9;
  aj = wv_add( ai, ai );   /* 2*a9 */
  c8 = wv_add( c8, wv_mul_ll( aj, d9 ) );   /* 2*19*a9^2 -> c8 (diag, odd, wrap) */

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

   The zip operation takes 4 scalar field elements (each with 10 limbs)
   and interleaves them into a single at_r2526x10_t where each __m256i
   vector holds the corresponding limb from all 4 elements.

   Memory layout after zip:
     out->limb[i] = [a->el[i], b->el[i], c->el[i], d->el[i]]

   The unzip operation reverses this, extracting 4 scalar elements. */

void
at_r2526x10_zip( at_r2526x10_t *             out,
                 at_f25519_scalar_t const *  a,
                 at_f25519_scalar_t const *  b,
                 at_f25519_scalar_t const *  c,
                 at_f25519_scalar_t const *  d ) {
  /* Access the scalar elements as uint64_t arrays.
     at_f25519_scalar_t is at_f25519_t which has el[12] (10 limbs + padding). */
  uint64_t const * ae = (uint64_t const *)a;
  uint64_t const * be = (uint64_t const *)b;
  uint64_t const * ce = (uint64_t const *)c;
  uint64_t const * de = (uint64_t const *)d;

  /* For each limb, create a vector with the 4 corresponding values.
     wv_t holds 4 uint64_t values in a __m256i. */
  for( int i = 0; i < AT_R2526X10_NUM_LIMBS; i++ ) {
    out->limb[i] = wv( ae[i], be[i], ce[i], de[i] );
  }
}

void
at_r2526x10_unzip( at_f25519_scalar_t *       a,
                   at_f25519_scalar_t *       b,
                   at_f25519_scalar_t *       c,
                   at_f25519_scalar_t *       d,
                   at_r2526x10_t const *      in ) {
  /* Access the scalar elements as uint64_t arrays */
  uint64_t * ae = (uint64_t *)a;
  uint64_t * be = (uint64_t *)b;
  uint64_t * ce = (uint64_t *)c;
  uint64_t * de = (uint64_t *)d;

  /* Extract each element's limb from the SIMD vector.
     wv_extract extracts the element at the given index. */
  for( int i = 0; i < AT_R2526X10_NUM_LIMBS; i++ ) {
    wv_t v = in->limb[i];
    ae[i] = wv_extract( v, 0 );
    be[i] = wv_extract( v, 1 );
    ce[i] = wv_extract( v, 2 );
    de[i] = wv_extract( v, 3 );
  }

  /* Clear padding limbs (10 and 11) */
  ae[10] = 0; ae[11] = 0;
  be[10] = 0; be[11] = 0;
  ce[10] = 0; ce[11] = 0;
  de[10] = 0; de[11] = 0;
}

#endif /* AT_HAS_AVX2 */
