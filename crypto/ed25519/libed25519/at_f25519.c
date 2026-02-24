/* Avatar F25519 field implementation
 *
 * This file provides implementations that are not defined inline by
 * the selected implementation header. When AVX-512 General is enabled,
 * most functions are provided inline in the header, so this file only
 * provides stubs and any missing functions.
 *
 * When AVX-512 IFMA is enabled, ALL functions in this file are provided
 * by avx512_ifma/at_f25519.c instead (the at_f25519_t struct layout differs).
 */

#include "at_f25519.h"

/* AVX-512 IFMA uses a different at_f25519_t layout (at_r43x6_t el, not array).
   All functions for IFMA are in avx512_ifma/at_f25519.c. */
#if !AT_HAS_AVX512_IFMA

/* at_f25519_rng_unsafe generates a random field element.
   Stubbed - not needed for signature verification. */
at_f25519_t *
at_f25519_rng_unsafe( at_f25519_t * r,
                      at_rng_t *    rng ) {
  (void)rng;
  for( int i = 0; i < 12; i++ ) r->el[i] = 0;
  return r;
}

/* at_f25519_debug prints a field element.
   Stubbed - not needed for production use. */
void
at_f25519_debug( char const *        name,
                 at_f25519_t const * a ) {
  (void)name;
  (void)a;
}

/* The following functions are provided inline by AVX-512 General and AVX2 headers.
   Only provide non-inline versions for the reference implementation. */
#if !AT_HAS_AVX512_GENERAL && !AT_HAS_AVX

/* at_f25519_pow22523 computes r = a^(2^252-3), and returns r. */
at_f25519_t *
at_f25519_pow22523( at_f25519_t *       r,
                    at_f25519_t const * a ) {
  at_f25519_t t0[1];
  at_f25519_t t1[1];
  at_f25519_t t2[1];

  at_f25519_sqr( t0, a      );
  at_f25519_sqr( t1, t0     );
  for( int i=1; i<  2; i++ ) at_f25519_sqr( t1, t1 );

  at_f25519_mul( t1, a,  t1 );
  at_f25519_mul( t0, t0, t1 );
  at_f25519_sqr( t0, t0     );
  at_f25519_mul( t0, t1, t0 );
  at_f25519_sqr( t1, t0     );
  for( int i=1; i<  5; i++ ) at_f25519_sqr( t1, t1 );

  at_f25519_mul( t0, t1, t0 );
  at_f25519_sqr( t1, t0     );
  for( int i=1; i< 10; i++ ) at_f25519_sqr( t1, t1 );

  at_f25519_mul( t1, t1, t0 );
  at_f25519_sqr( t2, t1     );
  for( int i=1; i< 20; i++ ) at_f25519_sqr( t2, t2 );

  at_f25519_mul( t1, t2, t1 );
  at_f25519_sqr( t1, t1     );
  for( int i=1; i< 10; i++ ) at_f25519_sqr( t1, t1 );

  at_f25519_mul( t0, t1, t0 );
  at_f25519_sqr( t1, t0     );
  for( int i=1; i< 50; i++ ) at_f25519_sqr( t1, t1 );

  at_f25519_mul( t1, t1, t0 );
  at_f25519_sqr( t2, t1     );
  for( int i=1; i<100; i++ ) at_f25519_sqr( t2, t2 );

  at_f25519_mul( t1, t2, t1 );
  at_f25519_sqr( t1, t1     );
  for( int i=1; i< 50; i++ ) at_f25519_sqr( t1, t1 );

  at_f25519_mul( t0, t1, t0 );
  at_f25519_sqr( t0, t0     );
  for( int i=1; i<  2; i++ ) at_f25519_sqr( t0, t0 );

  at_f25519_mul(r, t0, a  );
  return r;
}

/* at_f25519_inv computes r = 1/a, and returns r. */
at_f25519_t *
at_f25519_inv( at_f25519_t *       r,
               at_f25519_t const * a ) {
  at_f25519_t t0[1];
  at_f25519_t t1[1];
  at_f25519_t t2[1];
  at_f25519_t t3[1];

  /* Compute z**-1 = z**(2**255 - 19 - 2) with the exponent as
     2**255 - 21 = (2**5) * (2**250 - 1) + 11. */

  at_f25519_sqr( t0,  a     );                        /* t0 = z**2 */
  at_f25519_sqr( t1, t0     );
  at_f25519_sqr( t1, t1     );                        /* t1 = t0**(2**2) = z**8 */
  at_f25519_mul( t1,  a, t1 );                        /* t1 = z * t1 = z**9 */
  at_f25519_mul( t0, t0, t1 );                        /* t0 = t0 * t1 = z**11 -- stash t0 away for the end. */
  at_f25519_sqr( t2, t0     );                        /* t2 = t0**2 = z**22 */
  at_f25519_mul( t1, t1, t2 );                        /* t1 = t1 * t2 = z**(2**5 - 1) */
  at_f25519_sqr( t2, t1     );
  for( int i=1; i<  5; i++ ) at_f25519_sqr( t2, t2 ); /* t2 = t1**(2**5) = z**((2**5) * (2**5 - 1)) */
  at_f25519_mul( t1, t2, t1 );                        /* t1 = t1 * t2 = z**((2**5 + 1) * (2**5 - 1)) = z**(2**10 - 1) */
  at_f25519_sqr( t2, t1     );
  for( int i=1; i< 10; i++ ) at_f25519_sqr( t2, t2 );
  at_f25519_mul( t2, t2, t1 );                        /* t2 = z**(2**20 - 1) */
  at_f25519_sqr( t3, t2     );
  for( int i=1; i< 20; i++ ) at_f25519_sqr( t3, t3 );
  at_f25519_mul( t2, t3, t2 );                        /* t2 = z**(2**40 - 1) */
  for( int i=0; i< 10; i++ ) at_f25519_sqr( t2, t2 ); /* t2 = z**(2**10) * (2**40 - 1) */
  at_f25519_mul( t1, t2, t1 );                        /* t1 = z**(2**50 - 1) */
  at_f25519_sqr( t2, t1     );
  for( int i=1; i< 50; i++ ) at_f25519_sqr( t2, t2 );
  at_f25519_mul( t2, t2, t1 );                        /* t2 = z**(2**100 - 1) */
  at_f25519_sqr( t3, t2     );
  for( int i=1; i<100; i++ ) at_f25519_sqr( t3, t3 );
  at_f25519_mul( t2, t3, t2 );                        /* t2 = z**(2**200 - 1) */
  at_f25519_sqr( t2, t2     );
  for( int i=1; i< 50; i++ ) at_f25519_sqr( t2, t2 ); /* t2 = z**((2**50) * (2**200 - 1) */
  at_f25519_mul( t1, t2, t1 );                        /* t1 = z**(2**250 - 1) */
  at_f25519_sqr( t1, t1     );
  for( int i=1; i<  5; i++ ) at_f25519_sqr( t1, t1 ); /* t1 = z**((2**5) * (2**250 - 1)) */
  return at_f25519_mul( r, t1, t0 );                  /* Recall t0 = z**11; out = z**(2**255 - 21) */
}

/* at_f25519_sqrt_ratio computes r = (u * v^3) * (u * v^7)^((p-5)/8),
   returns 1 on success (is a square), 0 on failure (no square root). */
int
at_f25519_sqrt_ratio( at_f25519_t *       r,
                      at_f25519_t const * u,
                      at_f25519_t const * v ) {
  /* r = (u * v^3) * (u * v^7)^((p-5)/8) */
  at_f25519_t  v2[1]; at_f25519_sqr(  v2, v      );
  at_f25519_t  v3[1]; at_f25519_mul(  v3, v2, v  );
  at_f25519_t uv3[1]; at_f25519_mul( uv3, u,  v3 );
  at_f25519_t  v6[1]; at_f25519_sqr(  v6, v3     );
  at_f25519_t  v7[1]; at_f25519_mul(  v7, v6, v  );
  at_f25519_t uv7[1]; at_f25519_mul( uv7, u,  v7 );
  at_f25519_pow22523( r, uv7    );
  at_f25519_mul     ( r, r, uv3 );

  /* check = v * r^2 */
  at_f25519_t check[1];
  at_f25519_sqr( check, r        );
  at_f25519_mul( check, check, v );

  /* (correct_sign_sqrt)    check == u
     (flipped_sign_sqrt)    check == !u
     (flipped_sign_sqrt_i)  check == (!u * SQRT_M1) */
  at_f25519_t u_neg[1];        at_f25519_neg( u_neg,        u );
  at_f25519_t u_neg_sqrtm1[1]; at_f25519_mul( u_neg_sqrtm1, u_neg, at_f25519_sqrtm1 );
  int correct_sign_sqrt   = at_f25519_eq( check, u );
  int flipped_sign_sqrt   = at_f25519_eq( check, u_neg );
  int flipped_sign_sqrt_i = at_f25519_eq( check, u_neg_sqrtm1 );

  /* r_prime = SQRT_M1 * r */
  at_f25519_t r_prime[1];
  at_f25519_mul( r_prime, r, at_f25519_sqrtm1 );

  /* r = CT_SELECT(r_prime IF flipped_sign_sqrt | flipped_sign_sqrt_i ELSE r) */
  at_f25519_if( r, flipped_sign_sqrt|flipped_sign_sqrt_i, r_prime, r );
  at_f25519_abs( r, r );
  return correct_sign_sqrt|flipped_sign_sqrt;
}

#endif /* !AT_HAS_AVX512_GENERAL && !AT_HAS_AVX */

#endif /* !AT_HAS_AVX512_IFMA */
