#include "at/crypto/at_f25519.h"

/* at_f25519_rng generates a random at_f25519_t element.
   Note: insecure, for tests only. */
at_f25519_t *
at_f25519_rng_unsafe( at_f25519_t * r,
                      at_rng_t *    rng ) {
  uchar buf[32];
  for( int j=0; j<32; j++ ) {
    buf[j] = at_rng_uchar( rng );
  }
  return at_f25519_frombytes( r, buf );
}

/* at_f25519_debug prints a field element.
   Stubbed - not needed for production use. */
void
at_f25519_debug( char const *        name,
                 at_f25519_t const * a ) {
  (void)name;
  (void)a;
}

/*
 * AVX-512 IFMA wrappers for at_r43x6 field operations.
 *
 * The at_r43x6_t representation uses radix-2^43 in AVX-512 lanes.
 * These wrappers bridge the at_f25519_t pointer-based API to the
 * at_r43x6_t value-based API.
 */

/* at_f25519_pow22523 computes r = a^(2^252-3), and returns r. */
at_f25519_t *
at_f25519_pow22523( at_f25519_t *       r,
                    at_f25519_t const * a ) {
  r->el = at_r43x6_pow22523( a->el );
  return r;
}

/* at_f25519_inv computes r = 1/a, and returns r. */
at_f25519_t *
at_f25519_inv( at_f25519_t *       r,
               at_f25519_t const * a ) {
  r->el = at_r43x6_invert( a->el );
  return r;
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

/* at_f25519_pow22523_2 computes r1 = a1^(2^252-3), r2 = a2^(2^252-3).
   2-way parallel version with ILP. */
at_f25519_t *
at_f25519_pow22523_2( at_f25519_t * r1, at_f25519_t const * a1,
                      at_f25519_t * r2, at_f25519_t const * a2 ) {
  at_r43x6_pow22523_2( &r1->el, a1->el, &r2->el, a2->el );
  return r1;
}

/* at_f25519_sqrt_ratio2 computes two sqrt_ratio operations in parallel.
   Returns 1 if both succeed, 0 otherwise. */
int
at_f25519_sqrt_ratio2( at_f25519_t * r1, at_f25519_t const * u1, at_f25519_t const * v1,
                       at_f25519_t * r2, at_f25519_t const * u2, at_f25519_t const * v2 ) {
  int ok1 = at_f25519_sqrt_ratio( r1, u1, v1 );
  int ok2 = at_f25519_sqrt_ratio( r2, u2, v2 );
  return ok1 & ok2;
}
