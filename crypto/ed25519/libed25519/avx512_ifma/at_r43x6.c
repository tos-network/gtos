#include "at_r43x6.h"

/* at_r43x6_repsqr_mul(x,y,n) returns z = [x^(2^n)] y of an unreduced
   at_r43x6_t (in u44) with lanes 6 and 7 zero where x is an unreduced
   at_r43x6_t (in u47).  Assumes lanes 6 and 7 of x are zero.  Computed
   via n repeated squarings, yielding a cost of n at_r43x6_sqr. */

AT_FN_CONST static at_r43x6_t
at_r43x6_repsqr_mul( at_r43x6_t x,
                     at_r43x6_t y,
                     ulong      n ) {

 /* The below is R43X6_SQR1_INL wrapped in a loop to encourage inlining
    of the loop body and encourage the compiler to hoist various compile
    time constants out of the loop.  REPSQR is almost always paired with
    a MUL and this is almost always iterated.  So we incorporate the mul
    into this operation too to try to get the whole operation inlined
    but without too much instruction footprint for the below use cases. */

  for( ; n; n-- ) AT_R43X6_SQR1_INL( x, x );
  AT_R43X6_MUL1_INL( x, x, y );
  return x;
}

/* at_r43x6_repsqr_mul2 does:
     *_za = at_r43x6_repsqr_mul( xa, ya, n );
     *_zb = at_r43x6_repsqr_mul( xb, yb, n );
   but faster. */

static void
at_r43x6_repsqr_mul2( at_r43x6_t * _za, at_r43x6_t xa, at_r43x6_t ya,
                      at_r43x6_t * _zb, at_r43x6_t xb, at_r43x6_t yb,
                      ulong        n ) {

  /* Similar considerations as repsqr_mul */

  for( ; n; n-- ) AT_R43X6_SQR2_INL( xa, xa,  xb, xb );
  AT_R43X6_MUL2_INL( xa, xa, ya,  xb, xb, yb );
  *_za = xa; *_zb = xb;
}

at_r43x6_t
at_r43x6_invert( at_r43x6_t z ) {

  /* Theory:

          z^p       = z in GF(p)
       -> z^(p-1) z = z
       -> z^(p-1)   = 1
       -> z^(p-2) z = 1
       -> z^(p-2) is the multiplicative inverse of z in GF(p).

     Since p-2 is impractically large, we have to do this indirectly.
     This technique is adapted from the OpenSSL implementation.

       z^(p-2) = z^(2^255-21)
               = z^[(2^255)-(2^5)+11]
               = z^[(2^250)(2^5)-(2^5)+11]
               = z^[(2^250-1)(2^5) + 11]
               = [z^(2^250-1)]^(2^5) z^11

     z^11 is straightforward to compute directly.  [...]^(2^5) is
     straightforward to compute by repeated squaring.  z^(2^n-1) can be
     computed by a combination of repeated squaring and factorizations
     like:

       z^(2^n-1) = z^[(2^(n/2)+1)(2^(n/2)-1)]
                 = z^[2^(n/2) (2^(n/2)-1) + (2^(n/2)-1)]
                 = [z^(2^(n/2)-1)]^(2^(n/2)) z^(2^(n/2)-1)

     where the first term is the n/2 repeated squaring of z^(2^(n/2)-1)
     and the second term is the factor that initialized the repeated
     squaring. */

  /* Compute z^11 (and z^9 along the way) */

  at_r43x6_t z2       = at_r43x6_sqr       ( z                         ); /* TODO: consider repsqr_mul(z,one,1) for more reuse? */
  at_r43x6_t z9       = at_r43x6_repsqr_mul( z2,       z,          2UL );
  at_r43x6_t z11      = at_r43x6_repsqr_mul( z9,       z2,         0UL );

  /* Compute z^(2^250-1) */

  at_r43x6_t z2e5m1   = at_r43x6_repsqr_mul( z11,      z9,         1UL );
  at_r43x6_t z2e10m1  = at_r43x6_repsqr_mul( z2e5m1,   z2e5m1,     5UL );
  at_r43x6_t z2e20m1  = at_r43x6_repsqr_mul( z2e10m1,  z2e10m1,   10UL );
  at_r43x6_t z2e40m1  = at_r43x6_repsqr_mul( z2e20m1,  z2e20m1,   20UL );
  at_r43x6_t z2e50m1  = at_r43x6_repsqr_mul( z2e40m1,  z2e10m1,   10UL );
  at_r43x6_t z2e100m1 = at_r43x6_repsqr_mul( z2e50m1,  z2e50m1,   50UL );
  at_r43x6_t z2e200m1 = at_r43x6_repsqr_mul( z2e100m1, z2e100m1, 100UL );
  at_r43x6_t z2e250m1 = at_r43x6_repsqr_mul( z2e200m1, z2e50m1,   50UL );

  /* Combine z^(2^250-1) and z^11 */

  return at_r43x6_repsqr_mul( z2e250m1, z11, 5UL );
}

at_r43x6_t
at_r43x6_pow22523( at_r43x6_t z ) {

  /* This works nearly identical to invert.  The factorization is:

       z^(2^252-3) = z^[(2^252)-(2^2)+1]
                   = z^[(2^250-1)(2^2)+1]
                   = [z^(2^250-1)]^(2^2) z

     We compute z^(2^250-1) the same way as invert and then do a
     slightly different final combination. */

  /* Compute z^(2^250-1) */

  at_r43x6_t z2       = at_r43x6_sqr       ( z                        ); /* TODO: consider repsqr_mul(z,one,1) for more reuse? */
  at_r43x6_t z9       = at_r43x6_repsqr_mul( z2,      z,          2UL );
  at_r43x6_t z11      = at_r43x6_repsqr_mul( z9,      z2,         0UL );
  at_r43x6_t z2e5m1   = at_r43x6_repsqr_mul( z11,     z9,         1UL );
  at_r43x6_t z2e10m1  = at_r43x6_repsqr_mul( z2e5m1,  z2e5m1,     5UL );
  at_r43x6_t z2e20m1  = at_r43x6_repsqr_mul( z2e10m1, z2e10m1,   10UL );
  at_r43x6_t z2e40m1  = at_r43x6_repsqr_mul( z2e20m1, z2e20m1,   20UL );
  at_r43x6_t z2e50m1  = at_r43x6_repsqr_mul( z2e40m1, z2e10m1,   10UL );
  at_r43x6_t z2e100m1 = at_r43x6_repsqr_mul( z2e50m1, z2e50m1,   50UL );
  at_r43x6_t z2e200m1 = at_r43x6_repsqr_mul( z2e100m1,z2e100m1, 100UL );
  at_r43x6_t z2e250m1 = at_r43x6_repsqr_mul( z2e200m1,z2e50m1,   50UL );

  /* Combine z^(2^250-1) and z */

  return at_r43x6_repsqr_mul( z2e250m1, z, 2UL );
}

void
at_r43x6_pow22523_2( at_r43x6_t * _za, at_r43x6_t za,
                     at_r43x6_t * _zb, at_r43x6_t zb ) {

  /* This is identical to the above but runs two calculations at the
     same time for lots of ILP. */

  at_r43x6_t z2a,       z2b;       AT_R43X6_SQR2_INL   ( z2a,       za,                  z2b,       zb                         );
  at_r43x6_t z9a,       z9b;       at_r43x6_repsqr_mul2( &z9a,      z2a,      za,        &z9b,      z2b,      zb,          2UL );
  at_r43x6_t z11a,      z11b;      at_r43x6_repsqr_mul2( &z11a,     z9a,      z2a,       &z11b,     z9b,      z2b,         0UL );
  at_r43x6_t z2e5m1a,   z2e5m1b;   at_r43x6_repsqr_mul2( &z2e5m1a,  z11a,     z9a,       &z2e5m1b,  z11b,     z9b,         1UL );
  at_r43x6_t z2e10m1a,  z2e10m1b;  at_r43x6_repsqr_mul2( &z2e10m1a, z2e5m1a,  z2e5m1a,   &z2e10m1b, z2e5m1b,  z2e5m1b,     5UL );
  at_r43x6_t z2e20m1a,  z2e20m1b;  at_r43x6_repsqr_mul2( &z2e20m1a, z2e10m1a, z2e10m1a,  &z2e20m1b, z2e10m1b, z2e10m1b,   10UL );
  at_r43x6_t z2e40m1a,  z2e40m1b;  at_r43x6_repsqr_mul2( &z2e40m1a, z2e20m1a, z2e20m1a,  &z2e40m1b, z2e20m1b, z2e20m1b,   20UL );
  at_r43x6_t z2e50m1a,  z2e50m1b;  at_r43x6_repsqr_mul2( &z2e50m1a, z2e40m1a, z2e10m1a,  &z2e50m1b, z2e40m1b, z2e10m1b,   10UL );
  at_r43x6_t z2e100m1a, z2e100m1b; at_r43x6_repsqr_mul2( &z2e100m1a,z2e50m1a, z2e50m1a,  &z2e100m1b,z2e50m1b, z2e50m1b,   50UL );
  at_r43x6_t z2e200m1a, z2e200m1b; at_r43x6_repsqr_mul2( &z2e200m1a,z2e100m1a,z2e100m1a, &z2e200m1b,z2e100m1b,z2e100m1b, 100UL );
  at_r43x6_t z2e250m1a, z2e250m1b; at_r43x6_repsqr_mul2( &z2e250m1a,z2e200m1a,z2e50m1a,  &z2e250m1b,z2e200m1b,z2e50m1b,   50UL );

  /**/                             at_r43x6_repsqr_mul2( _za,       z2e250m1a,za,        _zb,       z2e250m1b,zb,          2UL );
}
