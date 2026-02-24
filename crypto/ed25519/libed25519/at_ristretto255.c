#include "at_ristretto255.h"

/* Ensure field and curve constants are initialized (defined in at_curve25519.c) */
extern void at_curve25519_init_constants( void );

at_ristretto255_point_t *
at_ristretto255_point_frombytes( at_ristretto255_point_t * h,
                                 uchar const              buf[ 32 ] ) {
  at_curve25519_init_constants();
  at_f25519_t s[1];
  at_f25519_frombytes( s, buf );

  uchar s_check[ 32 ];
  at_f25519_tobytes( s_check, s );

  /* we only accept canonical points */
  int canon_check = at_memeq( buf, s_check, 32UL );
  int lsb_check = buf[0] & 1;
  if( AT_UNLIKELY( ( 0==canon_check )
                 | lsb_check ) ) {
    return NULL;
  }

  at_f25519_t ss[1]; /* ss = s^2 */
  at_f25519_sqr( ss, s );

  at_f25519_t u1[1]; /* u1 = 1 - ss */
  at_f25519_t u2[1]; /* u2 = 1 + ss */
  at_f25519_sub( u1, at_f25519_one, ss );
  at_f25519_add( u2, at_f25519_one, ss );

  at_f25519_t u2sq[1]; /* u2_sqr = u2^2 */
  at_f25519_sqr( u2sq, u2 );

  /* v = -(D * u1^2) - u2_sqr */

  at_f25519_t v[1];
  at_f25519_sqr ( v, u1          );
  at_f25519_mul( v, v, at_f25519_d );
  at_f25519_neg( v, v           );
  at_f25519_sub( v, v, u2sq     );

  /* (was_square, inv_sq) = SQRT_RATIO_M1(1, v * u2_sqr) */

  at_f25519_t tmp0[1];
  at_f25519_t tmp1[1];
  at_f25519_mul( tmp1, v, u2sq );

  at_f25519_t inv_sq[1];
  int was_square = at_f25519_inv_sqrt( inv_sq, tmp1 );

  at_f25519_t den_x[1];  /* den_x = inv_sq * u2 */
  at_f25519_t den_y[1];  /* den_y = inv_sq * den_x * v */
  at_f25519_mul( den_x, inv_sq, u2    );
  at_f25519_mul( den_y, inv_sq, den_x );
  at_f25519_mul( den_y, den_y,  v     );

  /* x = CT_ABS(2 * s * den_x) */
  at_f25519_set( tmp0, at_f25519_two );
  at_f25519_mul( tmp0, tmp0, s     );
  at_f25519_mul( tmp0, tmp0, den_x );
  at_f25519_t x[1], y[1], t[1];
  at_f25519_abs( x, tmp0        );
  /* y = u1 * den_y */
  at_f25519_mul( y, u1, den_y   );
  /* z = 1 */
  /* t = x * y */
  at_f25519_mul( t, x, y  );

  int sgn_t = at_f25519_sgn( t );
  int y_zero = at_f25519_is_zero( y );
  if( (!was_square )
    | sgn_t
    | y_zero ) {
    return NULL;
  }

  return at_ed25519_point_from( h, x, y, at_f25519_one, t );
}

uchar *
at_ristretto255_point_tobytes( uchar                           buf[ 32 ],
                               at_ristretto255_point_t const * h ) {
  at_curve25519_init_constants();
  at_f25519_t x[1], y[1], z[1], t[1];
  at_ed25519_point_to( x, y, z, t, h );

  // uchar out[32];
  /* u1 = (z0 + y0) * (z0 - y0) */
  at_f25519_t tmp0 [1]; at_f25519_add( tmp0, z, y );
  at_f25519_t tmp1 [1]; at_f25519_sub( tmp1, z, y );
  at_f25519_t u1   [1]; at_f25519_mul( u1,   tmp0, tmp1 );

  /* u2 = (x0 * y0) */
  at_f25519_t u2   [1]; at_f25519_mul( u2, x, y );

  /* invsqrt = SQRT_RATIO_M1(1, u1 * u2^2) */
  at_f25519_t u2_sq[1]; at_f25519_sqr( u2_sq, u2 );
  at_f25519_mul( tmp1, u1, u2_sq );
  at_f25519_t inv_sqrt[1];
  at_f25519_inv_sqrt( inv_sqrt, tmp1 );

  // at_f25519_tobytes( out, inv_sqrt );
  // AT_LOG_HEXDUMP_WARNING(( "inv_sqrt", out, 32 ));

  /* den1 = invsqrt * u1
     den2 = invsqrt * u2 */
  at_f25519_t den1[1]; at_f25519_mul( den1, inv_sqrt, u1 );
  at_f25519_t den2[1]; at_f25519_mul( den2, inv_sqrt, u2 );

  /* z_inv = den1 * den2 * t0 */
  at_f25519_t z_inv[1];
  at_f25519_mul( z_inv, den1,  den2 );
  at_f25519_mul( z_inv, z_inv, t );

  /* ix0 = x0 * SQRT_M1
     iy0 = y0 * SQRT_M1 */
  at_f25519_t ix0[1]; at_f25519_mul( ix0, x, at_f25519_sqrtm1 );
  at_f25519_t iy0[1]; at_f25519_mul( iy0, y, at_f25519_sqrtm1 );

  /* enchanted_denominator = den1 * INVSQRT_A_MINUS_D */
  at_f25519_t enchanted_denominator[1];
  at_f25519_mul( enchanted_denominator, den1, at_f25519_invsqrt_a_minus_d );

  /* rotate = IS_NEGATIVE(t0 * z_inv) */
  at_f25519_t rotate_[1]; at_f25519_mul( rotate_, t, z_inv );
  int rotate = at_f25519_sgn( rotate_ );
  // AT_LOG_HEXDUMP_WARNING(( "rotate", &rotate, 1 ));

  /* x = CT_SELECT(iy0 IF rotate ELSE x0)
     y = CT_SELECT(ix0 IF rotate ELSE y0) */
  at_f25519_if( x, rotate, iy0, x );
  at_f25519_if( y, rotate, ix0, y );

  // at_f25519_tobytes( out, x );
  // AT_LOG_HEXDUMP_WARNING(( "x", out, 32 ));
  // at_f25519_tobytes( out, y );
  // AT_LOG_HEXDUMP_WARNING(( "y", out, 32 ));

  /* z = z0 */
  /* den_inv = CT_SELECT(enchanted_denominator IF rotate ELSE den2) */
  at_f25519_t den_inv[1];
  at_f25519_if( den_inv, rotate, enchanted_denominator, den2 );
  // at_f25519_tobytes( out, den_inv );
  // AT_LOG_HEXDUMP_WARNING(( "den_inv", out, 32 ));

  /* y = CT_NEG(y, IS_NEGATIVE(x * z_inv)) */
  at_f25519_t _isneg[1];
  int isneg = at_f25519_sgn( at_f25519_mul( _isneg, x, z_inv ) );
  at_f25519_t y_neg[1]; at_f25519_neg( y_neg, y );
  at_f25519_if( y, isneg, y_neg, y ); // this is not abs (condition is not sgn(y))

  /* s = CT_ABS(den_inv * (z - y)) */
  at_f25519_t s[1];
  at_f25519_sub( s, z, y       );
  at_f25519_mul( s, s, den_inv );
  at_f25519_abs( s, s );

  at_f25519_tobytes( buf, s );
  return buf;
}

/* Elligator2 map to ristretto group:
   https://ristretto.group/formulas/elligator.html
   This follows closely the golang implementation:
   https://github.com/gtank/ristretto255/blob/v0.1.2/ristretto255.go#L88 */
at_ristretto255_point_t *
at_ristretto255_map_to_curve( at_ristretto255_point_t * h,
                              uchar const               buf[ 32 ] ) {
  at_curve25519_init_constants();
  /* r = SQRT_M1 * t^2 */
  at_f25519_t r0[1];
  at_f25519_t r[1];
  at_f25519_frombytes( r0, buf );
  at_f25519_mul( r, at_f25519_sqrtm1, at_f25519_sqr( r, r0 ) );

  /* u = (r + 1) * ONE_MINUS_D_SQ */
  at_f25519_t u[1];
  at_f25519_add( u, r, at_f25519_one );
  at_f25519_mul( u, u, at_f25519_one_minus_d_sq ); //-> using mul2

  /* c = -1 */
  at_f25519_t c[1];
  at_f25519_set( c, at_f25519_minus_one );

  /* v = (c - r*D) * (r + D) */
  at_f25519_t v[1], r_plus_d[1];
  at_f25519_add( r_plus_d, r, at_f25519_d );
  at_f25519_mul( v, r, at_f25519_d ); //-> using mul2
  // at_f25519_mul2( v, r, at_f25519_d,
  //                 u, u, at_f25519_one_minus_d_sq );
  at_f25519_sub( v, c, v );
  at_f25519_mul( v, v, r_plus_d );

  /* (was_square, s) = SQRT_RATIO_M1(u, v) */
  at_f25519_t s[1];
  uchar was_square = (uchar)at_f25519_sqrt_ratio( s, u, v );

  /* s_prime = -CT_ABS(s*r0) */
  at_f25519_t s_prime[1];
  at_f25519_neg_abs( s_prime, at_f25519_mul( s_prime, s, r0 ) );

	/* s = CT_SELECT(s IF was_square ELSE s_prime) */
  at_f25519_if( s, was_square, s, s_prime );
	/* c = CT_SELECT(c IF was_square ELSE r) */
  at_f25519_if( c, was_square, c, r );

  /* N = c * (r - 1) * D_MINUS_ONE_SQ - v */
  at_f25519_t n[1];
  at_f25519_mul( n, c, at_f25519_sub( n, r, at_f25519_one ) );
  at_f25519_sub( n, at_f25519_mul( n, n, at_f25519_d_minus_one_sq ), v );

  /* w0 = 2 * s * v
     w1 = N * SQRT_AD_MINUS_ONE
     w2 = 1 - s^2
     w3 = 1 + s^2 */
  at_f25519_t s2[1];
  at_f25519_sqr( s2, s );
  at_f25519_t w0[1], w1[1], w2[1], w3[1];
  at_f25519_mul2( w0,s,v, w1,n,at_f25519_sqrt_ad_minus_one );
  at_f25519_add( w0, w0, w0 );
  // at_f25519_mul( w1, n, sqrt_ad_minus_one );
  at_f25519_sub( w2, at_f25519_one, s2 );
  at_f25519_add( w3, at_f25519_one, s2 );

  // at_f25519_mul( h->X, w0, w3 );
  // at_f25519_mul( h->Y, w2, w1 );
  // at_f25519_mul( h->Z, w1, w3 );
  // at_f25519_mul( h->T, w0, w2 );
  at_f25519_t x[1], y[1], z[1], t[1];
  at_f25519_mul4( x,w0,w3, y,w2,w1, z,w1,w3, t,w0,w2 );
  return at_ed25519_point_from( h, x, y, z, t );
}

at_ristretto255_point_t *
at_ristretto255_hash_to_curve( at_ristretto255_point_t * h,
                               uchar const               s[ 64 ] ) {
  at_ristretto255_point_t p1[1];
  at_ristretto255_point_t p2[1];

  at_ristretto255_map_to_curve( p1, s    );
  at_ristretto255_map_to_curve( p2, s+32 );

  return at_ristretto255_point_add(h, p1, p2);
}