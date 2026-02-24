/* AVX2 accelerated Curve25519/Ed25519 point operations.

   This implements point arithmetic using AVX2 field operations.
   The formulas follow the reference implementation but benefit from
   the accelerated field arithmetic. */

#include "at/crypto/at_crypto_base.h"

#if AT_HAS_AVX && !AT_HAS_AVX512_IFMA

/* Include our own AVX2 headers directly */
#include "at_curve25519.h"

/* Forward declarations for functions used before definition */
at_ed25519_point_t *
at_ed25519_point_dbl( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a );

/* ========================================================================
   Initialization of Curve Constants from Precomputed Tables
   ======================================================================== */

void
at_ed25519_avx2_init_constants( void ) {
  if( at_ed25519_avx2_constants_initialized ) return;

  /* Copy field constants from precomputed tables */
  at_f25519_set( at_f25519_d_storage, at_f25519_d_precomputed );
  at_f25519_set( at_f25519_sqrtm1_storage, at_f25519_sqrtm1_precomputed );
  at_f25519_set( at_f25519_k_storage, at_f25519_k_precomputed );

  /* Copy base point from precomputed table */
  at_ed25519_point_set( at_ed25519_base_point_storage,
                        at_ed25519_base_point_precomputed );

  /* Copy low-order point Y coordinates from precomputed tables */
  at_f25519_set( at_ed25519_order8_point_y0_storage,
                 at_ed25519_order8_point_y0_precomputed );
  at_f25519_set( at_ed25519_order8_point_y1_storage,
                 at_ed25519_order8_point_y1_precomputed );

  at_ed25519_avx2_constants_initialized = 1;
}

/* ========================================================================
   Point Addition

   Uses the unified addition formula from https://eprint.iacr.org/2008/522
   which is complete (works for a==b case).

   Cost: 8M + 1*k (or 9M if not using precomputed k*T)
   ======================================================================== */

/* at_ed25519_point_add_with_opts computes r = a + b with various options. */
static at_ed25519_point_t *
at_ed25519_point_add_with_opts( at_ed25519_point_t *       r,
                                at_ed25519_point_t const * a,
                                at_ed25519_point_t const * b,
                                int const                  b_Z_is_one,
                                int const                  b_is_precomputed,
                                int const                  skip_last_mul ) {
  at_f25519_t r1[1], r2[1], r3[1], r4[1];
  at_f25519_t r5[1], r6[1], r7[1], r8[1];
  at_f25519_t t[1];
  at_f25519_t const *r2p = r2, *r4p = r4;

  at_f25519_sub_nr( r1, a->Y, a->X );
  at_f25519_add_nr( r3, a->Y, a->X );

#if CURVE25519_PRECOMP_XY
  if( b_is_precomputed ) {
    r2p = b->X;
    r4p = b->Y;
  } else {
    at_f25519_sub_nr( r2, b->Y, b->X );
    at_f25519_add_nr( r4, b->Y, b->X );
  }
#else
  at_f25519_sub_nr( r2, b->Y, b->X );
  at_f25519_add_nr( r4, b->Y, b->X );
#endif

  if( b_Z_is_one ) {
    at_f25519_mul3( r5, r1,   r2p,
                    r6, r3,   r4p,
                    r7, a->T, b->T );
    at_f25519_add( r8, a->Z, a->Z );
  } else {
    at_f25519_add_nr( t, a->Z, a->Z );
    at_f25519_mul4( r5, r1,   r2p,
                    r6, r3,   r4p,
                    r7, a->T, b->T,
                    r8, t,    b->Z );
  }

  if( !b_is_precomputed ) {
    at_f25519_mul( r7, r7, at_f25519_k );
  }

  if( skip_last_mul ) {
    at_f25519_sub_nr( r->X, r6, r5 );
    at_f25519_sub_nr( r->Y, r8, r7 );
    at_f25519_add_nr( r->Z, r8, r7 );
    at_f25519_add_nr( r->T, r6, r5 );
  } else {
    /* Use reducing operations before mul4. The _nr variants can produce limbs
       up to ~28 bits from the 2p bias. When mul4 then computes 19*b[j], the
       result can exceed 32 bits, causing silent truncation in the SIMD
       wv_mul_ll (32x32->64) operation. Using the reducing versions ensures
       limbs stay within the expected 25/26-bit ranges. */
    at_f25519_sub( r1, r6, r5 );
    at_f25519_sub( r2, r8, r7 );
    at_f25519_add( r3, r8, r7 );
    at_f25519_add( r4, r6, r5 );

    at_f25519_mul4( r->X, r1, r2,
                    r->Y, r3, r4,
                    r->Z, r2, r3,
                    r->T, r1, r4 );

    /* Canonicalize to ensure field elements are in [0, p) */
    at_f25519_canonicalize( r->X );
    at_f25519_canonicalize( r->Y );
    at_f25519_canonicalize( r->Z );
    at_f25519_canonicalize( r->T );
  }
  return r;
}

/* at_ed25519_point_add computes r = a + b, and returns r.
   Note: The unified addition formula fails for a==b (P+P), so we detect
   this case and use dedicated doubling instead. */
at_ed25519_point_t *
at_ed25519_point_add( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a,
                      at_ed25519_point_t const * b ) {
  /* Detect P+P case and use doubling (unified formula fails for this) */
  if( at_ed25519_point_eq( a, b ) ) {
    return at_ed25519_point_dbl( r, a );
  }
  return at_ed25519_point_add_with_opts( r, a, b, 0, 0, 0 );
}

/* ========================================================================
   Point Subtraction
   ======================================================================== */

/* at_ed25519_point_sub_with_opts computes r = a - b with various options. */
static at_ed25519_point_t *
at_ed25519_point_sub_with_opts( at_ed25519_point_t *       r,
                                at_ed25519_point_t const * a,
                                at_ed25519_point_t const * b,
                                int const                  b_Z_is_one,
                                int const                  b_is_precomputed,
                                int const                  skip_last_mul ) {
  at_f25519_t r1[1], r2[1], r3[1], r4[1];
  at_f25519_t r5[1], r6[1], r7[1], r8[1];
  at_f25519_t t[1];
  at_f25519_t const *r2p = r2, *r4p = r4;

  at_f25519_sub_nr( r1, a->Y, a->X );
  at_f25519_add_nr( r3, a->Y, a->X );

#if CURVE25519_PRECOMP_XY
  if( b_is_precomputed ) {
    r2p = b->Y;  /* Swapped for subtraction */
    r4p = b->X;
  } else {
    at_f25519_add_nr( r2, b->Y, b->X );
    at_f25519_sub_nr( r4, b->Y, b->X );
  }
#else
  at_f25519_add_nr( r2, b->Y, b->X );
  at_f25519_sub_nr( r4, b->Y, b->X );
#endif

  if( b_Z_is_one ) {
    at_f25519_mul3( r5, r1,   r2p,
                    r6, r3,   r4p,
                    r7, a->T, b->T );
    at_f25519_add( r8, a->Z, a->Z );
  } else {
    at_f25519_add_nr( t, a->Z, a->Z );
    at_f25519_mul4( r5, r1,   r2p,
                    r6, r3,   r4p,
                    r7, a->T, b->T,
                    r8, t,    b->Z );
  }

  if( !b_is_precomputed ) {
    at_f25519_mul( r7, r7, at_f25519_k );
  }

  if( skip_last_mul ) {
    at_f25519_sub_nr( r->X, r6, r5 );
    at_f25519_add_nr( r->Y, r8, r7 );  /* Note: add for sub */
    at_f25519_sub_nr( r->Z, r8, r7 );  /* Note: sub for sub */
    at_f25519_add_nr( r->T, r6, r5 );
  } else {
    /* Use reducing operations before mul4 to avoid SIMD overflow
       (see comment in add function for details) */
    at_f25519_sub( r1, r6, r5 );
    at_f25519_add( r2, r8, r7 );
    at_f25519_sub( r3, r8, r7 );
    at_f25519_add( r4, r6, r5 );

    at_f25519_mul4( r->X, r1, r2,
                    r->Y, r3, r4,
                    r->Z, r2, r3,
                    r->T, r1, r4 );

    /* Canonicalize to ensure field elements are in [0, p) */
    at_f25519_canonicalize( r->X );
    at_f25519_canonicalize( r->Y );
    at_f25519_canonicalize( r->Z );
    at_f25519_canonicalize( r->T );
  }
  return r;
}

/* at_ed25519_point_sub computes r = a - b, and returns r.
   Note: P - P = identity, so we detect this case explicitly. */
at_ed25519_point_t *
at_ed25519_point_sub( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a,
                      at_ed25519_point_t const * b ) {
  /* Detect P-P case and return identity */
  if( at_ed25519_point_eq( a, b ) ) {
    return at_ed25519_point_set_zero( r );
  }
  return at_ed25519_point_sub_with_opts( r, a, b, 0, 0, 0 );
}

/* ========================================================================
   Point Doubling
   ======================================================================== */

at_ed25519_point_t *
at_ed25519_point_dbl( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a ) {
  at_ed25519_point_t t[1];
  at_ed25519_partial_dbl( t, a );
  return at_ed25519_point_add_final_mul( r, t );
}

/* ========================================================================
   Point Equality
   ======================================================================== */

int
at_ed25519_point_eq( at_ed25519_point_t const * a,
                     at_ed25519_point_t const * b ) {
  at_f25519_t x1[1], x2[1], y1[1], y2[1];
  at_f25519_mul( x1, b->X, a->Z );
  at_f25519_mul( x2, a->X, b->Z );
  at_f25519_mul( y1, b->Y, a->Z );
  at_f25519_mul( y2, a->Y, b->Z );
  return at_f25519_eq( x1, x2 ) & at_f25519_eq( y1, y2 );
}

int
at_ed25519_point_eq_z1( at_ed25519_point_t const * a,
                        at_ed25519_point_t const * b ) {
  at_f25519_t x1[1], y1[1];
  at_f25519_mul( x1, b->X, a->Z );
  at_f25519_mul( y1, b->Y, a->Z );
  return at_f25519_eq( x1, a->X ) & at_f25519_eq( y1, a->Y );
}

/* ========================================================================
   Serialization / Deserialization
   ======================================================================== */

/* at_ed25519_point_frombytes deserializes a 32-byte buffer into a point. */
at_ed25519_point_t *
at_ed25519_point_frombytes( at_ed25519_point_t * r,
                            uchar const          buf[ 32 ] ) {
  at_f25519_t x[1], y[1], t[1];
  at_f25519_frombytes( y, buf );
  uchar expected_x_sign = buf[31] >> 7;

  at_f25519_t u[1];
  at_f25519_t v[1];
  at_f25519_sqr( u, y );
  at_f25519_mul( v, u, at_f25519_d );
  at_f25519_sub( u, u, at_f25519_one );
  at_f25519_add( v, v, at_f25519_one );

  int was_square = at_f25519_sqrt_ratio( x, u, v );
  if( AT_UNLIKELY( !was_square ) ) {
    return NULL;
  }

  uchar actual_x_sign = (uchar)at_f25519_sgn( x );
  at_f25519_if( x, (int)(expected_x_sign ^ actual_x_sign), at_f25519_neg( t, x ), x );

  at_f25519_mul( t, x, y );
  return at_ed25519_point_from( r, x, y, at_f25519_one, t );
}

/* at_ed25519_point_frombytes_2x deserializes two points. */
int
at_ed25519_point_frombytes_2x( at_ed25519_point_t * r1,
                               uchar const          buf1[ 32 ],
                               at_ed25519_point_t * r2,
                               uchar const          buf2[ 32 ] ) {
  at_ed25519_point_t * res = NULL;
  res = at_ed25519_point_frombytes( r1, buf1 );
  if( res == NULL ) {
    return -1;
  }
  res = at_ed25519_point_frombytes( r2, buf2 );
  if( res == NULL ) {
    return -2;
  }
  return 0;
}

/* at_ed25519_point_tobytes serializes a point into a 32-byte buffer. */
uchar *
at_ed25519_point_tobytes( uchar                      buf[ 32 ],
                          at_ed25519_point_t const * a ) {
  at_f25519_t x[1], y[1], z[1], t[1];
  at_ed25519_point_to( x, y, z, t, a );

  at_f25519_t zi[1];
  at_f25519_inv( zi, z );
  at_f25519_mul( x, x, zi );
  at_f25519_mul( y, y, zi );

  at_f25519_tobytes( buf, y );
  buf[31] ^= (uchar)(at_f25519_sgn( x ) << 7);
  return buf;
}

/* ========================================================================
   Affine Helpers
   ======================================================================== */

at_ed25519_point_t *
at_curve25519_affine_frombytes( at_ed25519_point_t * r,
                                uchar const          x[ 32 ],
                                uchar const          y[ 32 ] ) {
  at_f25519_frombytes( r->X, x );
  at_f25519_frombytes( r->Y, y );
  at_f25519_set( r->Z, at_f25519_one );
  at_f25519_mul( r->T, r->X, r->Y );
  return r;
}

at_ed25519_point_t *
at_curve25519_into_affine( at_ed25519_point_t * r ) {
  at_f25519_t invz[1];
  at_f25519_inv( invz, r->Z );
  at_f25519_mul( r->X, r->X, invz );
  at_f25519_mul( r->Y, r->Y, invz );
  at_f25519_set( r->Z, at_f25519_one );
  at_f25519_mul( r->T, r->X, r->Y );
  return r;
}

at_ed25519_point_t *
at_curve25519_affine_add( at_ed25519_point_t *       r,
                          at_ed25519_point_t const * a,
                          at_ed25519_point_t const * b ) {
  at_ed25519_point_add( r, a, b );
  return at_curve25519_into_affine( r );
}

at_ed25519_point_t *
at_curve25519_affine_dbln( at_ed25519_point_t *       r,
                           at_ed25519_point_t const * a,
                           int const                  n ) {
  at_ed25519_point_dbln( r, a, n );
  return at_curve25519_into_affine( r );
}

void
at_curve25519_into_precomputed( at_ed25519_point_t * r ) {
#if CURVE25519_PRECOMP_XY
  at_f25519_t add[1], sub[1];
  at_f25519_add_nr( add, r->Y, r->X );
  at_f25519_sub_nr( sub, r->Y, r->X );
  at_f25519_set( r->X, sub );
  at_f25519_set( r->Y, add );
#endif
  at_f25519_mul( r->T, r->T, at_f25519_k );
}

/* ========================================================================
   Debug
   ======================================================================== */

void
at_ed25519_debug( char const *               name,
                  at_ed25519_point_t const * a ) {
  (void)name;
  (void)a;
}

/* ========================================================================
   Scalar Multiplication
   ======================================================================== */

/* Simple double-and-add scalar multiplication (variable time, for arbitrary points) */
static at_ed25519_point_t *
at_ed25519_point_scalarmul_vartime( at_ed25519_point_t *       r,
                                    uchar const                n[ 32 ],
                                    at_ed25519_point_t const * a ) {
  at_ed25519_point_t acc[1];
  at_ed25519_point_set_zero( acc );

  for( int i = 255; i >= 0; i-- ) {
    at_ed25519_point_dbl( acc, acc );
    int bit = (n[i/8] >> (i%8)) & 1;
    if( bit ) {
      at_ed25519_point_add( acc, acc, a );
    }
  }

  return at_ed25519_point_set( r, acc );
}

/* ========================================================================
   w-NAF Scalar Recoding

   Converts a 256-bit scalar to width-w Non-Adjacent Form.
   w=8 means digits are in {0, ±1, ±3, ±5, ..., ±127}.

   The w-NAF representation has the property that at most one of any
   w consecutive digits is non-zero, reducing the number of additions.
   ======================================================================== */

#define WNAF_WIDTH 8
#define WNAF_SIZE  257

/* Recode scalar to w-NAF form.
   w-NAF: every non-zero digit is odd, and between any two non-zero digits
   there are at least w-1 zeros. Digits are in range [-(2^(w-1)-1), 2^(w-1)-1].

   For w=8, digits are in {±1, ±3, ±5, ..., ±127}. */
static void
wnaf_recode( int8_t       wnaf[ WNAF_SIZE ],
             uchar const  scalar[ 32 ] ) {
  /* Copy scalar to a mutable 64-bit array for easier manipulation */
  uint64_t s[5] = { 0, 0, 0, 0, 0 };
  for( int i = 0; i < 32; i++ ) {
    s[i / 8] |= (uint64_t)scalar[i] << ((i % 8) * 8);
  }

  /* Initialize output */
  for( int i = 0; i < WNAF_SIZE; i++ ) wnaf[i] = 0;

  int pos = 0;

  /* Process while scalar is non-zero */
  while( pos < 256 && (s[0] | s[1] | s[2] | s[3] | s[4]) ) {
    if( s[0] & 1 ) {
      /* Scalar is odd - emit a digit */
      int digit = s[0] & ((1 << WNAF_WIDTH) - 1);  /* Extract w bits */

      if( digit >= (1 << (WNAF_WIDTH - 1)) ) {
        /* Make negative and add 2^w to scalar */
        digit -= (1 << WNAF_WIDTH);
      }

      wnaf[pos] = (int8_t)digit;

      /* Subtract digit from scalar (digit can be negative) */
      if( digit > 0 ) {
        /* Subtract positive digit */
        uint64_t borrow = (uint64_t)digit;
        for( int i = 0; i < 5 && borrow; i++ ) {
          uint64_t prev = s[i];
          s[i] -= borrow;
          borrow = (s[i] > prev) ? 1 : 0;
        }
      } else if( digit < 0 ) {
        /* Add absolute value of negative digit */
        uint64_t carry = (uint64_t)(-digit);
        for( int i = 0; i < 5 && carry; i++ ) {
          s[i] += carry;
          carry = (s[i] < carry) ? 1 : 0;
        }
      }
    }

    /* Right shift scalar by 1 */
    s[0] = (s[0] >> 1) | (s[1] << 63);
    s[1] = (s[1] >> 1) | (s[2] << 63);
    s[2] = (s[2] >> 1) | (s[3] << 63);
    s[3] = (s[3] >> 1) | (s[4] << 63);
    s[4] = s[4] >> 1;

    pos++;
  }
}

/* ========================================================================
   Fast Base Point Scalar Multiplication using w-NAF Table

   Uses precomputed table at_ed25519_base_point_wnaf_table[128] which
   contains odd multiples [1]B, [3]B, [5]B, ..., [255]B in precomputed format.

   Table entry i contains [(2i+1)]B.
   ======================================================================== */

/* Add precomputed point (in format Y-X, Y+X, k*T, Z) to accumulator */
static void
at_ed25519_point_add_precomputed( at_ed25519_point_t *       r,
                                  at_ed25519_point_t const * a,
                                  at_ed25519_point_t const * precomp,
                                  int                        negate ) {
  at_f25519_t r1[1], r2[1], r3[1], r4[1];
  at_f25519_t r5[1], r6[1], r7[1], r8[1];

  /* a format: (X, Y, T, Z) - standard extended coordinates */
  /* precomp format: (Y-X, Y+X, k*T, Z) */

  at_f25519_sub_nr( r1, a->Y, a->X );  /* r1 = Y1 - X1 */
  at_f25519_add_nr( r3, a->Y, a->X );  /* r3 = Y1 + X1 */

  /* For addition: multiply (Y1-X1) by (Y2-X2) and (Y1+X1) by (Y2+X2)
     For subtraction: swap the precomputed values */
  if( negate ) {
    /* -P has coordinates (-X, Y, -T, Z), so (Y-X, Y+X) becomes (Y+X, Y-X) */
    at_f25519_mul( r5, r1, precomp->Y );  /* r5 = (Y1-X1)(Y2+X2) */
    at_f25519_mul( r6, r3, precomp->X );  /* r6 = (Y1+X1)(Y2-X2) */
  } else {
    at_f25519_mul( r5, r1, precomp->X );  /* r5 = (Y1-X1)(Y2-X2) */
    at_f25519_mul( r6, r3, precomp->Y );  /* r6 = (Y1+X1)(Y2+X2) */
  }

  at_f25519_mul( r7, a->T, precomp->T );  /* r7 = T1 * (k*T2), already has k */
  at_f25519_add( r8, a->Z, a->Z );         /* r8 = 2*Z1 (precomp has Z=1) */

  if( negate ) {
    at_f25519_neg( r7, r7 );  /* Negate k*T for subtraction */
  }

  /* Use reducing operations before mul4 to avoid SIMD overflow.
     The _nr variants can produce limbs up to ~28 bits from the 2p bias.
     When mul4 then computes 19*b[j], the result can exceed 32 bits,
     causing silent truncation in the SIMD wv_mul_ll (32x32->64) operation. */
  at_f25519_sub( r1, r6, r5 );  /* E = r6 - r5 */
  at_f25519_sub( r2, r8, r7 );  /* F = r8 - r7 */
  at_f25519_add( r3, r8, r7 );  /* G = r8 + r7 */
  at_f25519_add( r4, r6, r5 );  /* H = r6 + r5 */

  at_f25519_mul4( r->X, r1, r2,
                  r->Y, r3, r4,
                  r->Z, r2, r3,
                  r->T, r1, r4 );

  /* Canonicalize to ensure field elements are in [0, p) */
  at_f25519_canonicalize( r->X );
  at_f25519_canonicalize( r->Y );
  at_f25519_canonicalize( r->Z );
  at_f25519_canonicalize( r->T );
}

/* Scalar multiplication with base point using w-NAF and precomputed table */
static at_ed25519_point_t *
at_ed25519_scalar_mul_base_wnaf( at_ed25519_point_t * r,
                                 uchar const          n[ 32 ] ) {
  int8_t wnaf[WNAF_SIZE];

  /* Recode scalar to w-NAF */
  wnaf_recode( wnaf, n );

  /* Initialize accumulator to identity */
  at_ed25519_point_set_zero( r );

  /* Process from most significant digit to least significant */
  int started = 0;
  for( int i = 255; i >= 0; i-- ) {
    if( started ) {
      at_ed25519_point_dbl( r, r );
    }

    int8_t digit = wnaf[i];
    if( digit != 0 ) {
      started = 1;
      int negate = digit < 0;
      int abs_digit = negate ? -digit : digit;

      /* Table index: digit d maps to entry (d-1)/2
         e.g., digit 1 -> entry 0, digit 3 -> entry 1, ... digit 255 -> entry 127 */
      int table_idx = (abs_digit - 1) / 2;

      at_ed25519_point_add_precomputed( r, r,
                                        &at_ed25519_base_point_wnaf_table[table_idx],
                                        negate );
    }
  }

  return r;
}

/* at_ed25519_scalar_mul is the public API for scalar multiplication. */
at_ed25519_point_t *
at_ed25519_scalar_mul( at_ed25519_point_t *       r,
                       uchar const                n[ 32 ],
                       at_ed25519_point_t const * a ) {
  return at_ed25519_point_scalarmul_vartime( r, n, a );
}

/* Scalar multiplication with base point using precomputed table. */
at_ed25519_point_t *
at_ed25519_scalar_mul_base( at_ed25519_point_t * r,
                            uchar const          scalar[ 32 ] ) {
  at_ed25519_avx2_init_constants();
  return at_ed25519_scalar_mul_base_wnaf( r, scalar );
}

/* Constant-time scalar multiplication with base point.
   Note: Currently uses variable-time w-NAF for performance.
   TODO: Implement constant-time version if needed for secret scalars. */
at_ed25519_point_t *
at_ed25519_scalar_mul_base_const_time( at_ed25519_point_t * r,
                                       uchar const          secret_scalar[ 32 ] ) {
  at_ed25519_avx2_init_constants();
  /* For now, use the w-NAF version. A truly constant-time version would
     need to always access all table entries and use conditional moves. */
  return at_ed25519_scalar_mul_base_wnaf( r, secret_scalar );
}

/* Double scalar multiplication: r = n1*a + n2*B where B is the base point.
   This is the core operation for EdDSA verification. */
at_ed25519_point_t *
at_ed25519_double_scalar_mul_base( at_ed25519_point_t *       r,
                                   uchar const                n1[ 32 ],
                                   at_ed25519_point_t const * a,
                                   uchar const                n2[ 32 ] ) {
  at_ed25519_avx2_init_constants();

  at_ed25519_point_t t1[1], t2[1];

  /* Compute n1*a using simple scalar multiplication */
  at_ed25519_point_scalarmul_vartime( t1, n1, a );

  /* Compute n2*B using fast w-NAF with precomputed table */
  at_ed25519_scalar_mul_base_wnaf( t2, n2 );

  /* Add them */
  return at_ed25519_point_add( r, t1, t2 );
}

/* Multi-scalar multiplication: r = sum(n[i] * a[i]) */
at_ed25519_point_t *
at_ed25519_multi_scalar_mul( at_ed25519_point_t *     r,
                             uchar const              n[],
                             at_ed25519_point_t const a[],
                             ulong const              sz ) {
  if( sz == 0 ) {
    return at_ed25519_point_set_zero( r );
  }

  /* Compute first term */
  at_ed25519_point_scalarmul_vartime( r, &n[0], &a[0] );

  /* Add remaining terms */
  at_ed25519_point_t tmp[1];
  for( ulong i = 1; i < sz; i++ ) {
    at_ed25519_point_scalarmul_vartime( tmp, &n[i*32], &a[i] );
    at_ed25519_point_add( r, r, tmp );
  }

  return r;
}

/* Straus multi-scalar multiplication for better performance with multiple scalars. */
#define STRAUS_MAX_BATCH_SZ 32
#define STRAUS_WINDOW_SZ    4
#define STRAUS_TABLE_SZ     (1 << STRAUS_WINDOW_SZ)

at_ed25519_point_t *
at_ed25519_multi_scalar_mul_straus( at_ed25519_point_t *     r,
                                    uchar const              n[],
                                    at_ed25519_point_t const a[],
                                    ulong const              sz ) {
  if( sz == 0 ) {
    return at_ed25519_point_set_zero( r );
  }

  if( sz == 1 ) {
    return at_ed25519_point_scalarmul_vartime( r, n, a );
  }

  /* Fall back to naive for very small or very large batches */
  if( sz < 4 || sz > STRAUS_MAX_BATCH_SZ ) {
    return at_ed25519_multi_scalar_mul( r, n, a, sz );
  }

  /* Precomputation tables */
  at_ed25519_point_t table[STRAUS_MAX_BATCH_SZ][STRAUS_TABLE_SZ];

  /* Build tables */
  for( ulong i = 0; i < sz; i++ ) {
    at_ed25519_point_set_zero( &table[i][0] );
    at_ed25519_point_set( &table[i][1], &a[i] );
    at_ed25519_point_dbl( &table[i][2], &a[i] );
    for( int j = 3; j < STRAUS_TABLE_SZ; j++ ) {
      at_ed25519_point_add( &table[i][j], &table[i][j-1], &a[i] );
    }
  }

  /* Initialize result */
  at_ed25519_point_set_zero( r );

  /* Process windows from MSB to LSB */
  for( int win = 63; win >= 0; win-- ) {
    /* Double 4 times (except first window) */
    if( win < 63 ) {
      at_ed25519_point_dbl( r, r );
      at_ed25519_point_dbl( r, r );
      at_ed25519_point_dbl( r, r );
      at_ed25519_point_dbl( r, r );
    }

    /* Add table lookups */
    for( ulong i = 0; i < sz; i++ ) {
      int bit_pos   = win * 4;
      int byte_idx  = bit_pos / 8;
      int bit_shift = bit_pos % 8;

      uchar const * scalar = &n[i * 32];
      int w = (scalar[byte_idx] >> bit_shift) & 0x0F;

      if( w != 0 ) {
        at_ed25519_point_add( r, r, &table[i][w] );
      }
    }
  }

  return r;
}

/* Multi-scalar mul with base point as first point */
at_ed25519_point_t *
at_ed25519_multi_scalar_mul_base( at_ed25519_point_t *     r,
                                  uchar const              n[],
                                  at_ed25519_point_t const a[],
                                  ulong const              sz ) {
  /* Ensure constants are initialized */
  at_ed25519_avx2_init_constants();

  if( sz == 0 ) {
    return at_ed25519_point_set_zero( r );
  }

  /* First scalar multiplies base point using optimized w-NAF */
  at_ed25519_scalar_mul_base_wnaf( r, &n[0] );

  /* Add remaining terms */
  at_ed25519_point_t tmp[1];
  for( ulong i = 1; i < sz; i++ ) {
    at_ed25519_point_scalarmul_vartime( tmp, &n[i*32], &a[i] );
    at_ed25519_point_add( r, r, tmp );
  }

  return r;
}

#endif /* AT_HAS_AVX2 && !AT_HAS_AVX512 */
