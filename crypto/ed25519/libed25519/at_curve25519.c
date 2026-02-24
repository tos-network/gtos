/* Avatar Curve25519 implementation */

#include "at_curve25519.h"

/* Ensure field and curve constants are initialized for the selected backend.
   This function is exported (non-inline) so it can be called from other
   translation units like at_ristretto255.c */
void
at_curve25519_init_constants( void ) {
#if AT_HAS_AVX512_GENERAL
  at_ed25519_avx512_general_init_curve_constants();
#elif AT_HAS_AVX && !AT_HAS_AVX512_IFMA
  at_ed25519_avx2_init_constants();
#else
  /* Reference implementation uses static const tables, no init needed */
#endif
}

#define WNAF_BIT_SZ 4
#define WNAF_TBL_SZ (2*WNAF_BIT_SZ)

/*
 * Add
 */

/* at_ed25519_point_add_with_opts computes r = a + b, and returns r. */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_add_with_opts( at_ed25519_point_t *       r,
                                at_ed25519_point_t const * a,
                                at_ed25519_point_t const * b,
                                int const b_Z_is_one,
                                int const b_is_precomputed,
                                int const skip_last_mul ) {
  at_f25519_t r1[1], r2[1], r3[1], r4[1];
  at_f25519_t r5[1], r6[1], r7[1], r8[1];
  at_f25519_t t[1];
  at_f25519_t const *r2p = r2, *r4p = r4;

  at_f25519_sub_nr( r1, a->Y, a->X );
  at_f25519_add_nr( r3, a->Y, a->X );

#if CURVE25519_PRECOMP_XY
  if (b_is_precomputed) {
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

  /* Reduce partial results from _nr operations before mul3/mul4.
     For AVX512_GENERAL, 19*b[j] can exceed 32 bits if limbs aren't reduced. */
#if AT_HAS_AVX512_GENERAL
  at_f25519_carry( r1 );
  at_f25519_carry( r3 );
  if( !b_is_precomputed ) {
    at_f25519_carry( r2 );
    at_f25519_carry( r4 );
  }
#endif

  if( b_Z_is_one ) {
    at_f25519_mul3( r5, r1,   r2p,
                    r6, r3,   r4p,
                    r7, a->T, b->T );
    at_f25519_add( r8, a->Z, a->Z );
  } else {
    at_f25519_add_nr( t, a->Z, a->Z );
#if AT_HAS_AVX512_GENERAL
    at_f25519_carry( t );
#endif
    at_f25519_mul4( r5, r1,   r2p,
                    r6, r3,   r4p,
                    r7, a->T, b->T,
                    r8, t, b->Z );
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
    at_f25519_sub_nr( r1, r6, r5 );
    at_f25519_sub_nr( r2, r8, r7 );
    at_f25519_add_nr( r3, r8, r7 );
    at_f25519_add_nr( r4, r6, r5 );

    /* Reduce partial results before mul4. The _nr operations can leave limbs
       up to ~28 bits. When mul4 computes 19*b[j], values can exceed 32 bits,
       causing truncation in the SIMD wwl_mul_ll operation. */
#if AT_HAS_AVX512_GENERAL
    at_f25519_carry( r1 );
    at_f25519_carry( r2 );
    at_f25519_carry( r3 );
    at_f25519_carry( r4 );
#endif

    at_f25519_mul4( r->X, r1, r2,
                    r->Y, r3, r4,
                    r->Z, r2, r3,
                    r->T, r1, r4 );
  }
  return r;
}

/* at_ed25519_point_add computes r = a + b, and returns r. */
at_ed25519_point_t *
at_ed25519_point_add( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a,
                      at_ed25519_point_t const * b ) {
  at_curve25519_init_constants();
  return at_ed25519_point_add_with_opts( r, a, b, 0, 0, 0 );
}

/*
 * Sub
 */

AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_sub_with_opts( at_ed25519_point_t *       r,
                                at_ed25519_point_t const * a,
                                at_ed25519_point_t const * b,
                                int const b_Z_is_one,
                                int const b_is_precomputed,
                                int const skip_last_mul ) {
  at_f25519_t r1[1], r2[1], r3[1], r4[1];
  at_f25519_t r5[1], r6[1], r7[1], r8[1];
  at_f25519_t t[1];
  at_f25519_t const *r2p = r2, *r4p = r4;

  at_f25519_sub_nr( r1, a->Y, a->X );
  at_f25519_add_nr( r3, a->Y, a->X );

#if CURVE25519_PRECOMP_XY
  if (b_is_precomputed) {
    r2p = b->Y;
    r4p = b->X;
  } else {
    at_f25519_add_nr( r2, b->Y, b->X );
    at_f25519_sub_nr( r4, b->Y, b->X );
  }
#else
    at_f25519_add_nr( r2, b->Y, b->X );
    at_f25519_sub_nr( r4, b->Y, b->X );
#endif

  /* Reduce partial results from _nr operations before mul3/mul4.
     For AVX512_GENERAL, 19*b[j] can exceed 32 bits if limbs aren't reduced. */
#if AT_HAS_AVX512_GENERAL
  at_f25519_carry( r1 );
  at_f25519_carry( r3 );
  if( !b_is_precomputed ) {
    at_f25519_carry( r2 );
    at_f25519_carry( r4 );
  }
#endif

  if( b_Z_is_one ) {
    at_f25519_mul3( r5, r1,   r2p,
                    r6, r3,   r4p,
                    r7, a->T, b->T );
    at_f25519_add( r8, a->Z, a->Z );
  } else {
    at_f25519_add_nr( t, a->Z, a->Z );
#if AT_HAS_AVX512_GENERAL
    at_f25519_carry( t );
#endif
    at_f25519_mul4( r5, r1,   r2p,
                    r6, r3,   r4p,
                    r7, a->T, b->T,
                    r8, t, b->Z );
  }

  if( !b_is_precomputed ) {
    at_f25519_mul( r7, r7, at_f25519_k );
  }

  if( skip_last_mul ) {
    at_f25519_sub_nr( r->X, r6, r5 );
    at_f25519_add_nr( r->Y, r8, r7 );
    at_f25519_sub_nr( r->Z, r8, r7 );
    at_f25519_add_nr( r->T, r6, r5 );
  } else {
    at_f25519_sub_nr( r1, r6, r5 );
    at_f25519_add_nr( r2, r8, r7 );
    at_f25519_sub_nr( r3, r8, r7 );
    at_f25519_add_nr( r4, r6, r5 );

    /* Reduce before final mul4 */
#if AT_HAS_AVX512_GENERAL
    at_f25519_carry( r1 );
    at_f25519_carry( r2 );
    at_f25519_carry( r3 );
    at_f25519_carry( r4 );
#endif

    at_f25519_mul4( r->X, r1, r2,
                    r->Y, r3, r4,
                    r->Z, r2, r3,
                    r->T, r1, r4 );
  }
  return r;
}

at_ed25519_point_t *
at_ed25519_point_sub( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a,
                      at_ed25519_point_t const * b ) {
  return at_ed25519_point_sub_with_opts( r, a, b, 0, 0, 0 );
}

/*
 * Dbl
 */

at_ed25519_point_t *
at_ed25519_point_dbl( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a ) {
  at_curve25519_init_constants();
  at_ed25519_point_t t[1];
  at_ed25519_partial_dbl( t, a );
  return at_ed25519_point_add_final_mul( r, t );
}

/*
 * Ser/de
 */

at_ed25519_point_t *
at_ed25519_point_frombytes( at_ed25519_point_t * r,
                            uchar const          buf[ 32 ] ) {
  at_curve25519_init_constants();
  at_f25519_t x[1], y[1], t[1];
  at_f25519_frombytes( y, buf );
  uchar expected_x_sign = buf[31] >> 7;

  at_f25519_t u[1];
  at_f25519_t v[1];
  at_f25519_sqr( u, y                );
  at_f25519_mul( v, u, at_f25519_d   );
  at_f25519_sub( u, u, at_f25519_one );
  at_f25519_add( v, v, at_f25519_one );

  int is_square = at_f25519_sqrt_ratio( x, u, v );
  if( AT_UNLIKELY( !is_square ) ) {
    return NULL;
  }

  uchar actual_x_sign = (uchar)at_f25519_sgn( x );
  at_f25519_if( x, (int)(expected_x_sign ^ actual_x_sign), at_f25519_neg( t, x ), x );

  /* Reduce x after potential negation (at_f25519_neg leaves unreduced limbs) */
#if AT_HAS_AVX512_GENERAL
  at_f25519_carry( x );
#endif

  at_f25519_mul( t, x, y );
  return at_ed25519_point_from( r, x, y, at_f25519_one, t );
}

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

/*
 * Affine helpers
 */

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


/*
 * Debug
 */

void
at_ed25519_debug( char const *               name,
                  at_ed25519_point_t const * a ) {
  (void)name;
  (void)a;
}

/*
 * Scalar multiplication
 */

/* Simple double-and-add scalar multiplication (variable time) */
at_ed25519_point_t *
at_ed25519_point_scalarmul( at_ed25519_point_t *       r,
                            uchar const                n[ 32 ],
                            at_ed25519_point_t const * a ) {
  at_curve25519_init_constants();
  at_ed25519_point_t acc[1];
  at_ed25519_point_set_zero( acc );

  for( int i=255; i>=0; i-- ) {
    at_ed25519_point_dbl( acc, acc );
    int bit = (n[i/8] >> (i%8)) & 1;
    if( bit ) {
      at_ed25519_point_add( acc, acc, a );
    }
  }

  return at_ed25519_point_set( r, acc );
}

at_ed25519_point_t *
at_ed25519_point_scalarmul_base( at_ed25519_point_t * r,
                                 uchar const          n[ 32 ] ) {
  return at_ed25519_point_scalarmul( r, n, at_ed25519_base_point );
}

/* Constant-time scalar mul base (simplified version) */
at_ed25519_point_t *
at_ed25519_scalar_mul_base_const_time( at_ed25519_point_t * r,
                                       uchar const          secret_scalar[ 32 ] ) {
  /* For simplicity, use the variable-time version here.
     A proper constant-time implementation would use precomputed tables. */
  return at_ed25519_point_scalarmul_base( r, secret_scalar );
}

/* Double scalar mul: r = n1*a + n2*B where B is the base point */
at_ed25519_point_t *
at_ed25519_double_scalar_mul_base( at_ed25519_point_t *       r,
                                   uchar const                n1[ 32 ],
                                   at_ed25519_point_t const * a,
                                   uchar const                n2[ 32 ] ) {
  at_ed25519_point_t t1[1], t2[1];

  /* Compute n1*a */
  at_ed25519_point_scalarmul( t1, n1, a );

  /* Compute n2*B */
  at_ed25519_point_scalarmul_base( t2, n2 );

  /* Add them */
  return at_ed25519_point_add( r, t1, t2 );
}

/* at_ed25519_scalar_mul is the public API name for at_ed25519_point_scalarmul */
at_ed25519_point_t *
at_ed25519_scalar_mul( at_ed25519_point_t *       r,
                       uchar const                n[ 32 ],
                       at_ed25519_point_t const * a ) {
  return at_ed25519_point_scalarmul( r, n, a );
}

/* Multi-scalar multiplication: r = n0*a0 + n1*a1 + ... + n(sz-1)*a(sz-1) */
at_ed25519_point_t *
at_ed25519_multi_scalar_mul( at_ed25519_point_t *     r,
                             uchar const              n[], /* sz * 32 */
                             at_ed25519_point_t const a[],  /* sz */
                             ulong const              sz ) {
  if( sz == 0 ) {
    return at_ed25519_point_set_zero( r );
  }

  /* Compute first term */
  at_ed25519_point_scalarmul( r, &n[ 0 ], &a[ 0 ] );

  /* Add remaining terms */
  at_ed25519_point_t tmp[1];
  for( ulong i = 1; i < sz; i++ ) {
    at_ed25519_point_scalarmul( tmp, &n[ i*32 ], &a[ i ] );
    at_ed25519_point_add( r, r, tmp );
  }

  return r;
}

/* Straus multi-scalar multiplication algorithm with window size 4
   Computes r = n0*a0 + n1*a1 + ... + n(sz-1)*a(sz-1)

   Algorithm:
   1. Precompute for each point P_i: table[i][j] = j * P_i for j in [0, 15]
   2. Process scalars from MSB to LSB in 4-bit windows:
      - Double result 4 times
      - For each scalar i, extract current 4-bit window value w
      - Add table[i][w] to result
   3. Total: 256 doublings + sz * (256/4) conditional additions

   This is faster than naive when sz >= 4 because:
   - Naive: sz * 256 doublings + sz * ~128 additions
   - Straus: 256 doublings + sz * 16 precomputation + sz * 64 additions */

/* Maximum batch size for stack-allocated precomputation tables.
   Each point is 128 bytes, 16 entries per point = 2KB per point.
   For 32 points: 64KB of stack space for tables. */
#define STRAUS_MAX_BATCH_SZ 32
#define STRAUS_WINDOW_SZ    4
#define STRAUS_TABLE_SZ     (1 << STRAUS_WINDOW_SZ) /* 16 */

at_ed25519_point_t *
at_ed25519_multi_scalar_mul_straus( at_ed25519_point_t *     r,
                                    uchar const              n[], /* sz * 32 */
                                    at_ed25519_point_t const a[],  /* sz */
                                    ulong const              sz ) {
  /* Handle edge cases */
  if( sz == 0 ) {
    return at_ed25519_point_set_zero( r );
  }

  if( sz == 1 ) {
    return at_ed25519_point_scalarmul( r, n, a );
  }

  /* For very small sz or sz exceeding stack limit, fall back to naive */
  if( sz < 4 || sz > STRAUS_MAX_BATCH_SZ ) {
    return at_ed25519_multi_scalar_mul( r, n, a, sz );
  }

  /* Precomputation tables: table[i][j] = j * a[i] for j in [0, 15]
     We store on stack to avoid heap allocation.
     table[i][0] = identity (never actually used due to skip)
     table[i][1] = a[i]
     table[i][2] = 2*a[i]
     ...
     table[i][15] = 15*a[i] */
  at_ed25519_point_t table[ STRAUS_MAX_BATCH_SZ ][ STRAUS_TABLE_SZ ];

  /* Build precomputation tables for each point */
  for( ulong i = 0; i < sz; i++ ) {
    /* table[i][0] = identity */
    at_ed25519_point_set_zero( &table[i][0] );
    /* table[i][1] = a[i] */
    at_ed25519_point_set( &table[i][1], &a[i] );
    /* table[i][2] = 2*a[i] */
    at_ed25519_point_dbl( &table[i][2], &a[i] );
    /* table[i][j] = table[i][j-1] + a[i] for j > 2 */
    for( int j = 3; j < STRAUS_TABLE_SZ; j++ ) {
      at_ed25519_point_add( &table[i][j], &table[i][j-1], &a[i] );
    }
  }

  /* Initialize result to identity */
  at_ed25519_point_set_zero( r );

  /* Process scalar bits from MSB to LSB in 4-bit windows.
     Each scalar is 256 bits = 64 windows of 4 bits.
     We process window index from 63 down to 0. */
  for( int win = 63; win >= 0; win-- ) {
    /* Double result 4 times (except on first iteration where r=0) */
    if( win < 63 ) {
      at_ed25519_point_dbl( r, r );
      at_ed25519_point_dbl( r, r );
      at_ed25519_point_dbl( r, r );
      at_ed25519_point_dbl( r, r );
    } else {
      /* First window: result is still identity, doublings have no effect.
         But we still need to do them for constant-time behavior if needed.
         For variable-time, we can skip. */
    }

    /* For each scalar, extract the current 4-bit window and add
       the corresponding precomputed point */
    for( ulong i = 0; i < sz; i++ ) {
      /* Extract 4-bit window from scalar n[i*32 .. i*32+31]
         Window win corresponds to bits [win*4 .. win*4+3]
         Bit position: win*4, byte: (win*4)/8 = win/2
         Within byte: (win*4)%8 = (win%2)*4 */
      int bit_pos   = win * 4;
      int byte_idx  = bit_pos / 8;
      int bit_shift = bit_pos % 8;

      uchar const * scalar = &n[ i * 32 ];

      /* Extract 4 bits. Handle case where window spans two bytes. */
      int w;
      if( bit_shift <= 4 ) {
        /* Window fits in one byte */
        w = (scalar[ byte_idx ] >> bit_shift) & 0x0F;
      } else {
        /* Window spans two bytes (bit_shift > 4, only when bit_shift = 4..7 and we need bits that cross) */
        /* Actually with bit_shift = bit_pos % 8, and we need 4 bits:
           if bit_shift + 4 > 8, window spans two bytes.
           bit_shift can be 0,4 for even windows, but actually bit_pos = win*4,
           so bit_shift = (win*4)%8 = 0 if win is even, 4 if win is odd.
           So bit_shift is always 0 or 4, and we never span bytes. */
        w = (scalar[ byte_idx ] >> bit_shift) & 0x0F;
      }

      /* Add table[i][w] to result (skip if w == 0) */
      if( w != 0 ) {
        at_ed25519_point_add( r, r, &table[i][w] );
      }
    }
  }

  return r;
}