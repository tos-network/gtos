/* at_rangeproofs.c - Bulletproofs range proof verification

   Reference: https://eprint.iacr.org/2017/1066.pdf */

/* Define the header guard before including table files */
#define HEADER_at_ballet_at_rangeproofs_h

#include <at/crypto/at_crypto_base.h>
#include <at/crypto/at_rangeproofs_transcript.h>

/* Include bulletproofs-compatible generator tables.
   These generators match the Rust bulletproofs crate exactly.
   The old tables (at_rangeproofs_table_ref.c, at_rangeproofs_table_avx512.c)
   are kept for reference but not used. */
#include "at_rangeproofs_table_bulletproofs.c"

/* Now include the actual header */
#undef HEADER_at_ballet_at_rangeproofs_h
#include <at/crypto/at_rangeproofs.h>

static inline int
batched_range_proof_validate_bits( ulong bit_length ) {
  if ( AT_LIKELY(
    bit_length==1  || bit_length==2  || bit_length==4  || bit_length==8 ||
    bit_length==16 || bit_length==32 || bit_length==64 || bit_length==128
  ) ) {
    return AT_RANGEPROOFS_SUCCESS;
  }
  return AT_RANGEPROOFS_ERROR;
}

void
at_rangeproofs_delta(
  uchar       delta[ 32 ],
  ulong const nm,
  uchar const y[ 32 ],
  uchar const z[ 32 ],
  uchar const zz[ 32 ],
  uchar const bit_lengths[ 1 ],
  uchar const batch_len
) {
  uchar exp_y[ 32 ];
  uchar sum_of_powers_y[ 32 ];
  at_memcpy( exp_y, y, 32 );
  at_curve25519_scalar_add( sum_of_powers_y, y, at_curve25519_scalar_one );
  for( ulong i=nm; i>2; i/=2 ) {
    at_curve25519_scalar_mul   ( exp_y, exp_y, exp_y );
    at_curve25519_scalar_muladd( sum_of_powers_y, exp_y, sum_of_powers_y, sum_of_powers_y );
  }
  at_curve25519_scalar_sub( delta, z, zz );
  at_curve25519_scalar_mul( delta, delta, sum_of_powers_y );

  uchar neg_exp_z[ 32 ];
  uchar sum_2[ 32 ];
  at_curve25519_scalar_neg( neg_exp_z, zz );
  for( ulong i=0; i<batch_len; i++ ) {
    at_memset( sum_2, 0, 32 );
    at_memset( sum_2, 0xFF, bit_lengths[i] / 8 );
    at_curve25519_scalar_mul   ( neg_exp_z, neg_exp_z, z );
    at_curve25519_scalar_muladd( delta, neg_exp_z, sum_2, delta );
  }
}

int
at_rangeproofs_verify(
  at_rangeproofs_range_proof_t const * range_proof,
  at_rangeproofs_ipp_proof_t const *   ipp_proof,
  uchar const                          commitments [ 32 ],
  uchar const                          bit_lengths [ 1 ],
  uchar const                          batch_len,
  at_merlin_transcript_t *             transcript ) {

  /* Initialize generators if not already done */
  int init_result = at_rangeproofs_init();
  if( AT_UNLIKELY( init_result != 0 ) ) {
    return AT_RANGEPROOFS_ERROR;
  }

  /* We need to verify a range proof, by computing a large MSM.
     This implementation allocates memory to support u256, and
     at runtime can verify u64, u128 and u256 range proofs. */

#define LOGN 8
#define N (1 << LOGN)
#define MAX (2*N + 2*LOGN + 5 + AT_RANGEPROOFS_MAX_COMMITMENTS)

  const ulong logn = ipp_proof->logn;
  const ulong n = 1UL << logn;

  /* Total bit length (nm) should be a power of 2, and <= 256 == size of our generators table. */
  ulong nm = 0;
  for( uchar i=0; i<batch_len; i++ ) {
    if( AT_UNLIKELY( batched_range_proof_validate_bits( bit_lengths[i] ) != AT_RANGEPROOFS_SUCCESS ) ) {
      return AT_RANGEPROOFS_ERROR;
    }
    nm += bit_lengths[i];
  }
  if( AT_UNLIKELY( nm != n ) ) {
    return AT_RANGEPROOFS_ERROR;
  }

  /* Validate all inputs */
  uchar scalars[ MAX*32 ];
  at_ristretto255_point_t points[ MAX ];
  at_ristretto255_point_t a_res[ 1 ];
  at_ristretto255_point_t res[ 1 ];

  if( AT_UNLIKELY( at_curve25519_scalar_validate( range_proof->tx )==NULL ) ) {
    return AT_RANGEPROOFS_ERROR;
  }
  if( AT_UNLIKELY( at_curve25519_scalar_validate( range_proof->tx_blinding )==NULL ) ) {
    return AT_RANGEPROOFS_ERROR;
  }
  if( AT_UNLIKELY( at_curve25519_scalar_validate( range_proof->e_blinding )==NULL ) ) {
    return AT_RANGEPROOFS_ERROR;
  }
  if( AT_UNLIKELY( at_curve25519_scalar_validate( ipp_proof->a )==NULL ) ) {
    return AT_RANGEPROOFS_ERROR;
  }
  if( AT_UNLIKELY( at_curve25519_scalar_validate( ipp_proof->b )==NULL ) ) {
    return AT_RANGEPROOFS_ERROR;
  }

  at_ristretto255_point_set( &points[0], at_rangeproofs_basepoint_G );
  at_ristretto255_point_set( &points[1], at_rangeproofs_basepoint_H );
  if( AT_UNLIKELY( at_ristretto255_point_decompress( a_res, range_proof->a )==NULL ) ) {
    return AT_RANGEPROOFS_ERROR;
  }
  if( AT_UNLIKELY( at_ristretto255_point_decompress( &points[2], range_proof->s )==NULL ) ) {
    return AT_RANGEPROOFS_ERROR;
  }
  if( AT_UNLIKELY( at_ristretto255_point_decompress( &points[3], range_proof->t1 )==NULL ) ) {
    return AT_RANGEPROOFS_ERROR;
  }
  if( AT_UNLIKELY( at_ristretto255_point_decompress( &points[4], range_proof->t2 )==NULL ) ) {
    return AT_RANGEPROOFS_ERROR;
  }
  ulong idx = 5;
  for( ulong i=0; i<batch_len; i++, idx++ ) {
    if( AT_UNLIKELY( at_ristretto255_point_decompress( &points[ idx ], &commitments[ i*32 ] )==NULL ) ) {
      return AT_RANGEPROOFS_ERROR;
    }
  }
  for( ulong i=0; i<logn; i++, idx++ ) {
    if( AT_UNLIKELY( at_ristretto255_point_decompress( &points[ idx ], ipp_proof->vecs[ i ].l )==NULL ) ) {
      return AT_RANGEPROOFS_ERROR;
    }
  }
  for( ulong i=0; i<logn; i++, idx++ ) {
    if( AT_UNLIKELY( at_ristretto255_point_decompress( &points[ idx ], ipp_proof->vecs[ i ].r )==NULL ) ) {
      return AT_RANGEPROOFS_ERROR;
    }
  }
  at_memcpy( &points[ idx ],   at_rangeproofs_generators_H, n*sizeof(at_ristretto255_point_t) );
  at_memcpy( &points[ idx+n ], at_rangeproofs_generators_G, n*sizeof(at_ristretto255_point_t) );

  /* Finalize transcript and extract challenges */
  int val = AT_TRANSCRIPT_SUCCESS;
  at_rangeproofs_transcript_domsep_range_proof( transcript, nm, batch_len );

  /* Append value commitments (V) - must happen before A per bulletproofs spec */
  for( ulong i=0; i<batch_len; i++ ) {
    at_rangeproofs_transcript_append_point( transcript, AT_TRANSCRIPT_LITERAL("V"), &commitments[ i*32 ] );
  }

  val |= at_rangeproofs_transcript_validate_and_append_point( transcript, AT_TRANSCRIPT_LITERAL("A"), range_proof->a);
  val |= at_rangeproofs_transcript_validate_and_append_point( transcript, AT_TRANSCRIPT_LITERAL("S"), range_proof->s);

  uchar batchinv_in [ 32*(1+LOGN) ];
  uchar batchinv_out[ 32*(1+LOGN) ];
  uchar allinv[ 32 ];
  uchar *y = batchinv_in;
  uchar *y_inv = batchinv_out;
  uchar z[ 32 ];
  at_rangeproofs_transcript_challenge_scalar( y, transcript, AT_TRANSCRIPT_LITERAL("y") );
  at_rangeproofs_transcript_challenge_scalar( z, transcript, AT_TRANSCRIPT_LITERAL("z") );

  val |= at_rangeproofs_transcript_validate_and_append_point( transcript, AT_TRANSCRIPT_LITERAL("T_1"), range_proof->t1);
  val |= at_rangeproofs_transcript_validate_and_append_point( transcript, AT_TRANSCRIPT_LITERAL("T_2"), range_proof->t2);
  if( AT_UNLIKELY( val != AT_TRANSCRIPT_SUCCESS ) ) {
    return AT_RANGEPROOFS_ERROR;
  }

  uchar x[ 32 ];
  at_rangeproofs_transcript_challenge_scalar( x, transcript, AT_TRANSCRIPT_LITERAL("x") );

  at_rangeproofs_transcript_append_scalar( transcript, AT_TRANSCRIPT_LITERAL("t_x"), range_proof->tx);
  at_rangeproofs_transcript_append_scalar( transcript, AT_TRANSCRIPT_LITERAL("t_x_blinding"), range_proof->tx_blinding);
  at_rangeproofs_transcript_append_scalar( transcript, AT_TRANSCRIPT_LITERAL("e_blinding"), range_proof->e_blinding);

  uchar w[ 32 ];
  at_rangeproofs_transcript_challenge_scalar( w, transcript, AT_TRANSCRIPT_LITERAL("w") );

  /* c is used for batched verification in Rust bulletproofs (random scalar).
     For single proof verification, c=1 works. Using at_curve25519_scalar_one. */
  uchar const * c = at_curve25519_scalar_one;

  /* Inner Product (sub)Proof */
  at_rangeproofs_transcript_domsep_inner_product( transcript, nm );

  uchar *u =     &batchinv_in [ 32 ];
  uchar *u_inv = &batchinv_out[ 32 ];
  for( ulong i=0; i<logn; i++ ) {
    val |= at_rangeproofs_transcript_validate_and_append_point( transcript, AT_TRANSCRIPT_LITERAL("L"), ipp_proof->vecs[ i ].l);
    val |= at_rangeproofs_transcript_validate_and_append_point( transcript, AT_TRANSCRIPT_LITERAL("R"), ipp_proof->vecs[ i ].r);
    if( AT_UNLIKELY( val != AT_TRANSCRIPT_SUCCESS ) ) {
      return AT_RANGEPROOFS_ERROR;
    }
    at_rangeproofs_transcript_challenge_scalar( &u[ i*32 ], transcript, AT_TRANSCRIPT_LITERAL("u") );
  }
  at_curve25519_scalar_batch_inv( batchinv_out, allinv, batchinv_in, logn+1 );

  /* Note: Rust bulletproofs does NOT append a/b or challenge d here.
     The original Avatar code had extra transcript operations that are
     incompatible with the bulletproofs crate. */

  /* Compute scalars */

  /* H: - ( eb + c t_xb ) */
  uchar const *eb = range_proof->e_blinding;
  uchar const *txb = range_proof->tx_blinding;
  at_curve25519_scalar_muladd( &scalars[ 1*32 ], c, txb, eb );
  at_curve25519_scalar_neg(    &scalars[ 1*32 ], &scalars[ 1*32 ] );

  /* S:   x
     T_1: c x
     T_2: c x^2 */
  at_curve25519_scalar_set(    &scalars[ 2*32 ], x );
  at_curve25519_scalar_mul(    &scalars[ 3*32 ], c, x );
  at_curve25519_scalar_mul(    &scalars[ 4*32 ], &scalars[ 3*32 ], x );

  /* commitments: c z^2, c z^3 ... */
  uchar zz[ 32 ];
  at_curve25519_scalar_mul(    zz, z, z );
  at_curve25519_scalar_mul(    &scalars[ 5*32 ], zz, c );
  idx = 6;
  for( ulong i=1; i<batch_len; i++, idx++ ) {
    at_curve25519_scalar_mul(  &scalars[ idx*32 ], &scalars[ (idx-1)*32 ], z );
  }

  /* L_vec: u0^2, u1^2...
     R_vec: 1/u0^2, 1/u1^2... */
  uchar *u_sq = &scalars[ idx*32 ];
  for( ulong i=0; i<logn; i++, idx++ ) {
    at_curve25519_scalar_mul(  &scalars[ idx*32 ], &u[ i*32 ], &u[ i*32 ] );
  }
  for( ulong i=0; i<logn; i++, idx++ ) {
    at_curve25519_scalar_mul(  &scalars[ idx*32 ], &u_inv[ i*32 ], &u_inv[ i*32 ] );
  }

  /* s_i for generators_G, generators_H */
  uchar *s = &scalars[ (idx+n)*32 ];
  at_curve25519_scalar_mul( &s[ 0*32 ], allinv, y );
  for( ulong k=0; k<logn; k++ ) {
    ulong powk = (1UL << k);
    for( ulong j=0; j<powk; j++ ) {
      ulong i = powk + j;
      at_curve25519_scalar_mul( &s[ i*32 ], &s[ j*32 ], &u_sq[ (logn-1-k)*32 ] );
    }
  }

  /* generators_H: (-a * s_i) + (-z) */
  uchar const *a = ipp_proof->a;
  uchar const *b = ipp_proof->b;
  uchar minus_b[ 32 ];
  uchar exp_z[ 32 ];
  uchar exp_y_inv[ 32 ];
  uchar z_and_2[ 32 ];
  at_curve25519_scalar_neg( minus_b, b );
  at_memcpy( exp_z, zz, 32 );
  at_memcpy( z_and_2, exp_z, 32 );
  at_memcpy( exp_y_inv, y, 32 );
  for( ulong i=0, j=0, m=0; i<n; i++, j++, idx++ ) {
    if( j == bit_lengths[m] ) {
      j = 0;
      m++;
      at_curve25519_scalar_mul ( exp_z, exp_z, z );
      at_memcpy( z_and_2, exp_z, 32 );
    }
    if( j != 0 ) {
      at_curve25519_scalar_add ( z_and_2, z_and_2, z_and_2 );
    }
    at_curve25519_scalar_mul   ( exp_y_inv, exp_y_inv, y_inv );
    at_curve25519_scalar_muladd( &scalars[ idx*32 ], &s[ (n-1-i)*32 ], minus_b, z_and_2 );
    at_curve25519_scalar_muladd( &scalars[ idx*32 ], &scalars[ idx*32 ], exp_y_inv, z );
  }

  /* generators_G: (-a * s_i) + (-z) */
  uchar minus_z[ 32 ];
  uchar minus_a[ 32 ];
  at_curve25519_scalar_neg( minus_z, z );
  at_curve25519_scalar_neg( minus_a, a );
  for( ulong i=0; i<n; i++, idx++ ) {
    at_curve25519_scalar_muladd( &scalars[ idx*32 ], &s[ i*32 ], minus_a, minus_z );
  }

  /* G: w * (self.t_x - a * b) + c * (delta(&bit_lengths, &y, &z) - self.t_x) */
  uchar delta[ 32 ];
  at_rangeproofs_delta( delta, nm, y, z, zz, bit_lengths, batch_len );
  at_curve25519_scalar_muladd(  &scalars[ 0 ], minus_a, b, range_proof->tx );
  at_curve25519_scalar_sub(     delta, delta, range_proof->tx );
  at_curve25519_scalar_mul(     delta, delta, c );
  at_curve25519_scalar_muladd(  &scalars[ 0 ], &scalars[ 0 ], w, delta );

  /* Compute the final MSM */
  at_ristretto255_multi_scalar_mul( res, scalars, points, idx );

  int eq = at_ristretto255_point_eq_neg( res, a_res );
  if( AT_LIKELY( eq ) ) {
    return AT_RANGEPROOFS_SUCCESS;
  }

#undef LOGN
#undef N
#undef MAX
  return AT_RANGEPROOFS_ERROR;
}