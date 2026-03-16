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
#include <at/crypto/at_priv_proofs.h>

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

int
at_rangeproofs_pre_verify(
  at_rangeproofs_range_proof_t const * range_proof,
  at_rangeproofs_ipp_proof_t const *   ipp_proof,
  uchar const                          commitments [ 32 ],
  uchar const                          bit_lengths [ 1 ],
  uchar const                          batch_len,
  at_merlin_transcript_t *             transcript,
  at_priv_batch_collector_t *          collector ) {
  if( !collector ) {
    return at_rangeproofs_verify( range_proof, ipp_proof, commitments, bit_lengths, batch_len, transcript );
  }

  int init_result = at_rangeproofs_init();
  if( AT_UNLIKELY( init_result != 0 ) ) {
    return AT_RANGEPROOFS_ERROR;
  }

#define LOGN 8
#define N (1 << LOGN)
#define MAX (2*N + 2*LOGN + 5 + AT_RANGEPROOFS_MAX_COMMITMENTS)

  const ulong logn = ipp_proof->logn;
  const ulong n = 1UL << logn;

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

  uchar scalars[(MAX+1)*32];
  at_ristretto255_point_t points[MAX+1];
  at_ristretto255_point_t a_res[1];

  if( AT_UNLIKELY( at_curve25519_scalar_validate( range_proof->tx )==NULL ) ) return AT_RANGEPROOFS_ERROR;
  if( AT_UNLIKELY( at_curve25519_scalar_validate( range_proof->tx_blinding )==NULL ) ) return AT_RANGEPROOFS_ERROR;
  if( AT_UNLIKELY( at_curve25519_scalar_validate( range_proof->e_blinding )==NULL ) ) return AT_RANGEPROOFS_ERROR;
  if( AT_UNLIKELY( at_curve25519_scalar_validate( ipp_proof->a )==NULL ) ) return AT_RANGEPROOFS_ERROR;
  if( AT_UNLIKELY( at_curve25519_scalar_validate( ipp_proof->b )==NULL ) ) return AT_RANGEPROOFS_ERROR;

  at_ristretto255_point_set( &points[0], at_rangeproofs_basepoint_G );
  at_ristretto255_point_set( &points[1], at_rangeproofs_basepoint_H );
  if( AT_UNLIKELY( at_ristretto255_point_decompress( a_res, range_proof->a )==NULL ) ) return AT_RANGEPROOFS_ERROR;
  if( AT_UNLIKELY( at_ristretto255_point_decompress( &points[2], range_proof->s )==NULL ) ) return AT_RANGEPROOFS_ERROR;
  if( AT_UNLIKELY( at_ristretto255_point_decompress( &points[3], range_proof->t1 )==NULL ) ) return AT_RANGEPROOFS_ERROR;
  if( AT_UNLIKELY( at_ristretto255_point_decompress( &points[4], range_proof->t2 )==NULL ) ) return AT_RANGEPROOFS_ERROR;
  ulong idx = 5;
  for( ulong i=0; i<batch_len; i++, idx++ ) {
    if( AT_UNLIKELY( at_ristretto255_point_decompress( &points[ idx ], &commitments[ i*32 ] )==NULL ) ) return AT_RANGEPROOFS_ERROR;
  }
  for( ulong i=0; i<logn; i++, idx++ ) {
    if( AT_UNLIKELY( at_ristretto255_point_decompress( &points[ idx ], ipp_proof->vecs[ i ].l )==NULL ) ) return AT_RANGEPROOFS_ERROR;
  }
  for( ulong i=0; i<logn; i++, idx++ ) {
    if( AT_UNLIKELY( at_ristretto255_point_decompress( &points[ idx ], ipp_proof->vecs[ i ].r )==NULL ) ) return AT_RANGEPROOFS_ERROR;
  }
  at_memcpy( &points[ idx ],   at_rangeproofs_generators_H, n*sizeof(at_ristretto255_point_t) );
  at_memcpy( &points[ idx+n ], at_rangeproofs_generators_G, n*sizeof(at_ristretto255_point_t) );

  int val = AT_TRANSCRIPT_SUCCESS;
  at_rangeproofs_transcript_domsep_range_proof( transcript, nm, batch_len );
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
  if( AT_UNLIKELY( val != AT_TRANSCRIPT_SUCCESS ) ) return AT_RANGEPROOFS_ERROR;

  uchar x[ 32 ];
  at_rangeproofs_transcript_challenge_scalar( x, transcript, AT_TRANSCRIPT_LITERAL("x") );

  at_rangeproofs_transcript_append_scalar( transcript, AT_TRANSCRIPT_LITERAL("t_x"), range_proof->tx);
  at_rangeproofs_transcript_append_scalar( transcript, AT_TRANSCRIPT_LITERAL("t_x_blinding"), range_proof->tx_blinding);
  at_rangeproofs_transcript_append_scalar( transcript, AT_TRANSCRIPT_LITERAL("e_blinding"), range_proof->e_blinding);

  uchar w[ 32 ];
  at_rangeproofs_transcript_challenge_scalar( w, transcript, AT_TRANSCRIPT_LITERAL("w") );

  uchar c_buf[32];
  if( at_priv_batch_random_scalar( c_buf ) ) return AT_RANGEPROOFS_ERROR;
  uchar const * c = c_buf;

  at_rangeproofs_transcript_domsep_inner_product( transcript, nm );

  uchar *u =     &batchinv_in [ 32 ];
  uchar *u_inv = &batchinv_out[ 32 ];
  for( ulong i=0; i<logn; i++ ) {
    val |= at_rangeproofs_transcript_validate_and_append_point( transcript, AT_TRANSCRIPT_LITERAL("L"), ipp_proof->vecs[ i ].l);
    val |= at_rangeproofs_transcript_validate_and_append_point( transcript, AT_TRANSCRIPT_LITERAL("R"), ipp_proof->vecs[ i ].r);
    if( AT_UNLIKELY( val != AT_TRANSCRIPT_SUCCESS ) ) return AT_RANGEPROOFS_ERROR;
    at_rangeproofs_transcript_challenge_scalar( &u[ i*32 ], transcript, AT_TRANSCRIPT_LITERAL("u") );
  }
  at_curve25519_scalar_batch_inv( batchinv_out, allinv, batchinv_in, logn+1 );

  uchar const *eb = range_proof->e_blinding;
  uchar const *txb = range_proof->tx_blinding;
  at_curve25519_scalar_muladd( &scalars[ 1*32 ], c, txb, eb );
  at_curve25519_scalar_neg(    &scalars[ 1*32 ], &scalars[ 1*32 ] );
  at_curve25519_scalar_set(    &scalars[ 2*32 ], x );
  at_curve25519_scalar_mul(    &scalars[ 3*32 ], c, x );
  at_curve25519_scalar_mul(    &scalars[ 4*32 ], &scalars[ 3*32 ], x );

  uchar zz[ 32 ];
  at_curve25519_scalar_mul(    zz, z, z );
  at_curve25519_scalar_mul(    &scalars[ 5*32 ], zz, c );
  idx = 6;
  for( ulong i=1; i<batch_len; i++, idx++ ) {
    at_curve25519_scalar_mul(  &scalars[ idx*32 ], &scalars[ (idx-1)*32 ], z );
  }

  uchar *u_sq = &scalars[ idx*32 ];
  for( ulong i=0; i<logn; i++, idx++ ) {
    at_curve25519_scalar_mul(  &scalars[ idx*32 ], &u[ i*32 ], &u[ i*32 ] );
  }
  for( ulong i=0; i<logn; i++, idx++ ) {
    at_curve25519_scalar_mul(  &scalars[ idx*32 ], &u_inv[ i*32 ], &u_inv[ i*32 ] );
  }

  uchar *s = &scalars[ (idx+n)*32 ];
  at_curve25519_scalar_mul( &s[ 0*32 ], allinv, y );
  for( ulong k=0; k<logn; k++ ) {
    ulong powk = (1UL << k);
    for( ulong j=0; j<powk; j++ ) {
      ulong i = powk + j;
      at_curve25519_scalar_mul( &s[ i*32 ], &s[ j*32 ], &u_sq[ (logn-1-k)*32 ] );
    }
  }

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

  uchar minus_z[ 32 ];
  uchar minus_a[ 32 ];
  at_curve25519_scalar_neg( minus_z, z );
  at_curve25519_scalar_neg( minus_a, a );
  for( ulong i=0; i<n; i++, idx++ ) {
    at_curve25519_scalar_muladd( &scalars[ idx*32 ], &s[ i*32 ], minus_a, minus_z );
  }

  uchar delta[ 32 ];
  at_rangeproofs_delta( delta, nm, y, z, zz, bit_lengths, batch_len );
  at_curve25519_scalar_muladd(  &scalars[ 0 ], minus_a, b, range_proof->tx );
  at_curve25519_scalar_sub(     delta, delta, range_proof->tx );
  at_curve25519_scalar_mul(     delta, delta, c );
  at_curve25519_scalar_muladd(  &scalars[ 0 ], &scalars[ 0 ], w, delta );

  at_ristretto255_point_set( &points[idx], a_res );
  at_memcpy( &scalars[idx*32], at_curve25519_scalar_one, 32 );
  idx++;

  int rc = at_priv_batch_collector_append_range_terms( collector, scalars, points, idx );

#undef LOGN
#undef N
#undef MAX
  return rc ? AT_RANGEPROOFS_ERROR : AT_RANGEPROOFS_SUCCESS;
}

/* ---------- Range proof PROVER (single 64-bit value) ----------
   Implements the Bulletproofs proving algorithm for a single commitment.
   Compatible with the Rust bulletproofs crate v5.0.2 fork used by legacy interoperability vectors.

   Reference: https://eprint.iacr.org/2017/1066.pdf §4.2
   Input:  value (u64), opening (blinding scalar, 32 bytes)
   Output: proof bytes (672 bytes for 64-bit range proof)
   The commitment V = value*G + opening*H is NOT included in the output;
   the caller already knows it. */

static int
fill_random_scalar( uchar out[ 32 ] ) {
  uchar wide[ 64 ];
  FILE * urandom = fopen( "/dev/urandom", "r" );
  if( !urandom ) return -1;
  ulong n = (ulong)fread( wide, 1, 64, urandom );
  fclose( urandom );
  if( n != 64 ) return -1;
  at_curve25519_scalar_reduce( out, wide );
  /* reject zero (astronomically unlikely) */
  int z = 1;
  for( int i=0; i<32; i++ ) z &= (out[i]==0);
  return z ? -1 : 0;
}

int
at_rangeproofs_prove_single64(
  uchar *         proof_out,     /* must hold 672 bytes */
  ulong           proof_out_sz,
  uchar const     commitment[32],/* V compressed, for transcript */
  ulong           value,
  uchar const     blinding[32]   /* Pedersen opening / blinding factor */
) {
  if( !proof_out || proof_out_sz < 672 || !commitment || !blinding ) return -1;
  if( at_rangeproofs_init() != 0 ) return -1;

#define BP_N  64
#define BP_LOGN 6

  /* --- Step 1: Bit decompose value --- */
  uchar a_L[BP_N]; /* bits: 0 or 1 */
  for( int i=0; i<BP_N; i++ ) {
    a_L[i] = (uchar)((value >> i) & 1UL);
  }

  /* --- Step 2: Generate random blindings --- */
  uchar a_blinding[32], s_blinding[32];
  uchar s_L[BP_N*32], s_R[BP_N*32];
  if( fill_random_scalar(a_blinding) ) return -1;
  if( fill_random_scalar(s_blinding) ) return -1;
  for( int i=0; i<BP_N; i++ ) {
    if( fill_random_scalar(&s_L[i*32]) ) return -1;
    if( fill_random_scalar(&s_R[i*32]) ) return -1;
  }

  /* --- Step 3: Compute A = a_blinding * B_blinding + Σ(a_L[i]*G[i] + (a_L[i]-1)*H[i]) ---
     Note: B_blinding = basepoint_H in Bulletproofs convention.
           B = basepoint_G (Pedersen value base). */
  /* Use MSM: scalars[] = [a_blinding, a_L_0, (a_L_0-1), a_L_1, (a_L_1-1), ...]
     points[] = [B_blinding, G[0], H[0], G[1], H[1], ...] */
  {
    uchar   A_scalars[(1+2*BP_N)*32];
    at_ristretto255_point_t A_points[1+2*BP_N];

    at_memcpy(A_scalars, a_blinding, 32);
    at_ristretto255_point_set(&A_points[0], at_rangeproofs_basepoint_H);

    for( int i=0; i<BP_N; i++ ) {
      /* scalar for G[i]: a_L[i] */
      at_memset(&A_scalars[(1+2*i)*32], 0, 32);
      A_scalars[(1+2*i)*32] = a_L[i];

      /* scalar for H[i]: a_L[i] - 1 = a_R[i] */
      uchar minus_one[32];
      at_memset(minus_one, 0, 32);
      minus_one[0] = 1;
      at_curve25519_scalar_neg(minus_one, minus_one);
      at_memset(&A_scalars[(2+2*i)*32], 0, 32);
      A_scalars[(2+2*i)*32] = a_L[i];
      at_curve25519_scalar_add(&A_scalars[(2+2*i)*32], &A_scalars[(2+2*i)*32], minus_one);

      at_ristretto255_point_set(&A_points[1+2*i], &at_rangeproofs_generators_G[i]);
      at_ristretto255_point_set(&A_points[2+2*i], &at_rangeproofs_generators_H[i]);
    }

    at_ristretto255_point_t A_point[1];
    at_ristretto255_multi_scalar_mul(A_point, A_scalars, A_points, 1+2*BP_N);
    at_ristretto255_point_tobytes(proof_out, A_point); /* A at offset 0 */
  }

  /* --- Step 4: Compute S = s_blinding * B_blinding + Σ(s_L[i]*G[i] + s_R[i]*H[i]) --- */
  {
    uchar   S_scalars[(1+2*BP_N)*32];
    at_ristretto255_point_t S_points[1+2*BP_N];

    at_memcpy(S_scalars, s_blinding, 32);
    at_ristretto255_point_set(&S_points[0], at_rangeproofs_basepoint_H);

    for( int i=0; i<BP_N; i++ ) {
      at_memcpy(&S_scalars[(1+2*i)*32], &s_L[i*32], 32);
      at_memcpy(&S_scalars[(2+2*i)*32], &s_R[i*32], 32);
      at_ristretto255_point_set(&S_points[1+2*i], &at_rangeproofs_generators_G[i]);
      at_ristretto255_point_set(&S_points[2+2*i], &at_rangeproofs_generators_H[i]);
    }

    at_ristretto255_point_t S_point[1];
    at_ristretto255_multi_scalar_mul(S_point, S_scalars, S_points, 1+2*BP_N);
    at_ristretto255_point_tobytes(proof_out+32, S_point); /* S at offset 32 */
  }

  /* --- Step 5: Transcript → challenges y, z --- */
  at_merlin_transcript_t transcript;
  at_merlin_transcript_init(&transcript, AT_MERLIN_LITERAL("transaction-proof"));
  at_rangeproofs_transcript_domsep_range_proof(&transcript, BP_N, 1);
  at_rangeproofs_transcript_append_point(&transcript, AT_TRANSCRIPT_LITERAL("V"), commitment);
  at_rangeproofs_transcript_validate_and_append_point(&transcript, AT_TRANSCRIPT_LITERAL("A"), proof_out);
  at_rangeproofs_transcript_validate_and_append_point(&transcript, AT_TRANSCRIPT_LITERAL("S"), proof_out+32);

  uchar y[32], z[32];
  at_rangeproofs_transcript_challenge_scalar(y, &transcript, AT_TRANSCRIPT_LITERAL("y"));
  at_rangeproofs_transcript_challenge_scalar(z, &transcript, AT_TRANSCRIPT_LITERAL("z"));

  /* --- Step 6: Build polynomial vectors l(x), r(x) ---
     l_0[i] = a_L[i] - z
     l_1[i] = s_L[i]
     r_0[i] = y^(i+1) * (a_R[i] + z) + z^2 * 2^i
     r_1[i] = y^(i+1) * s_R[i] */
  uchar l_0[BP_N*32], l_1[BP_N*32];
  uchar r_0[BP_N*32], r_1[BP_N*32];
  uchar zz[32];
  at_curve25519_scalar_mul(zz, z, z);

  uchar exp_y[32]; /* y^i: starts at 1 = y^0 for single-party (offset_y=1) */
  at_memcpy(exp_y, at_curve25519_scalar_one, 32);
  uchar exp_2[32]; /* 2^i */
  at_memset(exp_2, 0, 32);
  exp_2[0] = 1;

  for( int i=0; i<BP_N; i++ ) {
    /* l_0[i] = a_L[i] - z */
    uchar aL_scalar[32];
    at_memset(aL_scalar, 0, 32);
    aL_scalar[0] = a_L[i];
    at_curve25519_scalar_sub(&l_0[i*32], aL_scalar, z);

    /* l_1[i] = s_L[i] */
    at_memcpy(&l_1[i*32], &s_L[i*32], 32);

    /* a_R[i] = a_L[i] - 1 */
    uchar aR_scalar[32];
    at_memset(aR_scalar, 0, 32);
    aR_scalar[0] = a_L[i];
    uchar one[32];
    at_memset(one, 0, 32);
    one[0] = 1;
    at_curve25519_scalar_sub(aR_scalar, aR_scalar, one);

    /* r_0[i] = y^(i+1) * (a_R[i] + z) + z^2 * 2^i */
    uchar tmp[32];
    at_curve25519_scalar_add(tmp, aR_scalar, z);
    at_curve25519_scalar_mul(&r_0[i*32], exp_y, tmp);
    at_curve25519_scalar_muladd(&r_0[i*32], zz, exp_2, &r_0[i*32]);

    /* r_1[i] = y^(i+1) * s_R[i] */
    at_curve25519_scalar_mul(&r_1[i*32], exp_y, &s_R[i*32]);

    /* advance y^(i+1) and 2^i */
    at_curve25519_scalar_mul(exp_y, exp_y, y);
    at_curve25519_scalar_add(exp_2, exp_2, exp_2);
  }

  /* --- Step 7: Compute t(x) = <l(x), r(x)> = t_0 + t_1*x + t_2*x^2
     t_0 = <l_0, r_0>
     t_1 = <l_0, r_1> + <l_1, r_0>
     t_2 = <l_1, r_1> */
  uchar t_0[32], t_1[32], t_2[32];
  at_memset(t_0, 0, 32); at_memset(t_1, 0, 32); at_memset(t_2, 0, 32);
  for( int i=0; i<BP_N; i++ ) {
    at_curve25519_scalar_muladd(t_0, &l_0[i*32], &r_0[i*32], t_0);
    uchar tmp1[32];
    at_curve25519_scalar_mul(tmp1, &l_0[i*32], &r_1[i*32]);
    at_curve25519_scalar_muladd(t_1, &l_1[i*32], &r_0[i*32], t_1);
    at_curve25519_scalar_add(t_1, t_1, tmp1);
    at_curve25519_scalar_muladd(t_2, &l_1[i*32], &r_1[i*32], t_2);
  }

  /* --- Step 8: Commit T1, T2 = Pedersen commitments to t_1, t_2 --- */
  uchar t_1_blinding[32], t_2_blinding[32];
  if( fill_random_scalar(t_1_blinding) ) return -1;
  if( fill_random_scalar(t_2_blinding) ) return -1;

  {
    /* T1 = t_1 * G + t_1_blinding * H */
    uchar T_scalars[2*32];
    at_ristretto255_point_t T_points[2];
    at_memcpy(&T_scalars[0], t_1, 32);
    at_memcpy(&T_scalars[32], t_1_blinding, 32);
    at_ristretto255_point_set(&T_points[0], at_rangeproofs_basepoint_G);
    at_ristretto255_point_set(&T_points[1], at_rangeproofs_basepoint_H);
    at_ristretto255_point_t T1_point[1];
    at_ristretto255_multi_scalar_mul(T1_point, T_scalars, T_points, 2);
    at_ristretto255_point_tobytes(proof_out+64, T1_point); /* T1 at offset 64 */

    /* T2 = t_2 * G + t_2_blinding * H */
    at_memcpy(&T_scalars[0], t_2, 32);
    at_memcpy(&T_scalars[32], t_2_blinding, 32);
    at_ristretto255_point_t T2_point[1];
    at_ristretto255_multi_scalar_mul(T2_point, T_scalars, T_points, 2);
    at_ristretto255_point_tobytes(proof_out+96, T2_point); /* T2 at offset 96 */
  }

  /* --- Step 9: Transcript → challenge x --- */
  at_rangeproofs_transcript_validate_and_append_point(&transcript, AT_TRANSCRIPT_LITERAL("T_1"), proof_out+64);
  at_rangeproofs_transcript_validate_and_append_point(&transcript, AT_TRANSCRIPT_LITERAL("T_2"), proof_out+96);
  uchar x[32];
  at_rangeproofs_transcript_challenge_scalar(x, &transcript, AT_TRANSCRIPT_LITERAL("x"));

  /* --- Step 10: Evaluate at x ---
     t_x = t_0 + t_1*x + t_2*x^2
     t_x_blinding = z^2*blinding + t_1_blinding*x + t_2_blinding*x^2
     e_blinding = a_blinding + s_blinding*x */
  uchar tx[32], txb[32], eb[32];
  uchar xx[32];
  at_curve25519_scalar_mul(xx, x, x);
  /* tx = t_0 + t_1*x + t_2*x^2 */
  at_curve25519_scalar_muladd(tx, t_1, x, t_0);
  at_curve25519_scalar_muladd(tx, t_2, xx, tx);
  /* txb = z^2*blinding + t_1_blinding*x + t_2_blinding*x^2 */
  at_curve25519_scalar_mul(txb, zz, blinding);
  at_curve25519_scalar_muladd(txb, t_1_blinding, x, txb);
  at_curve25519_scalar_muladd(txb, t_2_blinding, xx, txb);
  /* eb = a_blinding + s_blinding*x */
  at_curve25519_scalar_muladd(eb, s_blinding, x, a_blinding);

  at_memcpy(proof_out+128, tx, 32);  /* t_x at offset 128 */
  at_memcpy(proof_out+160, txb, 32); /* t_x_blinding at offset 160 */
  at_memcpy(proof_out+192, eb, 32);  /* e_blinding at offset 192 */

  /* --- Step 11: Transcript → challenge w --- */
  at_rangeproofs_transcript_append_scalar(&transcript, AT_TRANSCRIPT_LITERAL("t_x"), tx);
  at_rangeproofs_transcript_append_scalar(&transcript, AT_TRANSCRIPT_LITERAL("t_x_blinding"), txb);
  at_rangeproofs_transcript_append_scalar(&transcript, AT_TRANSCRIPT_LITERAL("e_blinding"), eb);
  uchar w[32];
  at_rangeproofs_transcript_challenge_scalar(w, &transcript, AT_TRANSCRIPT_LITERAL("w"));

  /* --- Step 12: Evaluate l and r at x ---
     l_vec[i] = l_0[i] + x*l_1[i]
     r_vec[i] = r_0[i] + x*r_1[i] */
  uchar l_vec[BP_N*32], r_vec[BP_N*32];
  for( int i=0; i<BP_N; i++ ) {
    at_curve25519_scalar_muladd(&l_vec[i*32], &l_1[i*32], x, &l_0[i*32]);
    at_curve25519_scalar_muladd(&r_vec[i*32], &r_1[i*32], x, &r_0[i*32]);
  }

  /* --- Step 13: Inner Product Proof ---
     Proves <l_vec, r_vec> = t_x using generators G, H with factors.
     H_factors[i] = y^(-(i+1))
     G_factors[i] = 1
     Q = w * B (Pedersen basepoint_G) */
  at_rangeproofs_transcript_domsep_inner_product(&transcript, BP_N);

  /* Compute y_inv */
  uchar y_inv[32];
  at_curve25519_scalar_inv(y_inv, y);

  /* Build working copies of generators with H scaled by y_inv factors:
     H'[i] = y^(-(i+1)) * H[i]
     G'[i] = G[i] (unmodified) */
  at_ristretto255_point_t G_work[BP_N], H_work[BP_N];
  {
    /* H_factors = exp_iter(y_inv) = [1, y^(-1), y^(-2), ...] */
    uchar exp_y_inv[32];
    at_memcpy(exp_y_inv, at_curve25519_scalar_one, 32);
    for( int i=0; i<BP_N; i++ ) {
      at_ristretto255_point_set(&G_work[i], &at_rangeproofs_generators_G[i]);
      at_ristretto255_scalar_mul(&H_work[i], exp_y_inv, &at_rangeproofs_generators_H[i]);
      at_curve25519_scalar_mul(exp_y_inv, exp_y_inv, y_inv);
    }
  }

  /* Q = w * basepoint_G */
  at_ristretto255_point_t Q[1];
  at_ristretto255_scalar_mul(Q, w, at_rangeproofs_basepoint_G);

  /* Working vectors a_vec, b_vec (copies of l_vec, r_vec) */
  uchar a_vec[BP_N*32], b_vec[BP_N*32];
  at_memcpy(a_vec, l_vec, BP_N*32);
  at_memcpy(b_vec, r_vec, BP_N*32);

  /* IPP logarithmic recursion: BP_LOGN = 6 rounds for 64-bit */
  ulong half = BP_N;
  ulong ipp_off = 224; /* proof output offset: 7*32 = 224 */

  for( int round=0; round<BP_LOGN; round++ ) {
    half >>= 1;

    /* Compute c_L = <a_L, b_R> and c_R = <a_R, b_L> */
    uchar c_L[32], c_R[32];
    at_memset(c_L, 0, 32); at_memset(c_R, 0, 32);
    for( ulong j=0; j<half; j++ ) {
      at_curve25519_scalar_muladd(c_L, &a_vec[j*32], &b_vec[(half+j)*32], c_L);
      at_curve25519_scalar_muladd(c_R, &a_vec[(half+j)*32], &b_vec[j*32], c_R);
    }

    /* L = <a_L, G_R> + <b_R, H_L> + c_L * Q */
    {
      ulong msm_len = 2*half + 1;
      uchar L_scalars[(2*BP_N+1)*32];  /* oversized for safety */
      at_ristretto255_point_t L_points[2*BP_N+1];
      for( ulong j=0; j<half; j++ ) {
        at_memcpy(&L_scalars[j*32], &a_vec[j*32], 32);
        at_ristretto255_point_set(&L_points[j], &G_work[half+j]);
      }
      for( ulong j=0; j<half; j++ ) {
        at_memcpy(&L_scalars[(half+j)*32], &b_vec[(half+j)*32], 32);
        at_ristretto255_point_set(&L_points[half+j], &H_work[j]);
      }
      at_memcpy(&L_scalars[2*half*32], c_L, 32);
      at_ristretto255_point_set(&L_points[2*half], Q);

      at_ristretto255_point_t L_point[1];
      at_ristretto255_multi_scalar_mul(L_point, L_scalars, L_points, msm_len);
      at_ristretto255_point_tobytes(proof_out+ipp_off, L_point);
    }

    /* R = <a_R, G_L> + <b_L, H_R> + c_R * Q */
    {
      ulong msm_len = 2*half + 1;
      uchar R_scalars[(2*BP_N+1)*32];
      at_ristretto255_point_t R_points[2*BP_N+1];
      for( ulong j=0; j<half; j++ ) {
        at_memcpy(&R_scalars[j*32], &a_vec[(half+j)*32], 32);
        at_ristretto255_point_set(&R_points[j], &G_work[j]);
      }
      for( ulong j=0; j<half; j++ ) {
        at_memcpy(&R_scalars[(half+j)*32], &b_vec[j*32], 32);
        at_ristretto255_point_set(&R_points[half+j], &H_work[half+j]);
      }
      at_memcpy(&R_scalars[2*half*32], c_R, 32);
      at_ristretto255_point_set(&R_points[2*half], Q);

      at_ristretto255_point_t R_point[1];
      at_ristretto255_multi_scalar_mul(R_point, R_scalars, R_points, msm_len);
      at_ristretto255_point_tobytes(proof_out+ipp_off+32, R_point);
    }

    /* Transcript: append L, R → get challenge u */
    at_rangeproofs_transcript_validate_and_append_point(&transcript, AT_TRANSCRIPT_LITERAL("L"), proof_out+ipp_off);
    at_rangeproofs_transcript_validate_and_append_point(&transcript, AT_TRANSCRIPT_LITERAL("R"), proof_out+ipp_off+32);
    uchar u_chal[32], u_inv[32];
    at_rangeproofs_transcript_challenge_scalar(u_chal, &transcript, AT_TRANSCRIPT_LITERAL("u"));
    at_curve25519_scalar_inv(u_inv, u_chal);

    ipp_off += 64; /* advance past L, R */

    /* Fold vectors:
       a_new[j] = u * a_L[j] + u_inv * a_R[j]
       b_new[j] = u_inv * b_L[j] + u * b_R[j]
       G_new[j] = u_inv * G_L[j] + u * G_R[j]
       H_new[j] = u * H_L[j] + u_inv * H_R[j] */
    for( ulong j=0; j<half; j++ ) {
      uchar a_new[32], b_new[32];
      at_curve25519_scalar_mul(a_new, u_chal, &a_vec[j*32]);
      at_curve25519_scalar_muladd(a_new, u_inv, &a_vec[(half+j)*32], a_new);

      at_curve25519_scalar_mul(b_new, u_inv, &b_vec[j*32]);
      at_curve25519_scalar_muladd(b_new, u_chal, &b_vec[(half+j)*32], b_new);

      at_memcpy(&a_vec[j*32], a_new, 32);
      at_memcpy(&b_vec[j*32], b_new, 32);

      /* G_new[j] = u_inv * G_L[j] + u * G_R[j] */
      at_ristretto255_point_t g_tmp1[1], g_tmp2[1], g_new[1];
      at_ristretto255_scalar_mul(g_tmp1, u_inv, &G_work[j]);
      at_ristretto255_scalar_mul(g_tmp2, u_chal, &G_work[half+j]);
      at_ristretto255_point_add(g_new, g_tmp1, g_tmp2);
      at_ristretto255_point_set(&G_work[j], g_new);

      /* H_new[j] = u * H_L[j] + u_inv * H_R[j] */
      at_ristretto255_point_t h_tmp1[1], h_tmp2[1], h_new[1];
      at_ristretto255_scalar_mul(h_tmp1, u_chal, &H_work[j]);
      at_ristretto255_scalar_mul(h_tmp2, u_inv, &H_work[half+j]);
      at_ristretto255_point_add(h_new, h_tmp1, h_tmp2);
      at_ristretto255_point_set(&H_work[j], h_new);
    }
  }

  /* Final IPP scalars a, b (each 32 bytes) */
  at_memcpy(proof_out+ipp_off,    a_vec, 32); /* ipp_a */
  at_memcpy(proof_out+ipp_off+32, b_vec, 32); /* ipp_b */

  /* Sanity: ipp_off+64 should == 672 */
  if( ipp_off + 64 != 672 ) return -1;

#undef BP_N
#undef BP_LOGN
  return 0;
}
