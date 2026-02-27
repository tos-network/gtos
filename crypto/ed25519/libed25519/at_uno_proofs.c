/* at_uno_proofs.c - UNO Zero-Knowledge Proof Implementation

   This module implements verification of ShieldCommitmentProof and
   CiphertextValidityProof used in TOS UNO (privacy) transactions. */

#include "at/crypto/at_uno_proofs.h"
#include "at/crypto/at_curve25519.h"
#include "at/crypto/at_elgamal.h"

/* Ristretto255 basepoint G (compressed form).
   This matches the standard ristretto255 generator. */
uchar const AT_RISTRETTO_BASEPOINT_COMPRESSED[32] = {
  0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71,
  0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
  0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d,
  0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76
};

/* Pedersen commitment generator H (compressed form).
   This matches the bulletproofs crate's H generator. */
uchar const AT_PEDERSEN_H_COMPRESSED[32] = {
  0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc,
  0x65, 0xc3, 0x77, 0xa1, 0x04, 0x8d, 0x74, 0x5f,
  0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd,
  0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34
};

static void
merlin_challenge_scalar( at_merlin_transcript_t * transcript,
                         char const *             label,
                         uchar                    out[32] ) {
  uchar wide[64];
  at_merlin_transcript_challenge_bytes( transcript, label, (uint)at_strlen(label), wide, 64 );
  at_curve25519_scalar_reduce( out, wide );
}

static inline ulong
at_uno_be64_to_native( uchar const * p ) {
  return (ulong)( ((ulong)p[0] << 56) | ((ulong)p[1] << 48) |
                  ((ulong)p[2] << 40) | ((ulong)p[3] << 32) |
                  ((ulong)p[4] << 24) | ((ulong)p[5] << 16) |
                  ((ulong)p[6] << 8)  |  (ulong)p[7] );
}

static inline void
at_uno_native_to_be64( ulong v, uchar * p ) {
  p[0] = (uchar)(v >> 56);
  p[1] = (uchar)(v >> 48);
  p[2] = (uchar)(v >> 40);
  p[3] = (uchar)(v >> 32);
  p[4] = (uchar)(v >> 24);
  p[5] = (uchar)(v >> 16);
  p[6] = (uchar)(v >> 8);
  p[7] = (uchar)(v);
}

/**********************************************************************/
/* ShieldCommitmentProof                                               */
/**********************************************************************/

int
at_shield_proof_parse( uchar const          data[96],
                        at_shield_proof_t * out ) {
  if( !data || !out ) return -1;

  at_memcpy( out->Y_H, data, 32 );
  at_memcpy( out->Y_P, data + 32, 32 );
  at_memcpy( out->z, data + 64, 32 );

  /* Validate that z is a valid scalar */
  if( at_curve25519_scalar_validate( out->z ) == NULL ) {
    return -1;
  }

  return 0;
}

/* ShieldCommitmentProof verification:

   Given:
   - C = amount*G + r*H (commitment)
   - D = r*P (handle)
   - amount (known)

   Prove knowledge of r such that C - amount*G = r*H and D = r*P.

   Protocol (Fiat-Shamir):
   1. Prover sends Y_H = k*H, Y_P = k*P for random k
   2. Challenge c = Hash(transcript)
   3. Response z = k + c*r

   Verification:
   - z*H == Y_H + c*(C - amount*G)
   - z*P == Y_P + c*D
*/
int
at_shield_proof_verify( at_shield_proof_t const *   proof,
                         uchar const                commitment[32],
                         uchar const                receiver_handle[32],
                         uchar const                receiver_pubkey[32],
                         ulong                      amount,
                         at_merlin_transcript_t *   transcript ) {
  if( !proof || !commitment || !receiver_handle || !receiver_pubkey || !transcript ) {
    return -1;
  }

  /* Decompress points */
  at_ristretto255_point_t C_point[1];
  at_ristretto255_point_t D_point[1];
  at_ristretto255_point_t P_point[1];
  at_ristretto255_point_t Y_H_point[1];
  at_ristretto255_point_t Y_P_point[1];
  at_ristretto255_point_t G_point[1];
  at_ristretto255_point_t H_point[1];

  if( at_ristretto255_point_frombytes( C_point, commitment ) == NULL ) return -1;
  if( at_ristretto255_point_frombytes( D_point, receiver_handle ) == NULL ) return -1;
  if( at_ristretto255_point_frombytes( P_point, receiver_pubkey ) == NULL ) return -1;
  if( at_ristretto255_point_frombytes( Y_H_point, proof->Y_H ) == NULL ) return -1;
  if( at_ristretto255_point_frombytes( Y_P_point, proof->Y_P ) == NULL ) return -1;
  if( at_ristretto255_point_frombytes( G_point, AT_RISTRETTO_BASEPOINT_COMPRESSED ) == NULL ) return -1;
  if( at_ristretto255_point_frombytes( H_point, AT_PEDERSEN_H_COMPRESSED ) == NULL ) return -1;

  /* Domain separator - MUST match TOS Rust exactly:
     transcript.append_message(b"dom-sep", b"shield-commitment-proof") */
  at_merlin_transcript_append_message( transcript,
    AT_MERLIN_LITERAL( AT_PROOF_DOMAIN_SEP_LABEL ),
    (uchar const *)AT_SHIELD_PROOF_DOMAIN,
    sizeof(AT_SHIELD_PROOF_DOMAIN) - 1 );

  /* Append ONLY Y_H and Y_P - TOS Rust does NOT include commitment,
     handle, pubkey, or amount in the transcript */
  at_merlin_transcript_append_message( transcript,
    AT_MERLIN_LITERAL( AT_PROOF_LABEL_Y_H ), proof->Y_H, 32 );
  at_merlin_transcript_append_message( transcript,
    AT_MERLIN_LITERAL( AT_PROOF_LABEL_Y_P ), proof->Y_P, 32 );

  /* Get challenge scalar (label must be "c") */
  uchar challenge[64];
  at_merlin_transcript_challenge_bytes( transcript,
    AT_MERLIN_LITERAL( AT_PROOF_LABEL_CHALLENGE ), challenge, 64 );

  /* Finalization challenge (label "w", result discarded) */
  uchar finalize[64];
  at_merlin_transcript_challenge_bytes( transcript,
    AT_MERLIN_LITERAL( AT_PROOF_LABEL_FINALIZE ), finalize, 64 );

  /* Reduce challenge to scalar (mod L) */
  uchar c[32];
  at_curve25519_scalar_reduce( c, challenge );

  /* Compute amount*G */
  uchar amount_scalar[32];
  at_memset( amount_scalar, 0, 32 );
  /* Convert amount to little-endian scalar */
  for( int i = 0; i < 8; i++ ) {
    amount_scalar[i] = (uchar)(amount >> (i * 8));
  }
  at_ristretto255_point_t amount_G[1];
  at_ristretto255_scalar_mul( amount_G, amount_scalar, G_point );

  /* Compute C - amount*G (the randomness commitment r*H) */
  at_ristretto255_point_t C_minus_aG[1];
  at_ristretto255_point_sub( C_minus_aG, C_point, amount_G );

  /* Verify first equation: z*H == Y_H + c*(C - amount*G) */
  at_ristretto255_point_t lhs1[1];
  at_ristretto255_scalar_mul( lhs1, proof->z, H_point );

  at_ristretto255_point_t c_times_rH[1];
  at_ristretto255_scalar_mul( c_times_rH, c, C_minus_aG );

  at_ristretto255_point_t rhs1[1];
  at_ristretto255_point_add( rhs1, Y_H_point, c_times_rH );

  if( !at_ristretto255_point_eq( lhs1, rhs1 ) ) {
    return -1;
  }

  /* Verify second equation: z*P == Y_P + c*D */
  at_ristretto255_point_t lhs2[1];
  at_ristretto255_scalar_mul( lhs2, proof->z, P_point );

  at_ristretto255_point_t c_times_D[1];
  at_ristretto255_scalar_mul( c_times_D, c, D_point );

  at_ristretto255_point_t rhs2[1];
  at_ristretto255_point_add( rhs2, Y_P_point, c_times_D );

  if( !at_ristretto255_point_eq( lhs2, rhs2 ) ) {
    return -1;
  }

  return 0;
}

/**********************************************************************/
/* CiphertextValidityProof                                             */
/**********************************************************************/

int
at_ct_validity_proof_parse( uchar const              * data,
                             ulong                    data_sz,
                             int                      tx_version_t1,
                             at_ct_validity_proof_t * out,
                             ulong *                  bytes_read ) {
  if( !data || !out || !bytes_read ) return -1;

  ulong expected_sz = tx_version_t1 ? 160UL : 128UL;
  if( data_sz < expected_sz ) return -1;

  ulong off = 0;

  at_memcpy( out->Y_0, data + off, 32 );
  off += 32;

  at_memcpy( out->Y_1, data + off, 32 );
  off += 32;

  if( tx_version_t1 ) {
    out->has_Y_2 = 1;
    at_memcpy( out->Y_2, data + off, 32 );
    off += 32;
  } else {
    out->has_Y_2 = 0;
    at_memset( out->Y_2, 0, 32 );
  }

  at_memcpy( out->z_r, data + off, 32 );
  off += 32;

  at_memcpy( out->z_x, data + off, 32 );
  off += 32;

  /* Validate scalars */
  if( at_curve25519_scalar_validate( out->z_r ) == NULL ) return -1;
  if( at_curve25519_scalar_validate( out->z_x ) == NULL ) return -1;

  *bytes_read = off;
  return 0;
}

/* CiphertextValidityProof verification:

   For T0 (unshield - only sender handle):
   Given: C, D_sender, sender_pubkey
   Prove: C = x*G + r*H and D_sender = r*P_sender

   For T1 (uno transfer - both handles):
   Given: C, D_sender, D_receiver, sender_pubkey, receiver_pubkey
   Prove: C = x*G + r*H and D_sender = r*P_sender and D_receiver = r*P_receiver
*/
int
at_ct_validity_proof_verify( at_ct_validity_proof_t const * proof,
                              uchar const                    commitment[32],
                              uchar const                    sender_handle[32],
                              uchar const                    receiver_handle[32],
                              uchar const                    sender_pubkey[32],
                              uchar const                    receiver_pubkey[32],
                              int                            tx_version_t1,
                              at_merlin_transcript_t *       transcript ) {
  if( !proof || !commitment || !transcript ) {
    return -1;
  }

  /* receiver_handle and receiver_pubkey are ALWAYS required (for Y_1)
     TOS Rust: Y_1 = y_r * P_dest, where dest = receiver */
  if( !receiver_handle || !receiver_pubkey ) {
    return -1;
  }

  /* For T1, sender_handle and sender_pubkey are also required (for Y_2) */
  if( tx_version_t1 && (!sender_handle || !sender_pubkey) ) {
    return -1;
  }

  /* Decompress points */
  at_ristretto255_point_t C_point[1];
  at_ristretto255_point_t D_receiver[1];
  at_ristretto255_point_t P_receiver[1];
  at_ristretto255_point_t Y_0_point[1];
  at_ristretto255_point_t Y_1_point[1];
  at_ristretto255_point_t G_point[1];
  at_ristretto255_point_t H_point[1];

  if( at_ristretto255_point_frombytes( C_point, commitment ) == NULL ) return -1;
  if( at_ristretto255_point_frombytes( D_receiver, receiver_handle ) == NULL ) return -1;
  if( at_ristretto255_point_frombytes( P_receiver, receiver_pubkey ) == NULL ) return -1;
  if( at_ristretto255_point_frombytes( Y_0_point, proof->Y_0 ) == NULL ) return -1;
  if( at_ristretto255_point_frombytes( Y_1_point, proof->Y_1 ) == NULL ) return -1;
  if( at_ristretto255_point_frombytes( G_point, AT_RISTRETTO_BASEPOINT_COMPRESSED ) == NULL ) return -1;
  if( at_ristretto255_point_frombytes( H_point, AT_PEDERSEN_H_COMPRESSED ) == NULL ) return -1;

  at_ristretto255_point_t D_sender[1];
  at_ristretto255_point_t P_sender[1];
  at_ristretto255_point_t Y_2_point[1];

  if( tx_version_t1 ) {
    if( at_ristretto255_point_frombytes( D_sender, sender_handle ) == NULL ) return -1;
    if( at_ristretto255_point_frombytes( P_sender, sender_pubkey ) == NULL ) return -1;
    if( proof->has_Y_2 ) {
      if( at_ristretto255_point_frombytes( Y_2_point, proof->Y_2 ) == NULL ) return -1;
    }
  }

  /* Domain separator - MUST match TOS Rust exactly:
     transcript.append_message(b"dom-sep", b"validity-proof") */
  at_merlin_transcript_append_message( transcript,
    AT_MERLIN_LITERAL( AT_PROOF_DOMAIN_SEP_LABEL ),
    (uchar const *)AT_CT_VALIDITY_DOMAIN,
    sizeof(AT_CT_VALIDITY_DOMAIN) - 1 );

  /* Append ONLY Y_0, Y_1, Y_2 - TOS Rust does NOT include commitment,
     handles, or pubkeys in the transcript */
  at_merlin_transcript_append_message( transcript,
    AT_MERLIN_LITERAL( AT_PROOF_LABEL_Y_0 ), proof->Y_0, 32 );
  at_merlin_transcript_append_message( transcript,
    AT_MERLIN_LITERAL( AT_PROOF_LABEL_Y_1 ), proof->Y_1, 32 );

  if( tx_version_t1 && proof->has_Y_2 ) {
    at_merlin_transcript_append_message( transcript,
      AT_MERLIN_LITERAL( AT_PROOF_LABEL_Y_2 ), proof->Y_2, 32 );
  }

  /* Get challenge scalar (label must be "c") */
  uchar challenge[64];
  at_merlin_transcript_challenge_bytes( transcript,
    AT_MERLIN_LITERAL( AT_PROOF_LABEL_CHALLENGE ), challenge, 64 );

  /* Finalization challenge (label "w", result discarded) */
  uchar finalize[64];
  at_merlin_transcript_challenge_bytes( transcript,
    AT_MERLIN_LITERAL( AT_PROOF_LABEL_FINALIZE ), finalize, 64 );

  uchar c[32];
  at_curve25519_scalar_reduce( c, challenge );

  /* Verify: z_x*G + z_r*H == Y_0 + c*C */
  at_ristretto255_point_t zx_G[1];
  at_ristretto255_point_t zr_H[1];
  at_ristretto255_scalar_mul( zx_G, proof->z_x, G_point );
  at_ristretto255_scalar_mul( zr_H, proof->z_r, H_point );

  at_ristretto255_point_t lhs0[1];
  at_ristretto255_point_add( lhs0, zx_G, zr_H );

  at_ristretto255_point_t c_C[1];
  at_ristretto255_scalar_mul( c_C, c, C_point );

  at_ristretto255_point_t rhs0[1];
  at_ristretto255_point_add( rhs0, Y_0_point, c_C );

  if( !at_ristretto255_point_eq( lhs0, rhs0 ) ) {
    return -1;
  }

  /* Verify: z_r*P_receiver == Y_1 + c*D_receiver
     (TOS Rust: Y_1 = y_r * P_dest, where dest = receiver) */
  at_ristretto255_point_t zr_Pr[1];
  at_ristretto255_scalar_mul( zr_Pr, proof->z_r, P_receiver );

  at_ristretto255_point_t c_Dr[1];
  at_ristretto255_scalar_mul( c_Dr, c, D_receiver );

  at_ristretto255_point_t rhs1[1];
  at_ristretto255_point_add( rhs1, Y_1_point, c_Dr );

  if( !at_ristretto255_point_eq( zr_Pr, rhs1 ) ) {
    return -1;
  }

  /* For T1, also verify: z_r*P_sender == Y_2 + c*D_sender
     (TOS Rust: Y_2 = y_r * P_source, where source = sender) */
  if( tx_version_t1 && proof->has_Y_2 ) {
    at_ristretto255_point_t zr_Ps[1];
    at_ristretto255_scalar_mul( zr_Ps, proof->z_r, P_sender );

    at_ristretto255_point_t c_Ds[1];
    at_ristretto255_scalar_mul( c_Ds, c, D_sender );

    at_ristretto255_point_t rhs2[1];
    at_ristretto255_point_add( rhs2, Y_2_point, c_Ds );

    if( !at_ristretto255_point_eq( zr_Ps, rhs2 ) ) {
      return -1;
    }
  }

  return 0;
}

int
at_commitment_eq_proof_parse( uchar const *              data,
                              ulong                      data_sz,
                              at_commitment_eq_proof_t * out ) {
  if( !data || !out || data_sz < AT_COMMITMENT_EQ_PROOF_SZ ) return -1;
  at_memcpy( out->Y_0, data + 0, 32 );
  at_memcpy( out->Y_1, data + 32, 32 );
  at_memcpy( out->Y_2, data + 64, 32 );
  at_memcpy( out->z_s, data + 96, 32 );
  at_memcpy( out->z_x, data + 128, 32 );
  at_memcpy( out->z_r, data + 160, 32 );
  if( at_curve25519_scalar_validate( out->z_s ) == NULL ) return -1;
  if( at_curve25519_scalar_validate( out->z_x ) == NULL ) return -1;
  if( at_curve25519_scalar_validate( out->z_r ) == NULL ) return -1;
  return 0;
}

int
at_commitment_eq_proof_verify( at_commitment_eq_proof_t const * proof,
                               uchar const                      source_pubkey[32],
                               uchar const                      source_ciphertext[64],
                               uchar const                      destination_commitment[32],
                               at_merlin_transcript_t *         transcript ) {
  if( !proof || !source_pubkey || !source_ciphertext || !destination_commitment || !transcript ) return -1;

  at_ristretto255_point_t p_source[1], c_source[1], d_source[1], c_dest[1];
  at_ristretto255_point_t y0[1], y1[1], y2[1], g_point[1], h_point[1];

  if( !at_ristretto255_point_frombytes( p_source, source_pubkey ) ) return -1;
  if( !at_ristretto255_point_frombytes( c_source, source_ciphertext ) ) return -1;
  if( !at_ristretto255_point_frombytes( d_source, source_ciphertext + 32 ) ) return -1;
  if( !at_ristretto255_point_frombytes( c_dest, destination_commitment ) ) return -1;
  if( !at_ristretto255_point_frombytes( y0, proof->Y_0 ) ) return -1;
  if( !at_ristretto255_point_frombytes( y1, proof->Y_1 ) ) return -1;
  if( !at_ristretto255_point_frombytes( y2, proof->Y_2 ) ) return -1;
  if( !at_ristretto255_point_frombytes( g_point, AT_RISTRETTO_BASEPOINT_COMPRESSED ) ) return -1;
  if( !at_ristretto255_point_frombytes( h_point, AT_PEDERSEN_H_COMPRESSED ) ) return -1;

  at_merlin_transcript_append_message( transcript,
    AT_MERLIN_LITERAL( AT_PROOF_DOMAIN_SEP_LABEL ),
    (uchar const *)AT_EQ_PROOF_DOMAIN,
    sizeof(AT_EQ_PROOF_DOMAIN)-1 );
  at_merlin_transcript_append_message( transcript, AT_MERLIN_LITERAL( AT_PROOF_LABEL_Y_0 ), proof->Y_0, 32 );
  at_merlin_transcript_append_message( transcript, AT_MERLIN_LITERAL( AT_PROOF_LABEL_Y_1 ), proof->Y_1, 32 );
  at_merlin_transcript_append_message( transcript, AT_MERLIN_LITERAL( AT_PROOF_LABEL_Y_2 ), proof->Y_2, 32 );

  uchar c[32];
  merlin_challenge_scalar( transcript, AT_PROOF_LABEL_CHALLENGE, c );

  at_merlin_transcript_append_message( transcript, AT_MERLIN_LITERAL( AT_PROOF_LABEL_Z_S ), proof->z_s, 32 );
  at_merlin_transcript_append_message( transcript, AT_MERLIN_LITERAL( AT_PROOF_LABEL_Z_X ), proof->z_x, 32 );
  at_merlin_transcript_append_message( transcript, AT_MERLIN_LITERAL( AT_PROOF_LABEL_Z_R ), proof->z_r, 32 );

  uchar w[32], ww[32];
  merlin_challenge_scalar( transcript, AT_PROOF_LABEL_FINALIZE, w );
  at_curve25519_scalar_mul( ww, w, w );

  uchar neg_c[32], neg_one[32], neg_w[32], neg_ww[32];
  uchar one[32] = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  at_curve25519_scalar_neg( neg_c, c );
  at_curve25519_scalar_neg( neg_one, one );
  at_curve25519_scalar_neg( neg_w, w );
  at_curve25519_scalar_neg( neg_ww, ww );

  uchar w_zx[32], w_zs[32], w_c[32], ww_zx[32], ww_zr[32], ww_c[32];
  uchar neg_w_c[32], neg_ww_c[32];
  at_curve25519_scalar_mul( w_zx, w, proof->z_x );
  at_curve25519_scalar_mul( w_zs, w, proof->z_s );
  at_curve25519_scalar_mul( w_c,  w, c );
  at_curve25519_scalar_mul( ww_zx, ww, proof->z_x );
  at_curve25519_scalar_mul( ww_zr, ww, proof->z_r );
  at_curve25519_scalar_mul( ww_c,  ww, c );
  at_curve25519_scalar_neg( neg_w_c, w_c );
  at_curve25519_scalar_neg( neg_ww_c, ww_c );

  uchar scalars[11*32];
  at_memcpy( scalars + 0*32,  proof->z_s, 32 );
  at_memcpy( scalars + 1*32,  neg_c,      32 );
  at_memcpy( scalars + 2*32,  neg_one,    32 );
  at_memcpy( scalars + 3*32,  w_zx,       32 );
  at_memcpy( scalars + 4*32,  w_zs,       32 );
  at_memcpy( scalars + 5*32,  neg_w_c,    32 );
  at_memcpy( scalars + 6*32,  neg_w,      32 );
  at_memcpy( scalars + 7*32,  ww_zx,      32 );
  at_memcpy( scalars + 8*32,  ww_zr,      32 );
  at_memcpy( scalars + 9*32,  neg_ww_c,   32 );
  at_memcpy( scalars + 10*32, neg_ww,     32 );

  at_ristretto255_point_t points[11];
  at_ristretto255_point_set( &points[0],  p_source );
  at_ristretto255_point_set( &points[1],  h_point );
  at_ristretto255_point_set( &points[2],  y0 );
  at_ristretto255_point_set( &points[3],  g_point );
  at_ristretto255_point_set( &points[4],  d_source );
  at_ristretto255_point_set( &points[5],  c_source );
  at_ristretto255_point_set( &points[6],  y1 );
  at_ristretto255_point_set( &points[7],  g_point );
  at_ristretto255_point_set( &points[8],  h_point );
  at_ristretto255_point_set( &points[9],  c_dest );
  at_ristretto255_point_set( &points[10], y2 );

  at_ristretto255_point_t check[1], zero[1];
  at_ristretto255_multi_scalar_mul( check, scalars, points, 11 );
  at_ristretto255_point_set_zero( zero );
  return at_ristretto255_point_eq( check, zero ) ? 0 : -1;
}

int
at_commitment_eq_proof_pre_verify( at_commitment_eq_proof_t const * proof,
                                   uchar const                      source_pubkey[32],
                                   uchar const                      source_ciphertext[64],
                                   uchar const                      destination_commitment[32],
                                   at_merlin_transcript_t *         transcript,
                                   at_uno_batch_collector_t *       collector ) {
  (void)collector;
  return at_commitment_eq_proof_verify( proof,
                                        source_pubkey,
                                        source_ciphertext,
                                        destination_commitment,
                                        transcript );
}

int
at_balance_proof_parse( uchar const *        data,
                        ulong                data_sz,
                        at_balance_proof_t * out ) {
  if( !data || !out || data_sz < AT_BALANCE_PROOF_SZ ) return -1;
  out->amount = at_uno_be64_to_native( data );
  return at_commitment_eq_proof_parse( data + 8, data_sz - 8, &out->commitment_eq_proof );
}

int
at_balance_proof_verify( at_balance_proof_t const * proof,
                         uchar const                public_key[32],
                         uchar const                source_ciphertext[64] ) {
  at_merlin_transcript_t transcript;
  at_uno_batch_collector_t collector;
  at_merlin_transcript_init( &transcript, AT_MERLIN_LITERAL( "balance_proof" ) );
  at_uno_batch_collector_init( &collector );
  return at_balance_proof_pre_verify( proof,
                                      public_key,
                                      source_ciphertext,
                                      &transcript,
                                      &collector );
}

int
at_balance_proof_pre_verify( at_balance_proof_t const * proof,
                             uchar const                public_key[32],
                             uchar const                source_ciphertext[64],
                             at_merlin_transcript_t *   transcript,
                             at_uno_batch_collector_t * collector ) {
  (void)collector;
  if( !proof || !public_key || !source_ciphertext ) return -1;

  at_pedersen_opening_t opening_one;
  at_memset( &opening_one, 0, sizeof(opening_one) );
  opening_one.bytes[0] = 1u;

  at_elgamal_public_key_t pk;
  at_memcpy( pk.bytes, public_key, 32 );

  at_elgamal_compressed_ciphertext_t amount_ct;
  if( at_elgamal_encrypt_with_opening( &amount_ct, &pk, proof->amount, &opening_one ) ) return -1;

  at_elgamal_compressed_ciphertext_t zeroed;
  if( at_elgamal_ct_sub_compressed( zeroed.bytes, source_ciphertext, amount_ct.bytes ) ) return -1;

  at_elgamal_compressed_commitment_t dest_commitment;
  if( at_pedersen_commitment_new_with_opening( &dest_commitment, 0UL, &opening_one ) ) return -1;

  if( !transcript ) return -1;
  at_merlin_transcript_append_message( transcript,
    AT_MERLIN_LITERAL( AT_PROOF_DOMAIN_SEP_LABEL ),
    (uchar const *)AT_BALANCE_PROOF_DOMAIN,
    sizeof(AT_BALANCE_PROOF_DOMAIN)-1 );
  uchar amount_be[8];
  at_uno_native_to_be64( proof->amount, amount_be );
  at_merlin_transcript_append_message( transcript, AT_MERLIN_LITERAL( "amount" ), amount_be, 8 );
  at_merlin_transcript_append_message( transcript, AT_MERLIN_LITERAL( "source_ct" ), source_ciphertext, 64 );

  return at_commitment_eq_proof_verify( &proof->commitment_eq_proof,
                                        public_key,
                                        zeroed.bytes,
                                        dest_commitment.bytes,
                                        transcript );
}

int
at_shield_proof_pre_verify( at_shield_proof_t const *   proof,
                            uchar const                commitment[32],
                            uchar const                receiver_handle[32],
                            uchar const                receiver_pubkey[32],
                            ulong                      amount,
                            at_merlin_transcript_t *   transcript,
                            at_uno_batch_collector_t * collector ) {
  (void)collector;
  return at_shield_proof_verify( proof,
                                 commitment,
                                 receiver_handle,
                                 receiver_pubkey,
                                 amount,
                                 transcript );
}

int
at_ct_validity_proof_pre_verify( at_ct_validity_proof_t const * proof,
                                 uchar const                    commitment[32],
                                 uchar const                    sender_handle[32],
                                 uchar const                    receiver_handle[32],
                                 uchar const                    sender_pubkey[32],
                                 uchar const                    receiver_pubkey[32],
                                 int                            tx_version_t1,
                                 at_merlin_transcript_t *       transcript,
                                 at_uno_batch_collector_t *     collector ) {
  (void)collector;
  return at_ct_validity_proof_verify( proof,
                                      commitment,
                                      sender_handle,
                                      receiver_handle,
                                      sender_pubkey,
                                      receiver_pubkey,
                                      tx_version_t1,
                                      transcript );
}
