//go:build cgo && ed25519c
// +build cgo,ed25519c

#include "priv_batch_cgo.h"

#include <stdlib.h>

#include "at_priv_proofs.h"
#include "at_rangeproofs.h"
#include "at_merlin.h"

struct gtos_priv_batch_verifier {
  at_priv_batch_collector_t collector;
};

static void
gtos_priv_transcript_append_ctx_cgo( at_merlin_transcript_t * t,
                                     unsigned char const *    ctx,
                                     size_t                   ctx_sz ) {
  if( t && ctx && ctx_sz ) {
    at_merlin_transcript_append_message( t,
      AT_MERLIN_LITERAL("chain-ctx"),
      ctx, (uint)ctx_sz );
  }
}

gtos_priv_batch_verifier_t *
gtos_priv_batch_new( void ) {
  gtos_priv_batch_verifier_t * verifier = (gtos_priv_batch_verifier_t *)malloc( sizeof(*verifier) );
  if( !verifier ) return NULL;
  at_priv_batch_collector_init( &verifier->collector );
  return verifier;
}

void
gtos_priv_batch_free( gtos_priv_batch_verifier_t * verifier ) {
  if( !verifier ) return;
  at_priv_batch_collector_clear( &verifier->collector );
  free( verifier );
}

int
gtos_priv_batch_add_shield_ctx( gtos_priv_batch_verifier_t * verifier,
                                unsigned char const *       proof96,
                                unsigned char const *       commitment,
                                unsigned char const *       receiver_handle,
                                unsigned char const *       receiver_pubkey,
                                unsigned long               amount,
                                unsigned char const *       ctx,
                                size_t                      ctx_sz ) {
  if( !verifier || !proof96 || !commitment || !receiver_handle || !receiver_pubkey ) return -1;
  at_shield_proof_t proof;
  if( at_shield_proof_parse( proof96, &proof ) ) return -1;
  at_merlin_transcript_t transcript;
  at_merlin_transcript_init( &transcript, AT_MERLIN_LITERAL(AT_SHIELD_PROOF_DOMAIN) );
  gtos_priv_transcript_append_ctx_cgo( &transcript, ctx, ctx_sz );
  return at_shield_proof_pre_verify( &proof,
                                     commitment,
                                     receiver_handle,
                                     receiver_pubkey,
                                     amount,
                                     &transcript,
                                     &verifier->collector );
}

int
gtos_priv_batch_add_ct_validity_ctx( gtos_priv_batch_verifier_t * verifier,
                                     unsigned char const *       proof,
                                     size_t                      proof_sz,
                                     unsigned char const *       commitment,
                                     unsigned char const *       sender_handle,
                                     unsigned char const *       receiver_handle,
                                     unsigned char const *       sender_pubkey,
                                     unsigned char const *       receiver_pubkey,
                                     int                         tx_version_t1,
                                     unsigned char const *       ctx,
                                     size_t                      ctx_sz ) {
  if( !verifier || !proof || !commitment || !receiver_handle || !receiver_pubkey ) return -1;
  at_ct_validity_proof_t parsed;
  unsigned long bytes_read = 0UL;
  if( at_ct_validity_proof_parse( proof, (ulong)proof_sz, tx_version_t1, &parsed, &bytes_read ) ) return -1;
  if( bytes_read != (unsigned long)proof_sz ) return -1;
  at_merlin_transcript_t transcript;
  at_merlin_transcript_init( &transcript, AT_MERLIN_LITERAL(AT_CT_VALIDITY_DOMAIN) );
  gtos_priv_transcript_append_ctx_cgo( &transcript, ctx, ctx_sz );
  return at_ct_validity_proof_pre_verify( &parsed,
                                          commitment,
                                          sender_handle,
                                          receiver_handle,
                                          sender_pubkey,
                                          receiver_pubkey,
                                          tx_version_t1,
                                          &transcript,
                                          &verifier->collector );
}

int
gtos_priv_batch_add_commitment_eq_ctx( gtos_priv_batch_verifier_t * verifier,
                                       unsigned char const *       proof192,
                                       unsigned char const *       source_pubkey,
                                       unsigned char const *       source_ciphertext64,
                                       unsigned char const *       destination_commitment,
                                       unsigned char const *       ctx,
                                       size_t                      ctx_sz ) {
  if( !verifier || !proof192 || !source_pubkey || !source_ciphertext64 || !destination_commitment ) return -1;
  at_commitment_eq_proof_t proof;
  if( at_commitment_eq_proof_parse( proof192, AT_COMMITMENT_EQ_PROOF_SZ, &proof ) ) return -1;
  at_merlin_transcript_t transcript;
  at_merlin_transcript_init( &transcript, AT_MERLIN_LITERAL(AT_NEW_COMMITMENT_EQ_PROOF_DOMAIN) );
  gtos_priv_transcript_append_ctx_cgo( &transcript, ctx, ctx_sz );
  return at_commitment_eq_proof_pre_verify( &proof,
                                            source_pubkey,
                                            source_ciphertext64,
                                            destination_commitment,
                                            &transcript,
                                            &verifier->collector );
}

int
gtos_priv_batch_add_balance_ctx( gtos_priv_batch_verifier_t * verifier,
                                 unsigned char const *       proof_bytes,
                                 unsigned char const *       public_key,
                                 unsigned char const *       source_ciphertext64,
                                 unsigned char const *       ctx,
                                 size_t                      ctx_sz ) {
  if( !verifier || !proof_bytes || !public_key || !source_ciphertext64 ) return -1;
  at_balance_proof_t proof;
  if( at_balance_proof_parse( proof_bytes, AT_BALANCE_PROOF_SZ, &proof ) ) return -1;
  at_merlin_transcript_t transcript;
  at_merlin_transcript_init( &transcript, AT_MERLIN_LITERAL("balance_proof") );
  gtos_priv_transcript_append_ctx_cgo( &transcript, ctx, ctx_sz );
  return at_balance_proof_pre_verify( &proof,
                                      public_key,
                                      source_ciphertext64,
                                      &transcript,
                                      &verifier->collector );
}

int
gtos_priv_batch_add_range( gtos_priv_batch_verifier_t * verifier,
                           unsigned char const *       proof,
                           size_t                      proof_sz,
                           unsigned char const *       commitments,
                           unsigned char const *       bit_lengths,
                           unsigned char               batch_len ) {
  if( !verifier || !proof || !commitments || !bit_lengths || !batch_len || batch_len > AT_RANGEPROOFS_MAX_COMMITMENTS ) return -1;

  unsigned long nm = 0UL;
  for( unsigned long i=0UL; i<(unsigned long)batch_len; i++ ) nm += (unsigned long)bit_lengths[i];
  if( nm==0UL || nm>256UL || (nm & (nm-1UL)) ) return -1;

  unsigned long logn = 0UL;
  while( (1UL<<logn) < nm ) logn++;
  if( logn > 8UL ) return -1;
  if( (unsigned long)proof_sz != 224UL + (2UL * logn * 32UL) + 64UL ) return -1;

  at_rangeproofs_range_proof_t range_proof;
  at_memcpy( range_proof.a,           proof + 0UL,   32UL );
  at_memcpy( range_proof.s,           proof + 32UL,  32UL );
  at_memcpy( range_proof.t1,          proof + 64UL,  32UL );
  at_memcpy( range_proof.t2,          proof + 96UL,  32UL );
  at_memcpy( range_proof.tx,          proof + 128UL, 32UL );
  at_memcpy( range_proof.tx_blinding, proof + 160UL, 32UL );
  at_memcpy( range_proof.e_blinding,  proof + 192UL, 32UL );

  at_rangeproofs_ipp_vecs_t ipp_vecs[8];
  unsigned long off = 224UL;
  for( unsigned long i=0UL; i<logn; i++ ) {
    at_memcpy( ipp_vecs[i].l, proof + off, 32UL );
    off += 32UL;
    at_memcpy( ipp_vecs[i].r, proof + off, 32UL );
    off += 32UL;
  }

  unsigned char ipp_a[32];
  unsigned char ipp_b[32];
  at_memcpy( ipp_a, proof + off, 32UL );
  off += 32UL;
  at_memcpy( ipp_b, proof + off, 32UL );

  at_rangeproofs_ipp_proof_t ipp_proof = {0};
  *(unsigned char *)&ipp_proof.logn = (unsigned char)logn;
  ipp_proof.vecs = ipp_vecs;
  ipp_proof.a = ipp_a;
  ipp_proof.b = ipp_b;

  at_merlin_transcript_t transcript;
  at_merlin_transcript_init( &transcript, AT_MERLIN_LITERAL("transaction-proof") );
  return at_rangeproofs_pre_verify( &range_proof,
                                    &ipp_proof,
                                    commitments,
                                    bit_lengths,
                                    batch_len,
                                    &transcript,
                                    &verifier->collector );
}

int
gtos_priv_batch_verify( gtos_priv_batch_verifier_t * verifier ) {
  if( !verifier ) return -1;
  return at_priv_batch_collector_verify( &verifier->collector );
}
