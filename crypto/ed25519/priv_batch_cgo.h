#ifndef GTOS_PRIV_BATCH_CGO_H
#define GTOS_PRIV_BATCH_CGO_H

#include <stddef.h>

typedef struct gtos_priv_batch_verifier gtos_priv_batch_verifier_t;

gtos_priv_batch_verifier_t *
gtos_priv_batch_new( void );

void
gtos_priv_batch_free( gtos_priv_batch_verifier_t * verifier );

int
gtos_priv_batch_add_shield_ctx( gtos_priv_batch_verifier_t * verifier,
                                unsigned char const *       proof96,
                                unsigned char const *       commitment,
                                unsigned char const *       receiver_handle,
                                unsigned char const *       receiver_pubkey,
                                unsigned long               amount,
                                unsigned char const *       ctx,
                                size_t                      ctx_sz );

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
                                     size_t                      ctx_sz );

int
gtos_priv_batch_add_commitment_eq_ctx( gtos_priv_batch_verifier_t * verifier,
                                       unsigned char const *       proof192,
                                       unsigned char const *       source_pubkey,
                                       unsigned char const *       source_ciphertext64,
                                       unsigned char const *       destination_commitment,
                                       unsigned char const *       ctx,
                                       size_t                      ctx_sz );

int
gtos_priv_batch_add_range( gtos_priv_batch_verifier_t * verifier,
                           unsigned char const *       proof,
                           size_t                      proof_sz,
                           unsigned char const *       commitments,
                           unsigned char const *       bit_lengths,
                           unsigned char               batch_len );

int
gtos_priv_batch_verify( gtos_priv_batch_verifier_t * verifier );

#endif /* GTOS_PRIV_BATCH_CGO_H */
