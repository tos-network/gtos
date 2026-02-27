//go:build cgo && ed25519c

package ed25519

/*
#cgo CFLAGS: -std=gnu17
#cgo CFLAGS: -I${SRCDIR}/libed25519
#cgo CFLAGS: -I${SRCDIR}/libed25519/include

#include <stddef.h>
#include "at_uno_proofs.h"
#include "at_merlin.h"
#include "at_elgamal.h"

#include "./libed25519/at_ristretto255.c"
#include "./libed25519/at_schnorr.c"
#include "./libed25519/at_bech32.c"
#include "./libed25519/at_merlin.c"
#include "./libed25519/at_elgamal.c"
#include "./libed25519/at_rangeproofs.c"
#include "./libed25519/at_uno_proofs.c"

// gtos_uno_transcript_append_ctx appends canonical chain context bytes to an
// already-initialised Merlin transcript. This binds the proof to the specific
// chain, action type, sender, and receiver, preventing cross-chain and
// cross-action replay. The label "chain-ctx" must match the prover.
static void gtos_uno_transcript_append_ctx(at_merlin_transcript_t *t,
                                           const unsigned char *ctx,
                                           size_t ctx_sz) {
  if (ctx && ctx_sz > 0) {
    at_merlin_transcript_append_message(t,
        AT_MERLIN_LITERAL("chain-ctx"),
        ctx, (uint)ctx_sz);
  }
}

static int gtos_uno_verify_shield_ctx(const unsigned char *proof96,
                                      const unsigned char *commitment,
                                      const unsigned char *receiver_handle,
                                      const unsigned char *receiver_pubkey,
                                      unsigned long amount,
                                      const unsigned char *ctx,
                                      size_t ctx_sz) {
  at_shield_proof_t proof;
  if (at_shield_proof_parse(proof96, &proof) != 0) {
    return -1;
  }
  at_merlin_transcript_t transcript;
  at_merlin_transcript_init(&transcript, AT_MERLIN_LITERAL(AT_SHIELD_PROOF_DOMAIN));
  gtos_uno_transcript_append_ctx(&transcript, ctx, ctx_sz);
  return at_shield_proof_verify(&proof, commitment, receiver_handle, receiver_pubkey, amount, &transcript);
}

static int gtos_uno_verify_ct_validity_ctx(const unsigned char *proof,
                                           size_t proof_sz,
                                           const unsigned char *commitment,
                                           const unsigned char *sender_handle,
                                           const unsigned char *receiver_handle,
                                           const unsigned char *sender_pubkey,
                                           const unsigned char *receiver_pubkey,
                                           int tx_version_t1,
                                           const unsigned char *ctx,
                                           size_t ctx_sz) {
  at_ct_validity_proof_t parsed;
  unsigned long bytes_read = 0;
  if (at_ct_validity_proof_parse(proof, (ulong)proof_sz, tx_version_t1, &parsed, &bytes_read) != 0) {
    return -1;
  }
  if (bytes_read != (unsigned long)proof_sz) {
    return -1;
  }
  at_merlin_transcript_t transcript;
  at_merlin_transcript_init(&transcript, AT_MERLIN_LITERAL(AT_CT_VALIDITY_DOMAIN));
  gtos_uno_transcript_append_ctx(&transcript, ctx, ctx_sz);
  return at_ct_validity_proof_verify(&parsed, commitment, sender_handle, receiver_handle, sender_pubkey, receiver_pubkey, tx_version_t1, &transcript);
}

static int gtos_uno_verify_balance_ctx(const unsigned char *proof,
                                       size_t proof_sz,
                                       const unsigned char *public_key,
                                       const unsigned char *source_ciphertext64,
                                       const unsigned char *ctx,
                                       size_t ctx_sz) {
  at_balance_proof_t parsed;
  if (at_balance_proof_parse(proof, (ulong)proof_sz, &parsed) != 0) {
    return -1;
  }
  at_merlin_transcript_t transcript;
  at_uno_batch_collector_t collector;
  at_uno_batch_collector_init(&collector);
  at_merlin_transcript_init(&transcript, AT_MERLIN_LITERAL("balance_proof"));
  gtos_uno_transcript_append_ctx(&transcript, ctx, ctx_sz);
  return at_balance_proof_pre_verify(&parsed, public_key, source_ciphertext64, &transcript, &collector);
}

static int gtos_uno_verify_shield(const unsigned char *proof96,
                                  const unsigned char *commitment,
                                  const unsigned char *receiver_handle,
                                  const unsigned char *receiver_pubkey,
                                  unsigned long amount) {
  at_shield_proof_t proof;
  if (at_shield_proof_parse(proof96, &proof) != 0) {
    return -1;
  }
  at_merlin_transcript_t transcript;
  at_merlin_transcript_init(&transcript, AT_MERLIN_LITERAL(AT_SHIELD_PROOF_DOMAIN));
  return at_shield_proof_verify(&proof, commitment, receiver_handle, receiver_pubkey, amount, &transcript);
}

static int gtos_uno_verify_ct_validity(const unsigned char *proof,
                                       size_t proof_sz,
                                       const unsigned char *commitment,
                                       const unsigned char *sender_handle,
                                       const unsigned char *receiver_handle,
                                       const unsigned char *sender_pubkey,
                                       const unsigned char *receiver_pubkey,
                                       int tx_version_t1) {
  at_ct_validity_proof_t parsed;
  unsigned long bytes_read = 0;
  if (at_ct_validity_proof_parse(proof, (ulong)proof_sz, tx_version_t1, &parsed, &bytes_read) != 0) {
    return -1;
  }
  if (bytes_read != (unsigned long)proof_sz) {
    return -1;
  }
  at_merlin_transcript_t transcript;
  at_merlin_transcript_init(&transcript, AT_MERLIN_LITERAL(AT_CT_VALIDITY_DOMAIN));
  return at_ct_validity_proof_verify(&parsed, commitment, sender_handle, receiver_handle, sender_pubkey, receiver_pubkey, tx_version_t1, &transcript);
}

static int gtos_uno_verify_commitment_eq(const unsigned char *proof192,
                                         const unsigned char *source_pubkey,
                                         const unsigned char *source_ciphertext64,
                                         const unsigned char *destination_commitment) {
  at_commitment_eq_proof_t proof;
  if (at_commitment_eq_proof_parse(proof192, AT_COMMITMENT_EQ_PROOF_SZ, &proof) != 0) {
    return -1;
  }
  at_merlin_transcript_t transcript;
  at_merlin_transcript_init(&transcript, AT_MERLIN_LITERAL(AT_NEW_COMMITMENT_EQ_PROOF_DOMAIN));
  return at_commitment_eq_proof_verify(&proof, source_pubkey, source_ciphertext64, destination_commitment, &transcript);
}

static int gtos_uno_verify_balance(const unsigned char *proof,
                                   size_t proof_sz,
                                   const unsigned char *public_key,
                                   const unsigned char *source_ciphertext64) {
  at_balance_proof_t parsed;
  if (at_balance_proof_parse(proof, (ulong)proof_sz, &parsed) != 0) {
    return -1;
  }
  return at_balance_proof_verify(&parsed, public_key, source_ciphertext64);
}

static int gtos_elgamal_ct_add_compressed(unsigned char *out64, const unsigned char *a64, const unsigned char *b64) {
  return at_elgamal_ct_add_compressed(out64, a64, b64);
}

static int gtos_elgamal_ct_sub_compressed(unsigned char *out64, const unsigned char *a64, const unsigned char *b64) {
  return at_elgamal_ct_sub_compressed(out64, a64, b64);
}

static int gtos_elgamal_ct_add_amount_compressed(unsigned char *out64, const unsigned char *in64, unsigned long amount) {
  at_elgamal_ct_t in_ct;
  at_elgamal_ct_t out_ct;
  if (at_elgamal_ct_decompress(&in_ct, in64) != 0) {
    return -1;
  }
  if (at_elgamal_ct_add_amount(&out_ct, &in_ct, amount) != 0) {
    return -1;
  }
  at_elgamal_ct_compress(out64, &out_ct);
  return 0;
}

static int gtos_elgamal_ct_sub_amount_compressed(unsigned char *out64, const unsigned char *in64, unsigned long amount) {
  at_elgamal_ct_t in_ct;
  at_elgamal_ct_t out_ct;
  if (at_elgamal_ct_decompress(&in_ct, in64) != 0) {
    return -1;
  }
  if (at_elgamal_ct_sub_amount(&out_ct, &in_ct, amount) != 0) {
    return -1;
  }
  at_elgamal_ct_compress(out64, &out_ct);
  return 0;
}

static int gtos_elgamal_ct_normalize_compressed(unsigned char *out64, const unsigned char *in64) {
  at_elgamal_ct_t ct;
  if (at_elgamal_ct_decompress(&ct, in64) != 0) {
    return -1;
  }
  at_elgamal_ct_compress(out64, &ct);
  return 0;
}

static int gtos_elgamal_ct_zero_compressed(unsigned char *out64) {
  at_elgamal_ct_t ct;
  at_elgamal_ct_set_zero(&ct);
  at_elgamal_ct_compress(out64, &ct);
  return 0;
}

static int gtos_elgamal_ct_add_scalar_compressed(unsigned char *out64,
                                                 const unsigned char *in64,
                                                 const unsigned char *scalar32) {
  at_elgamal_ct_t in_ct;
  at_elgamal_ct_t out_ct;
  if (at_elgamal_ct_decompress(&in_ct, in64) != 0) {
    return -1;
  }
  if (at_elgamal_ct_add_scalar(&out_ct, &in_ct, scalar32) != 0) {
    return -1;
  }
  at_elgamal_ct_compress(out64, &out_ct);
  return 0;
}

static int gtos_elgamal_ct_sub_scalar_compressed(unsigned char *out64,
                                                 const unsigned char *in64,
                                                 const unsigned char *scalar32) {
  at_elgamal_ct_t in_ct;
  at_elgamal_ct_t out_ct;
  if (at_elgamal_ct_decompress(&in_ct, in64) != 0) {
    return -1;
  }
  if (at_elgamal_ct_sub_scalar(&out_ct, &in_ct, scalar32) != 0) {
    return -1;
  }
  at_elgamal_ct_compress(out64, &out_ct);
  return 0;
}

static int gtos_elgamal_ct_mul_scalar_compressed(unsigned char *out64,
                                                 const unsigned char *in64,
                                                 const unsigned char *scalar32) {
  at_elgamal_ct_t in_ct;
  at_elgamal_ct_t out_ct;
  if (at_elgamal_ct_decompress(&in_ct, in64) != 0) {
    return -1;
  }
  if (at_elgamal_ct_mul_scalar(&out_ct, &in_ct, scalar32) != 0) {
    return -1;
  }
  at_elgamal_ct_compress(out64, &out_ct);
  return 0;
}

static int gtos_elgamal_public_key_from_private(unsigned char *out32, const unsigned char *priv32) {
  at_elgamal_private_key_t priv;
  at_elgamal_public_key_t pub;
  at_memcpy(priv.bytes, priv32, 32);
  if (at_elgamal_public_key_from_private(&pub, &priv) != 0) {
    return -1;
  }
  at_memcpy(out32, pub.bytes, 32);
  return 0;
}

static int gtos_elgamal_encrypt(unsigned char *out64, const unsigned char *pub32, unsigned long amount) {
  at_elgamal_public_key_t pub;
  at_elgamal_compressed_ciphertext_t ct;
  at_memcpy(pub.bytes, pub32, 32);
  if (at_elgamal_encrypt(&ct, NULL, &pub, amount) != 0) {
    return -1;
  }
  at_memcpy(out64, ct.bytes, 64);
  return 0;
}

static int gtos_pedersen_opening_generate(unsigned char *out32) {
  at_pedersen_opening_t opening;
  if (at_pedersen_opening_generate(&opening) != 0) {
    return -1;
  }
  at_memcpy(out32, opening.bytes, 32);
  return 0;
}

static int gtos_pedersen_commitment_new(unsigned char *out32,
                                        unsigned char *opening32_out,
                                        unsigned long amount) {
  at_elgamal_compressed_commitment_t commitment;
  at_pedersen_opening_t opening;
  if (at_pedersen_commitment_new(&commitment, &opening, amount) != 0) {
    return -1;
  }
  at_memcpy(out32, commitment.bytes, 32);
  if (opening32_out) {
    at_memcpy(opening32_out, opening.bytes, 32);
  }
  return 0;
}

static int gtos_pedersen_commitment_with_opening(unsigned char *out32,
                                                 unsigned long amount,
                                                 const unsigned char *opening32) {
  at_pedersen_opening_t opening;
  at_elgamal_compressed_commitment_t commitment;
  at_memcpy(opening.bytes, opening32, 32);
  if (at_pedersen_commitment_new_with_opening(&commitment, amount, &opening) != 0) {
    return -1;
  }
  at_memcpy(out32, commitment.bytes, 32);
  return 0;
}

static int gtos_elgamal_decrypt_handle_with_opening(unsigned char *out32,
                                                    const unsigned char *pub32,
                                                    const unsigned char *opening32) {
  at_elgamal_public_key_t pub;
  at_pedersen_opening_t opening;
  at_elgamal_compressed_handle_t handle;
  at_memcpy(pub.bytes, pub32, 32);
  at_memcpy(opening.bytes, opening32, 32);
  if (at_elgamal_decrypt_handle(&handle, &pub, &opening) != 0) {
    return -1;
  }
  at_memcpy(out32, handle.bytes, 32);
  return 0;
}

static int gtos_elgamal_encrypt_with_opening(unsigned char *out64,
                                             const unsigned char *pub32,
                                             unsigned long amount,
                                             const unsigned char *opening32) {
  at_elgamal_public_key_t pub;
  at_pedersen_opening_t opening;
  at_elgamal_compressed_ciphertext_t ct;
  at_memcpy(pub.bytes, pub32, 32);
  at_memcpy(opening.bytes, opening32, 32);
  if (at_elgamal_encrypt_with_opening(&ct, &pub, amount, &opening) != 0) {
    return -1;
  }
  at_memcpy(out64, ct.bytes, 64);
  return 0;
}

static int gtos_elgamal_encrypt_with_generated_opening(unsigned char *out64,
                                                       unsigned char *opening32_out,
                                                       const unsigned char *pub32,
                                                       unsigned long amount) {
  at_elgamal_public_key_t pub;
  at_pedersen_opening_t opening;
  at_elgamal_compressed_ciphertext_t ct;
  at_memcpy(pub.bytes, pub32, 32);
  if (at_elgamal_encrypt(&ct, &opening, &pub, amount) != 0) {
    return -1;
  }
  at_memcpy(out64, ct.bytes, 64);
  if (opening32_out) {
    at_memcpy(opening32_out, opening.bytes, 32);
  }
  return 0;
}

static int gtos_elgamal_keypair_generate(unsigned char *pub32_out,
                                         unsigned char *priv32_out) {
  at_elgamal_keypair_t keypair;
  if (at_elgamal_keypair_generate(&keypair) != 0) {
    return -1;
  }
  at_memcpy(pub32_out, keypair.public_key.bytes, 32);
  at_memcpy(priv32_out, keypair.private_key.bytes, 32);
  return 0;
}

static int gtos_elgamal_decrypt_to_point(unsigned char *out32, const unsigned char *priv32, const unsigned char *ct64) {
  at_elgamal_private_key_t priv;
  at_elgamal_compressed_ciphertext_t ct;
  at_memcpy(priv.bytes, priv32, 32);
  at_memcpy(ct.bytes, ct64, 64);
  return at_elgamal_private_key_decrypt_to_point(out32, &priv, &ct);
}

static int gtos_elgamal_public_key_to_address(char *out,
                                              size_t out_sz,
                                              int mainnet,
                                              const unsigned char *pub32) {
  at_elgamal_public_key_t pub;
  at_memcpy(pub.bytes, pub32, 32);
  return at_elgamal_public_key_to_address(out, (ulong)out_sz, mainnet, &pub);
}

static int gtos_uno_verify_rangeproof(const unsigned char *proof,
                                      size_t proof_sz,
                                      const unsigned char *commitments,
                                      const unsigned char *bit_lengths,
                                      unsigned char batch_len) {
  if (!proof || !commitments || !bit_lengths || batch_len == 0 || batch_len > AT_RANGEPROOFS_MAX_COMMITMENTS) {
    return -1;
  }

  unsigned long nm = 0UL;
  for (unsigned long i = 0UL; i < (unsigned long)batch_len; i++) {
    nm += (unsigned long)bit_lengths[i];
  }
  if (nm == 0UL || nm > 256UL || (nm & (nm - 1UL)) != 0UL) {
    return -1;
  }
  unsigned long logn = 0UL;
  while ((1UL << logn) < nm) {
    logn++;
  }
  if (logn > 8UL) {
    return -1;
  }

  const unsigned long range_base = 224UL;
  const unsigned long ipp_scalars = 64UL;
  unsigned long expected = range_base + (2UL * logn * 32UL) + ipp_scalars;
  if ((unsigned long)proof_sz != expected) {
    return -1;
  }

  at_rangeproofs_range_proof_t range_proof;
  at_memcpy(range_proof.a,           proof + 0UL,   32UL);
  at_memcpy(range_proof.s,           proof + 32UL,  32UL);
  at_memcpy(range_proof.t1,          proof + 64UL,  32UL);
  at_memcpy(range_proof.t2,          proof + 96UL,  32UL);
  at_memcpy(range_proof.tx,          proof + 128UL, 32UL);
  at_memcpy(range_proof.tx_blinding, proof + 160UL, 32UL);
  at_memcpy(range_proof.e_blinding,  proof + 192UL, 32UL);

  at_rangeproofs_ipp_vecs_t ipp_vecs[8];
  unsigned long off = range_base;
  for (unsigned long i = 0UL; i < logn; i++) {
    at_memcpy(ipp_vecs[i].l, proof + off, 32UL);
    off += 32UL;
    at_memcpy(ipp_vecs[i].r, proof + off, 32UL);
    off += 32UL;
  }

  unsigned char ipp_a[32];
  unsigned char ipp_b[32];
  at_memcpy(ipp_a, proof + off, 32UL);
  off += 32UL;
  at_memcpy(ipp_b, proof + off, 32UL);

  at_rangeproofs_ipp_proof_t ipp_proof = {0};
  *(unsigned char *)&ipp_proof.logn = (unsigned char)logn;
  ipp_proof.vecs = ipp_vecs;
  ipp_proof.a = ipp_a;
  ipp_proof.b = ipp_b;

  at_merlin_transcript_t transcript;
  at_merlin_transcript_init(&transcript, AT_MERLIN_LITERAL("transaction-proof"));

  return at_rangeproofs_verify(&range_proof, &ipp_proof, commitments, bit_lengths, batch_len, &transcript);
}

static void gtos_uno_u64_to_le_scalar(unsigned char out32[32], unsigned long amount) {
  at_memset(out32, 0, 32);
  for (int i = 0; i < 8; i++) {
    out32[i] = (unsigned char)(amount >> (8 * i));
  }
}

static void gtos_uno_u64_to_be8(unsigned char out8[8], unsigned long amount) {
  out8[0] = (unsigned char)(amount >> 56);
  out8[1] = (unsigned char)(amount >> 48);
  out8[2] = (unsigned char)(amount >> 40);
  out8[3] = (unsigned char)(amount >> 32);
  out8[4] = (unsigned char)(amount >> 24);
  out8[5] = (unsigned char)(amount >> 16);
  out8[6] = (unsigned char)(amount >> 8);
  out8[7] = (unsigned char)(amount);
}

static int gtos_uno_scalar_is_zero(const unsigned char s[32]) {
  unsigned char acc = 0;
  for (int i = 0; i < 32; i++) {
    acc |= s[i];
  }
  return acc == 0;
}

static int gtos_uno_prove_commitment_eq_into(unsigned char proof192_out[192],
                                             const unsigned char source_privkey32[32],
                                             const unsigned char source_pubkey32[32],
                                             const unsigned char source_ciphertext64[64],
                                             const unsigned char destination_commitment32[32],
                                             unsigned long amount,
                                             const unsigned char opening32[32],
                                             at_merlin_transcript_t *transcript) {
  if (!proof192_out || !source_privkey32 || !source_pubkey32 || !source_ciphertext64 || !destination_commitment32 || !opening32 || !transcript) {
    return -1;
  }
  if (!at_curve25519_scalar_validate(source_privkey32) || gtos_uno_scalar_is_zero(source_privkey32)) {
    return -1;
  }
  if (!at_curve25519_scalar_validate(opening32)) {
    return -1;
  }

  at_pedersen_opening_t opening;
  at_memcpy(opening.bytes, opening32, 32);
  at_elgamal_compressed_commitment_t expected_commitment;
  if (at_pedersen_commitment_new_with_opening(&expected_commitment, amount, &opening) != 0) {
    return -1;
  }
  if (at_memcmp(expected_commitment.bytes, destination_commitment32, 32) != 0) {
    return -1;
  }

  at_ristretto255_point_t p_source[1], d_source[1], g_point[1], h_point[1];
  if (!at_ristretto255_point_frombytes(p_source, source_pubkey32)) return -1;
  if (!at_ristretto255_point_frombytes(d_source, source_ciphertext64 + 32)) return -1;
  if (!at_ristretto255_point_frombytes(g_point, AT_RISTRETTO_BASEPOINT_COMPRESSED)) return -1;
  if (!at_ristretto255_point_frombytes(h_point, AT_PEDERSEN_H_COMPRESSED)) return -1;

  at_pedersen_opening_t y_s, y_x, y_r;
  if (at_pedersen_opening_generate(&y_s) != 0 ||
      at_pedersen_opening_generate(&y_x) != 0 ||
      at_pedersen_opening_generate(&y_r) != 0) {
    return -1;
  }

  at_ristretto255_point_t y0[1], y1[1], y2[1];
  at_ristretto255_point_t yx_g[1], ys_d[1], yr_h[1];
  at_ristretto255_scalar_mul(y0, y_s.bytes, p_source);
  at_ristretto255_scalar_mul(yx_g, y_x.bytes, g_point);
  at_ristretto255_scalar_mul(ys_d, y_s.bytes, d_source);
  at_ristretto255_point_add(y1, yx_g, ys_d);
  at_ristretto255_scalar_mul(yr_h, y_r.bytes, h_point);
  at_ristretto255_point_add(y2, yx_g, yr_h);

  unsigned char Y0[32], Y1[32], Y2[32];
  at_ristretto255_point_tobytes(Y0, y0);
  at_ristretto255_point_tobytes(Y1, y1);
  at_ristretto255_point_tobytes(Y2, y2);

  at_merlin_transcript_append_message(transcript,
    AT_MERLIN_LITERAL(AT_PROOF_DOMAIN_SEP_LABEL),
    (unsigned char const *)AT_EQ_PROOF_DOMAIN,
    sizeof(AT_EQ_PROOF_DOMAIN) - 1);
  at_merlin_transcript_append_message(transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_Y_0), Y0, 32);
  at_merlin_transcript_append_message(transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_Y_1), Y1, 32);
  at_merlin_transcript_append_message(transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_Y_2), Y2, 32);

  unsigned char c[32];
  merlin_challenge_scalar(transcript, AT_PROOF_LABEL_CHALLENGE, c);

  unsigned char x_scalar[32];
  gtos_uno_u64_to_le_scalar(x_scalar, amount);
  unsigned char z_s[32], z_x[32], z_r[32];
  at_curve25519_scalar_muladd(z_s, c, source_privkey32, y_s.bytes);
  at_curve25519_scalar_muladd(z_x, c, x_scalar, y_x.bytes);
  at_curve25519_scalar_muladd(z_r, c, opening32, y_r.bytes);

  at_merlin_transcript_append_message(transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_Z_S), z_s, 32);
  at_merlin_transcript_append_message(transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_Z_X), z_x, 32);
  at_merlin_transcript_append_message(transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_Z_R), z_r, 32);
  unsigned char finalize[32];
  merlin_challenge_scalar(transcript, AT_PROOF_LABEL_FINALIZE, finalize);

  at_memcpy(proof192_out + 0, Y0, 32);
  at_memcpy(proof192_out + 32, Y1, 32);
  at_memcpy(proof192_out + 64, Y2, 32);
  at_memcpy(proof192_out + 96, z_s, 32);
  at_memcpy(proof192_out + 128, z_x, 32);
  at_memcpy(proof192_out + 160, z_r, 32);
  return 0;
}

static int gtos_uno_prove_shield_ctx(unsigned char proof96_out[96],
                                     unsigned char commitment32_out[32],
                                     unsigned char receiver_handle32_out[32],
                                     const unsigned char receiver_pubkey32[32],
                                     unsigned long amount,
                                     const unsigned char opening32[32],
                                     const unsigned char *ctx,
                                     size_t ctx_sz) {
  if (!proof96_out || !commitment32_out || !receiver_handle32_out || !receiver_pubkey32 || !opening32) {
    return -1;
  }
  if (!at_curve25519_scalar_validate(opening32)) {
    return -1;
  }

  at_pedersen_opening_t opening;
  at_memcpy(opening.bytes, opening32, 32);
  at_elgamal_public_key_t receiver_pub;
  at_memcpy(receiver_pub.bytes, receiver_pubkey32, 32);

  at_elgamal_compressed_commitment_t commitment;
  at_elgamal_compressed_handle_t receiver_handle;
  if (at_pedersen_commitment_new_with_opening(&commitment, amount, &opening) != 0) return -1;
  if (at_elgamal_decrypt_handle(&receiver_handle, &receiver_pub, &opening) != 0) return -1;

  at_ristretto255_point_t H[1], P[1];
  if (!at_ristretto255_point_frombytes(H, AT_PEDERSEN_H_COMPRESSED)) return -1;
  if (!at_ristretto255_point_frombytes(P, receiver_pubkey32)) return -1;

  at_pedersen_opening_t k;
  if (at_pedersen_opening_generate(&k) != 0) return -1;

  at_ristretto255_point_t YH[1], YP[1];
  at_ristretto255_scalar_mul(YH, k.bytes, H);
  at_ristretto255_scalar_mul(YP, k.bytes, P);

  unsigned char Y_H[32], Y_P[32];
  at_ristretto255_point_tobytes(Y_H, YH);
  at_ristretto255_point_tobytes(Y_P, YP);

  at_merlin_transcript_t transcript;
  at_merlin_transcript_init(&transcript, AT_MERLIN_LITERAL(AT_SHIELD_PROOF_DOMAIN));
  gtos_uno_transcript_append_ctx(&transcript, ctx, ctx_sz);
  at_merlin_transcript_append_message(&transcript,
    AT_MERLIN_LITERAL(AT_PROOF_DOMAIN_SEP_LABEL),
    (unsigned char const *)AT_SHIELD_PROOF_DOMAIN,
    sizeof(AT_SHIELD_PROOF_DOMAIN) - 1);
  at_merlin_transcript_append_message(&transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_Y_H), Y_H, 32);
  at_merlin_transcript_append_message(&transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_Y_P), Y_P, 32);

  unsigned char challenge[64];
  at_merlin_transcript_challenge_bytes(&transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_CHALLENGE), challenge, 64);
  unsigned char finalize[64];
  at_merlin_transcript_challenge_bytes(&transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_FINALIZE), finalize, 64);

  unsigned char c[32], z[32];
  at_curve25519_scalar_reduce(c, challenge);
  at_curve25519_scalar_muladd(z, c, opening32, k.bytes);

  at_memcpy(proof96_out + 0, Y_H, 32);
  at_memcpy(proof96_out + 32, Y_P, 32);
  at_memcpy(proof96_out + 64, z, 32);
  at_memcpy(commitment32_out, commitment.bytes, 32);
  at_memcpy(receiver_handle32_out, receiver_handle.bytes, 32);
  return 0;
}

static int gtos_uno_prove_ct_validity_ctx(unsigned char *proof_out,
                                          size_t proof_sz,
                                          unsigned char commitment32_out[32],
                                          unsigned char sender_handle32_out[32],
                                          unsigned char receiver_handle32_out[32],
                                          const unsigned char sender_pubkey32[32],
                                          const unsigned char receiver_pubkey32[32],
                                          unsigned long amount,
                                          const unsigned char opening32[32],
                                          int tx_version_t1,
                                          const unsigned char *ctx,
                                          size_t ctx_sz) {
  if (!proof_out || !commitment32_out || !sender_handle32_out || !receiver_handle32_out ||
      !sender_pubkey32 || !receiver_pubkey32 || !opening32) {
    return -1;
  }
  size_t want = tx_version_t1 ? 160UL : 128UL;
  if (proof_sz != want) {
    return -1;
  }
  if (!at_curve25519_scalar_validate(opening32)) {
    return -1;
  }

  at_pedersen_opening_t opening;
  at_memcpy(opening.bytes, opening32, 32);
  at_elgamal_public_key_t sender_pub, receiver_pub;
  at_memcpy(sender_pub.bytes, sender_pubkey32, 32);
  at_memcpy(receiver_pub.bytes, receiver_pubkey32, 32);

  at_elgamal_compressed_commitment_t commitment;
  at_elgamal_compressed_handle_t sender_handle, receiver_handle;
  if (at_pedersen_commitment_new_with_opening(&commitment, amount, &opening) != 0) return -1;
  if (at_elgamal_decrypt_handle(&sender_handle, &sender_pub, &opening) != 0) return -1;
  if (at_elgamal_decrypt_handle(&receiver_handle, &receiver_pub, &opening) != 0) return -1;

  at_ristretto255_point_t G[1], H[1], P_sender[1], P_receiver[1];
  if (!at_ristretto255_point_frombytes(G, AT_RISTRETTO_BASEPOINT_COMPRESSED)) return -1;
  if (!at_ristretto255_point_frombytes(H, AT_PEDERSEN_H_COMPRESSED)) return -1;
  if (!at_ristretto255_point_frombytes(P_sender, sender_pubkey32)) return -1;
  if (!at_ristretto255_point_frombytes(P_receiver, receiver_pubkey32)) return -1;

  at_pedersen_opening_t y_r, y_x;
  if (at_pedersen_opening_generate(&y_r) != 0 || at_pedersen_opening_generate(&y_x) != 0) {
    return -1;
  }

  at_ristretto255_point_t y0[1], y1[1], y2[1], yx_g[1], yr_h[1];
  at_ristretto255_scalar_mul(yx_g, y_x.bytes, G);
  at_ristretto255_scalar_mul(yr_h, y_r.bytes, H);
  at_ristretto255_point_add(y0, yx_g, yr_h);
  at_ristretto255_scalar_mul(y1, y_r.bytes, P_receiver);
  if (tx_version_t1) {
    at_ristretto255_scalar_mul(y2, y_r.bytes, P_sender);
  }

  unsigned char Y0[32], Y1[32], Y2[32];
  at_ristretto255_point_tobytes(Y0, y0);
  at_ristretto255_point_tobytes(Y1, y1);
  if (tx_version_t1) {
    at_ristretto255_point_tobytes(Y2, y2);
  }

  at_merlin_transcript_t transcript;
  at_merlin_transcript_init(&transcript, AT_MERLIN_LITERAL(AT_CT_VALIDITY_DOMAIN));
  gtos_uno_transcript_append_ctx(&transcript, ctx, ctx_sz);
  at_merlin_transcript_append_message(&transcript,
    AT_MERLIN_LITERAL(AT_PROOF_DOMAIN_SEP_LABEL),
    (unsigned char const *)AT_CT_VALIDITY_DOMAIN,
    sizeof(AT_CT_VALIDITY_DOMAIN) - 1);
  at_merlin_transcript_append_message(&transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_Y_0), Y0, 32);
  at_merlin_transcript_append_message(&transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_Y_1), Y1, 32);
  if (tx_version_t1) {
    at_merlin_transcript_append_message(&transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_Y_2), Y2, 32);
  }

  unsigned char challenge[64];
  at_merlin_transcript_challenge_bytes(&transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_CHALLENGE), challenge, 64);
  unsigned char finalize[64];
  at_merlin_transcript_challenge_bytes(&transcript, AT_MERLIN_LITERAL(AT_PROOF_LABEL_FINALIZE), finalize, 64);

  unsigned char c[32], z_r[32], z_x[32], x_scalar[32];
  at_curve25519_scalar_reduce(c, challenge);
  gtos_uno_u64_to_le_scalar(x_scalar, amount);
  at_curve25519_scalar_muladd(z_r, c, opening32, y_r.bytes);
  at_curve25519_scalar_muladd(z_x, c, x_scalar, y_x.bytes);

  at_memcpy(proof_out + 0, Y0, 32);
  at_memcpy(proof_out + 32, Y1, 32);
  if (tx_version_t1) {
    at_memcpy(proof_out + 64, Y2, 32);
    at_memcpy(proof_out + 96, z_r, 32);
    at_memcpy(proof_out + 128, z_x, 32);
  } else {
    at_memcpy(proof_out + 64, z_r, 32);
    at_memcpy(proof_out + 96, z_x, 32);
  }

  at_memcpy(commitment32_out, commitment.bytes, 32);
  at_memcpy(sender_handle32_out, sender_handle.bytes, 32);
  at_memcpy(receiver_handle32_out, receiver_handle.bytes, 32);
  return 0;
}

static int gtos_uno_prove_balance_ctx(unsigned char proof200_out[200],
                                      const unsigned char source_privkey32[32],
                                      const unsigned char source_ciphertext64[64],
                                      unsigned long amount,
                                      const unsigned char *ctx,
                                      size_t ctx_sz) {
  if (!proof200_out || !source_privkey32 || !source_ciphertext64) {
    return -1;
  }
  if (!at_curve25519_scalar_validate(source_privkey32) || gtos_uno_scalar_is_zero(source_privkey32)) {
    return -1;
  }

  at_elgamal_private_key_t source_priv;
  at_memcpy(source_priv.bytes, source_privkey32, 32);
  at_elgamal_public_key_t source_pub;
  if (at_elgamal_public_key_from_private(&source_pub, &source_priv) != 0) {
    return -1;
  }

  at_pedersen_opening_t opening_one;
  at_memset(opening_one.bytes, 0, 32);
  opening_one.bytes[0] = 1u;

  at_elgamal_compressed_ciphertext_t amount_ct;
  if (at_elgamal_encrypt_with_opening(&amount_ct, &source_pub, amount, &opening_one) != 0) {
    return -1;
  }
  at_elgamal_compressed_ciphertext_t zeroed;
  if (at_elgamal_ct_sub_compressed(zeroed.bytes, source_ciphertext64, amount_ct.bytes) != 0) {
    return -1;
  }
  at_elgamal_compressed_commitment_t destination_commitment;
  if (at_pedersen_commitment_new_with_opening(&destination_commitment, 0UL, &opening_one) != 0) {
    return -1;
  }

  at_merlin_transcript_t transcript;
  at_merlin_transcript_init(&transcript, AT_MERLIN_LITERAL("balance_proof"));
  gtos_uno_transcript_append_ctx(&transcript, ctx, ctx_sz);
  at_merlin_transcript_append_message(&transcript,
    AT_MERLIN_LITERAL(AT_PROOF_DOMAIN_SEP_LABEL),
    (unsigned char const *)AT_BALANCE_PROOF_DOMAIN,
    sizeof(AT_BALANCE_PROOF_DOMAIN) - 1);

  unsigned char amount_be[8];
  gtos_uno_u64_to_be8(amount_be, amount);
  at_merlin_transcript_append_message(&transcript, AT_MERLIN_LITERAL("amount"), amount_be, 8);
  at_merlin_transcript_append_message(&transcript, AT_MERLIN_LITERAL("source_ct"), source_ciphertext64, 64);

  unsigned char eq_proof[192];
  if (gtos_uno_prove_commitment_eq_into(
      eq_proof,
      source_privkey32,
      source_pub.bytes,
      zeroed.bytes,
      destination_commitment.bytes,
      0UL,
      opening_one.bytes,
      &transcript) != 0) {
    return -1;
  }

  at_memcpy(proof200_out + 0, amount_be, 8);
  at_memcpy(proof200_out + 8, eq_proof, 192);
  return 0;
}
*/
import "C"

import (
	_ "github.com/tos-network/gtos/crypto/libsha3"
	"strings"
	"unsafe"
)

func VerifyUNOShieldProof(proof96, commitment, receiverHandle, receiverPubkey []byte, amount uint64) error {
	if len(proof96) != 96 || len(commitment) != 32 || len(receiverHandle) != 32 || len(receiverPubkey) != 32 {
		return ErrUNOInvalidInput
	}
	if C.gtos_uno_verify_shield(
		(*C.uchar)(unsafe.Pointer(&proof96[0])),
		(*C.uchar)(unsafe.Pointer(&commitment[0])),
		(*C.uchar)(unsafe.Pointer(&receiverHandle[0])),
		(*C.uchar)(unsafe.Pointer(&receiverPubkey[0])),
		C.ulong(amount),
	) != 0 {
		return ErrUNOInvalidProof
	}
	return nil
}

func VerifyUNOCTValidityProof(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey []byte, txVersionT1 bool) error {
	if len(proof) == 0 || len(commitment) != 32 || len(senderHandle) != 32 || len(receiverHandle) != 32 || len(senderPubkey) != 32 || len(receiverPubkey) != 32 {
		return ErrUNOInvalidInput
	}
	wantLen := 128
	t1 := C.int(0)
	if txVersionT1 {
		wantLen = 160
		t1 = 1
	}
	if len(proof) != wantLen {
		return ErrUNOInvalidInput
	}
	if C.gtos_uno_verify_ct_validity(
		(*C.uchar)(unsafe.Pointer(&proof[0])),
		C.size_t(len(proof)),
		(*C.uchar)(unsafe.Pointer(&commitment[0])),
		(*C.uchar)(unsafe.Pointer(&senderHandle[0])),
		(*C.uchar)(unsafe.Pointer(&receiverHandle[0])),
		(*C.uchar)(unsafe.Pointer(&senderPubkey[0])),
		(*C.uchar)(unsafe.Pointer(&receiverPubkey[0])),
		t1,
	) != 0 {
		return ErrUNOInvalidProof
	}
	return nil
}

func VerifyUNOShieldProofWithContext(proof96, commitment, receiverHandle, receiverPubkey []byte, amount uint64, ctx []byte) error {
	if len(proof96) != 96 || len(commitment) != 32 || len(receiverHandle) != 32 || len(receiverPubkey) != 32 {
		return ErrUNOInvalidInput
	}
	var ctxPtr *C.uchar
	if len(ctx) > 0 {
		ctxPtr = (*C.uchar)(unsafe.Pointer(&ctx[0]))
	}
	if C.gtos_uno_verify_shield_ctx(
		(*C.uchar)(unsafe.Pointer(&proof96[0])),
		(*C.uchar)(unsafe.Pointer(&commitment[0])),
		(*C.uchar)(unsafe.Pointer(&receiverHandle[0])),
		(*C.uchar)(unsafe.Pointer(&receiverPubkey[0])),
		C.ulong(amount),
		ctxPtr,
		C.size_t(len(ctx)),
	) != 0 {
		return ErrUNOInvalidProof
	}
	return nil
}

func VerifyUNOCTValidityProofWithContext(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey []byte, txVersionT1 bool, ctx []byte) error {
	if len(proof) == 0 || len(commitment) != 32 || len(senderHandle) != 32 || len(receiverHandle) != 32 || len(senderPubkey) != 32 || len(receiverPubkey) != 32 {
		return ErrUNOInvalidInput
	}
	wantLen := 128
	t1 := C.int(0)
	if txVersionT1 {
		wantLen = 160
		t1 = 1
	}
	if len(proof) != wantLen {
		return ErrUNOInvalidInput
	}
	var ctxPtr *C.uchar
	if len(ctx) > 0 {
		ctxPtr = (*C.uchar)(unsafe.Pointer(&ctx[0]))
	}
	if C.gtos_uno_verify_ct_validity_ctx(
		(*C.uchar)(unsafe.Pointer(&proof[0])),
		C.size_t(len(proof)),
		(*C.uchar)(unsafe.Pointer(&commitment[0])),
		(*C.uchar)(unsafe.Pointer(&senderHandle[0])),
		(*C.uchar)(unsafe.Pointer(&receiverHandle[0])),
		(*C.uchar)(unsafe.Pointer(&senderPubkey[0])),
		(*C.uchar)(unsafe.Pointer(&receiverPubkey[0])),
		t1,
		ctxPtr,
		C.size_t(len(ctx)),
	) != 0 {
		return ErrUNOInvalidProof
	}
	return nil
}

func VerifyUNOBalanceProofWithContext(proof, publicKey, sourceCiphertext64 []byte, ctx []byte) error {
	if len(proof) != 200 || len(publicKey) != 32 || len(sourceCiphertext64) != 64 {
		return ErrUNOInvalidInput
	}
	var ctxPtr *C.uchar
	if len(ctx) > 0 {
		ctxPtr = (*C.uchar)(unsafe.Pointer(&ctx[0]))
	}
	if C.gtos_uno_verify_balance_ctx(
		(*C.uchar)(unsafe.Pointer(&proof[0])),
		C.size_t(len(proof)),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&sourceCiphertext64[0])),
		ctxPtr,
		C.size_t(len(ctx)),
	) != 0 {
		return ErrUNOInvalidProof
	}
	return nil
}

func ProveUNOShieldProofWithContext(receiverPubkey []byte, amount uint64, opening32 []byte, ctx []byte) (proof96 []byte, commitment32 []byte, receiverHandle32 []byte, err error) {
	if len(receiverPubkey) != 32 || len(opening32) != 32 {
		return nil, nil, nil, ErrUNOInvalidInput
	}
	proof96 = make([]byte, 96)
	commitment32 = make([]byte, 32)
	receiverHandle32 = make([]byte, 32)
	var ctxPtr *C.uchar
	if len(ctx) > 0 {
		ctxPtr = (*C.uchar)(unsafe.Pointer(&ctx[0]))
	}
	if C.gtos_uno_prove_shield_ctx(
		(*C.uchar)(unsafe.Pointer(&proof96[0])),
		(*C.uchar)(unsafe.Pointer(&commitment32[0])),
		(*C.uchar)(unsafe.Pointer(&receiverHandle32[0])),
		(*C.uchar)(unsafe.Pointer(&receiverPubkey[0])),
		C.ulong(amount),
		(*C.uchar)(unsafe.Pointer(&opening32[0])),
		ctxPtr,
		C.size_t(len(ctx)),
	) != 0 {
		return nil, nil, nil, ErrUNOOperationFailed
	}
	return proof96, commitment32, receiverHandle32, nil
}

func ProveUNOShieldProof(receiverPubkey []byte, amount uint64, opening32 []byte) (proof96 []byte, commitment32 []byte, receiverHandle32 []byte, err error) {
	return ProveUNOShieldProofWithContext(receiverPubkey, amount, opening32, nil)
}

func ProveUNOCTValidityProofWithContext(senderPubkey, receiverPubkey []byte, amount uint64, opening32 []byte, txVersionT1 bool, ctx []byte) (proof []byte, commitment32 []byte, senderHandle32 []byte, receiverHandle32 []byte, err error) {
	if len(senderPubkey) != 32 || len(receiverPubkey) != 32 || len(opening32) != 32 {
		return nil, nil, nil, nil, ErrUNOInvalidInput
	}
	proofLen := 128
	t1 := C.int(0)
	if txVersionT1 {
		proofLen = 160
		t1 = 1
	}
	proof = make([]byte, proofLen)
	commitment32 = make([]byte, 32)
	senderHandle32 = make([]byte, 32)
	receiverHandle32 = make([]byte, 32)
	var ctxPtr *C.uchar
	if len(ctx) > 0 {
		ctxPtr = (*C.uchar)(unsafe.Pointer(&ctx[0]))
	}
	if C.gtos_uno_prove_ct_validity_ctx(
		(*C.uchar)(unsafe.Pointer(&proof[0])),
		C.size_t(len(proof)),
		(*C.uchar)(unsafe.Pointer(&commitment32[0])),
		(*C.uchar)(unsafe.Pointer(&senderHandle32[0])),
		(*C.uchar)(unsafe.Pointer(&receiverHandle32[0])),
		(*C.uchar)(unsafe.Pointer(&senderPubkey[0])),
		(*C.uchar)(unsafe.Pointer(&receiverPubkey[0])),
		C.ulong(amount),
		(*C.uchar)(unsafe.Pointer(&opening32[0])),
		t1,
		ctxPtr,
		C.size_t(len(ctx)),
	) != 0 {
		return nil, nil, nil, nil, ErrUNOOperationFailed
	}
	return proof, commitment32, senderHandle32, receiverHandle32, nil
}

func ProveUNOCTValidityProof(senderPubkey, receiverPubkey []byte, amount uint64, opening32 []byte, txVersionT1 bool) (proof []byte, commitment32 []byte, senderHandle32 []byte, receiverHandle32 []byte, err error) {
	return ProveUNOCTValidityProofWithContext(senderPubkey, receiverPubkey, amount, opening32, txVersionT1, nil)
}

func ProveUNOBalanceProofWithContext(sourcePrivkey32, sourceCiphertext64 []byte, amount uint64, ctx []byte) ([]byte, error) {
	if len(sourcePrivkey32) != 32 || len(sourceCiphertext64) != 64 {
		return nil, ErrUNOInvalidInput
	}
	proof := make([]byte, 200)
	var ctxPtr *C.uchar
	if len(ctx) > 0 {
		ctxPtr = (*C.uchar)(unsafe.Pointer(&ctx[0]))
	}
	if C.gtos_uno_prove_balance_ctx(
		(*C.uchar)(unsafe.Pointer(&proof[0])),
		(*C.uchar)(unsafe.Pointer(&sourcePrivkey32[0])),
		(*C.uchar)(unsafe.Pointer(&sourceCiphertext64[0])),
		C.ulong(amount),
		ctxPtr,
		C.size_t(len(ctx)),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return proof, nil
}

func ProveUNOBalanceProof(sourcePrivkey32, sourceCiphertext64 []byte, amount uint64) ([]byte, error) {
	return ProveUNOBalanceProofWithContext(sourcePrivkey32, sourceCiphertext64, amount, nil)
}

func ElgamalCTAddCompressed(a64, b64 []byte) ([]byte, error) {
	if len(a64) != 64 || len(b64) != 64 {
		return nil, ErrUNOInvalidInput
	}
	out := make([]byte, 64)
	if C.gtos_elgamal_ct_add_compressed(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&a64[0])),
		(*C.uchar)(unsafe.Pointer(&b64[0])),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func ElgamalCTSubCompressed(a64, b64 []byte) ([]byte, error) {
	if len(a64) != 64 || len(b64) != 64 {
		return nil, ErrUNOInvalidInput
	}
	out := make([]byte, 64)
	if C.gtos_elgamal_ct_sub_compressed(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&a64[0])),
		(*C.uchar)(unsafe.Pointer(&b64[0])),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func ElgamalCTAddAmountCompressed(in64 []byte, amount uint64) ([]byte, error) {
	if len(in64) != 64 {
		return nil, ErrUNOInvalidInput
	}
	out := make([]byte, 64)
	if C.gtos_elgamal_ct_add_amount_compressed(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&in64[0])),
		C.ulong(amount),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func ElgamalCTSubAmountCompressed(in64 []byte, amount uint64) ([]byte, error) {
	if len(in64) != 64 {
		return nil, ErrUNOInvalidInput
	}
	out := make([]byte, 64)
	if C.gtos_elgamal_ct_sub_amount_compressed(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&in64[0])),
		C.ulong(amount),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func ElgamalCTNormalizeCompressed(in64 []byte) ([]byte, error) {
	if len(in64) != 64 {
		return nil, ErrUNOInvalidInput
	}
	out := make([]byte, 64)
	if C.gtos_elgamal_ct_normalize_compressed(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&in64[0])),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func ElgamalCTZeroCompressed() ([]byte, error) {
	out := make([]byte, 64)
	if C.gtos_elgamal_ct_zero_compressed(
		(*C.uchar)(unsafe.Pointer(&out[0])),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func ElgamalCTAddScalarCompressed(in64, scalar32 []byte) ([]byte, error) {
	if len(in64) != 64 || len(scalar32) != 32 {
		return nil, ErrUNOInvalidInput
	}
	out := make([]byte, 64)
	if C.gtos_elgamal_ct_add_scalar_compressed(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&in64[0])),
		(*C.uchar)(unsafe.Pointer(&scalar32[0])),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func ElgamalCTSubScalarCompressed(in64, scalar32 []byte) ([]byte, error) {
	if len(in64) != 64 || len(scalar32) != 32 {
		return nil, ErrUNOInvalidInput
	}
	out := make([]byte, 64)
	if C.gtos_elgamal_ct_sub_scalar_compressed(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&in64[0])),
		(*C.uchar)(unsafe.Pointer(&scalar32[0])),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func ElgamalCTMulScalarCompressed(in64, scalar32 []byte) ([]byte, error) {
	if len(in64) != 64 || len(scalar32) != 32 {
		return nil, ErrUNOInvalidInput
	}
	out := make([]byte, 64)
	if C.gtos_elgamal_ct_mul_scalar_compressed(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&in64[0])),
		(*C.uchar)(unsafe.Pointer(&scalar32[0])),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func VerifyUNOCommitmentEqProof(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment []byte) error {
	if len(proof192) != 192 || len(sourcePubkey) != 32 || len(sourceCiphertext64) != 64 || len(destinationCommitment) != 32 {
		return ErrUNOInvalidInput
	}
	if C.gtos_uno_verify_commitment_eq(
		(*C.uchar)(unsafe.Pointer(&proof192[0])),
		(*C.uchar)(unsafe.Pointer(&sourcePubkey[0])),
		(*C.uchar)(unsafe.Pointer(&sourceCiphertext64[0])),
		(*C.uchar)(unsafe.Pointer(&destinationCommitment[0])),
	) != 0 {
		return ErrUNOInvalidProof
	}
	return nil
}

func VerifyUNOBalanceProof(proof, publicKey, sourceCiphertext64 []byte) error {
	if len(proof) != 200 || len(publicKey) != 32 || len(sourceCiphertext64) != 64 {
		return ErrUNOInvalidInput
	}
	if C.gtos_uno_verify_balance(
		(*C.uchar)(unsafe.Pointer(&proof[0])),
		C.size_t(len(proof)),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&sourceCiphertext64[0])),
	) != 0 {
		return ErrUNOInvalidProof
	}
	return nil
}

func VerifyUNORangeProof(proof []byte, commitments []byte, bitLengths []byte, batchLen uint8) error {
	if batchLen == 0 {
		return ErrUNOInvalidInput
	}
	if len(commitments) != int(batchLen)*32 || len(bitLengths) != int(batchLen) || len(proof) == 0 {
		return ErrUNOInvalidInput
	}
	if C.gtos_uno_verify_rangeproof(
		(*C.uchar)(unsafe.Pointer(&proof[0])),
		C.size_t(len(proof)),
		(*C.uchar)(unsafe.Pointer(&commitments[0])),
		(*C.uchar)(unsafe.Pointer(&bitLengths[0])),
		C.uchar(batchLen),
	) != 0 {
		return ErrUNOInvalidProof
	}
	return nil
}

func ElgamalPublicKeyFromPrivate(priv32 []byte) ([]byte, error) {
	if len(priv32) != 32 {
		return nil, ErrUNOInvalidInput
	}
	out := make([]byte, 32)
	if C.gtos_elgamal_public_key_from_private(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&priv32[0])),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func ElgamalEncrypt(pub32 []byte, amount uint64) ([]byte, error) {
	if len(pub32) != 32 {
		return nil, ErrUNOInvalidInput
	}
	out := make([]byte, 64)
	if C.gtos_elgamal_encrypt(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&pub32[0])),
		C.ulong(amount),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func PedersenOpeningGenerate() ([]byte, error) {
	out := make([]byte, 32)
	if C.gtos_pedersen_opening_generate(
		(*C.uchar)(unsafe.Pointer(&out[0])),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func PedersenCommitmentNew(amount uint64) (commitment32 []byte, opening32 []byte, err error) {
	commitment32 = make([]byte, 32)
	opening32 = make([]byte, 32)
	if C.gtos_pedersen_commitment_new(
		(*C.uchar)(unsafe.Pointer(&commitment32[0])),
		(*C.uchar)(unsafe.Pointer(&opening32[0])),
		C.ulong(amount),
	) != 0 {
		return nil, nil, ErrUNOOperationFailed
	}
	return commitment32, opening32, nil
}

func PedersenCommitmentWithOpening(opening32 []byte, amount uint64) ([]byte, error) {
	if len(opening32) != 32 {
		return nil, ErrUNOInvalidInput
	}
	out := make([]byte, 32)
	if C.gtos_pedersen_commitment_with_opening(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.ulong(amount),
		(*C.uchar)(unsafe.Pointer(&opening32[0])),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func ElgamalDecryptHandleWithOpening(pub32, opening32 []byte) ([]byte, error) {
	if len(pub32) != 32 || len(opening32) != 32 {
		return nil, ErrUNOInvalidInput
	}
	out := make([]byte, 32)
	if C.gtos_elgamal_decrypt_handle_with_opening(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&pub32[0])),
		(*C.uchar)(unsafe.Pointer(&opening32[0])),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func ElgamalEncryptWithOpening(pub32 []byte, amount uint64, opening32 []byte) ([]byte, error) {
	if len(pub32) != 32 || len(opening32) != 32 {
		return nil, ErrUNOInvalidInput
	}
	out := make([]byte, 64)
	if C.gtos_elgamal_encrypt_with_opening(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&pub32[0])),
		C.ulong(amount),
		(*C.uchar)(unsafe.Pointer(&opening32[0])),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func ElgamalEncryptWithGeneratedOpening(pub32 []byte, amount uint64) (ct64 []byte, opening32 []byte, err error) {
	if len(pub32) != 32 {
		return nil, nil, ErrUNOInvalidInput
	}
	ct64 = make([]byte, 64)
	opening32 = make([]byte, 32)
	if C.gtos_elgamal_encrypt_with_generated_opening(
		(*C.uchar)(unsafe.Pointer(&ct64[0])),
		(*C.uchar)(unsafe.Pointer(&opening32[0])),
		(*C.uchar)(unsafe.Pointer(&pub32[0])),
		C.ulong(amount),
	) != 0 {
		return nil, nil, ErrUNOOperationFailed
	}
	return ct64, opening32, nil
}

func ElgamalKeypairGenerate() (pub32 []byte, priv32 []byte, err error) {
	pub32 = make([]byte, 32)
	priv32 = make([]byte, 32)
	if C.gtos_elgamal_keypair_generate(
		(*C.uchar)(unsafe.Pointer(&pub32[0])),
		(*C.uchar)(unsafe.Pointer(&priv32[0])),
	) != 0 {
		return nil, nil, ErrUNOOperationFailed
	}
	return pub32, priv32, nil
}

func ElgamalDecryptToPoint(priv32, ct64 []byte) ([]byte, error) {
	if len(priv32) != 32 || len(ct64) != 64 {
		return nil, ErrUNOInvalidInput
	}
	out := make([]byte, 32)
	if C.gtos_elgamal_decrypt_to_point(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&priv32[0])),
		(*C.uchar)(unsafe.Pointer(&ct64[0])),
	) != 0 {
		return nil, ErrUNOOperationFailed
	}
	return out, nil
}

func ElgamalPublicKeyToAddress(pub32 []byte, mainnet bool) (string, error) {
	if len(pub32) != 32 {
		return "", ErrUNOInvalidInput
	}
	out := make([]byte, 128)
	net := C.int(0)
	if mainnet {
		net = 1
	}
	if C.gtos_elgamal_public_key_to_address(
		(*C.char)(unsafe.Pointer(&out[0])),
		C.size_t(len(out)),
		net,
		(*C.uchar)(unsafe.Pointer(&pub32[0])),
	) != 0 {
		return "", ErrUNOOperationFailed
	}
	s := C.GoString((*C.char)(unsafe.Pointer(&out[0])))
	if strings.TrimSpace(s) == "" {
		return "", ErrUNOOperationFailed
	}
	return s, nil
}
