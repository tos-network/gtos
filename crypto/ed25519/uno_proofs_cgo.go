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

static int gtos_elgamal_decrypt_to_point(unsigned char *out32, const unsigned char *priv32, const unsigned char *ct64) {
  at_elgamal_private_key_t priv;
  at_elgamal_compressed_ciphertext_t ct;
  at_memcpy(priv.bytes, priv32, 32);
  at_memcpy(ct.bytes, ct64, 64);
  return at_elgamal_private_key_decrypt_to_point(out32, &priv, &ct);
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
*/
import "C"

import (
	_ "github.com/tos-network/gtos/crypto/libsha3"
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
