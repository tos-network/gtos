//go:build cgo && ed25519c

package ed25519

/*
#cgo CFLAGS: -std=gnu17
#cgo CFLAGS: -I${SRCDIR}
#include "priv_batch_cgo.h"
*/
import "C"

import (
	"runtime"
	"unsafe"
)

type PrivBatchVerifier struct {
	ptr *C.gtos_priv_batch_verifier_t
}

func NewPrivBatchVerifier() *PrivBatchVerifier {
	b := &PrivBatchVerifier{ptr: C.gtos_priv_batch_new()}
	if b.ptr != nil {
		runtime.SetFinalizer(b, (*PrivBatchVerifier).free)
	}
	return b
}

func (b *PrivBatchVerifier) free() {
	if b.ptr != nil {
		C.gtos_priv_batch_free(b.ptr)
		b.ptr = nil
	}
}

func (b *PrivBatchVerifier) ensure() error {
	if b == nil || b.ptr == nil {
		return ErrPrivOperationFailed
	}
	return nil
}

func (b *PrivBatchVerifier) AddPrivShieldProofWithContext(proof96, commitment, receiverHandle, receiverPubkey []byte, amount uint64, ctx []byte) error {
	if len(proof96) != 96 || len(commitment) != 32 || len(receiverHandle) != 32 || len(receiverPubkey) != 32 {
		return ErrPrivInvalidInput
	}
	if err := b.ensure(); err != nil {
		return err
	}
	var ctxPtr *C.uchar
	if len(ctx) > 0 {
		ctxPtr = (*C.uchar)(unsafe.Pointer(&ctx[0]))
	}
	if C.gtos_priv_batch_add_shield_ctx(
		b.ptr,
		(*C.uchar)(unsafe.Pointer(&proof96[0])),
		(*C.uchar)(unsafe.Pointer(&commitment[0])),
		(*C.uchar)(unsafe.Pointer(&receiverHandle[0])),
		(*C.uchar)(unsafe.Pointer(&receiverPubkey[0])),
		C.ulong(amount),
		ctxPtr,
		C.size_t(len(ctx)),
	) != 0 {
		return ErrPrivInvalidProof
	}
	return nil
}

func (b *PrivBatchVerifier) AddPrivCTValidityProofWithContext(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey []byte, txVersionT1 bool, ctx []byte) error {
	wantLen := 128
	if txVersionT1 {
		wantLen = 160
	}
	if len(proof) != wantLen || len(commitment) != 32 || len(senderHandle) != 32 || len(receiverHandle) != 32 || len(senderPubkey) != 32 || len(receiverPubkey) != 32 {
		return ErrPrivInvalidInput
	}
	if err := b.ensure(); err != nil {
		return err
	}
	var ctxPtr *C.uchar
	if len(ctx) > 0 {
		ctxPtr = (*C.uchar)(unsafe.Pointer(&ctx[0]))
	}
	version := C.int(0)
	if txVersionT1 {
		version = 1
	}
	if C.gtos_priv_batch_add_ct_validity_ctx(
		b.ptr,
		(*C.uchar)(unsafe.Pointer(&proof[0])),
		C.size_t(len(proof)),
		(*C.uchar)(unsafe.Pointer(&commitment[0])),
		(*C.uchar)(unsafe.Pointer(&senderHandle[0])),
		(*C.uchar)(unsafe.Pointer(&receiverHandle[0])),
		(*C.uchar)(unsafe.Pointer(&senderPubkey[0])),
		(*C.uchar)(unsafe.Pointer(&receiverPubkey[0])),
		version,
		ctxPtr,
		C.size_t(len(ctx)),
	) != 0 {
		return ErrPrivInvalidProof
	}
	return nil
}

func (b *PrivBatchVerifier) AddPrivCommitmentEqProofWithContext(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment []byte, ctx []byte) error {
	if len(proof192) != 192 || len(sourcePubkey) != 32 || len(sourceCiphertext64) != 64 || len(destinationCommitment) != 32 {
		return ErrPrivInvalidInput
	}
	if err := b.ensure(); err != nil {
		return err
	}
	var ctxPtr *C.uchar
	if len(ctx) > 0 {
		ctxPtr = (*C.uchar)(unsafe.Pointer(&ctx[0]))
	}
	if C.gtos_priv_batch_add_commitment_eq_ctx(
		b.ptr,
		(*C.uchar)(unsafe.Pointer(&proof192[0])),
		(*C.uchar)(unsafe.Pointer(&sourcePubkey[0])),
		(*C.uchar)(unsafe.Pointer(&sourceCiphertext64[0])),
		(*C.uchar)(unsafe.Pointer(&destinationCommitment[0])),
		ctxPtr,
		C.size_t(len(ctx)),
	) != 0 {
		return ErrPrivInvalidProof
	}
	return nil
}

func (b *PrivBatchVerifier) AddPrivRangeProof(proof []byte, commitments []byte, bitLengths []byte, batchLen uint8) error {
	if batchLen == 0 {
		return ErrPrivInvalidInput
	}
	if len(commitments) != int(batchLen)*32 || len(bitLengths) != int(batchLen) || len(proof) == 0 {
		return ErrPrivInvalidInput
	}
	if err := b.ensure(); err != nil {
		return err
	}
	if C.gtos_priv_batch_add_range(
		b.ptr,
		(*C.uchar)(unsafe.Pointer(&proof[0])),
		C.size_t(len(proof)),
		(*C.uchar)(unsafe.Pointer(&commitments[0])),
		(*C.uchar)(unsafe.Pointer(&bitLengths[0])),
		C.uchar(batchLen),
	) != 0 {
		return ErrPrivInvalidProof
	}
	return nil
}

func (b *PrivBatchVerifier) Verify() error {
	if err := b.ensure(); err != nil {
		return err
	}
	if C.gtos_priv_batch_verify(b.ptr) != 0 {
		return ErrPrivInvalidProof
	}
	return nil
}
