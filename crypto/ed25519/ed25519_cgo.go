//go:build cgo && ed25519c

package ed25519

/*
#cgo CFLAGS: -std=gnu17
#cgo CFLAGS: -I${SRCDIR}/libed25519
#cgo CFLAGS: -I${SRCDIR}/libed25519/include

#include <stddef.h>

// Feature selection (mirrors Avatar native capability switches).
#ifndef AT_HAS_INT128
# if defined(__SIZEOF_INT128__)
#  define AT_HAS_INT128 1
# else
#  define AT_HAS_INT128 0
# endif
#endif

#ifndef AT_HAS_X86
# if defined(__x86_64__) || defined(__i386__)
#  define AT_HAS_X86 1
# else
#  define AT_HAS_X86 0
# endif
#endif

#ifndef AT_HAS_SSE
# if defined(__SSE4_2__)
#  define AT_HAS_SSE 1
# else
#  define AT_HAS_SSE 0
# endif
#endif

#ifndef AT_HAS_AVX
# if defined(__AVX2__)
#  define AT_HAS_AVX 1
# else
#  define AT_HAS_AVX 0
# endif
#endif

#ifndef AT_HAS_AVX512
# if defined(__AVX512F__)
#  define AT_HAS_AVX512 1
# else
#  define AT_HAS_AVX512 0
# endif
#endif

#ifndef AT_HAS_AVX512_IFMA
# if defined(__AVX512IFMA__) && defined(__AVX512VBMI__)
#  define AT_HAS_AVX512_IFMA 1
# else
#  define AT_HAS_AVX512_IFMA 0
# endif
#endif

#ifndef AT_HAS_AVX512_GENERAL
# define AT_HAS_AVX512_GENERAL (AT_HAS_AVX512 && !AT_HAS_AVX512_IFMA)
#endif

// Keep SHA512 on portable core in this cgo integration path.
#ifndef AT_SHA512_CORE_IMPL
# define AT_SHA512_CORE_IMPL 0
#endif

#include "at_ed25519.h"
#include "at_curve25519.h"
#include "at_sha512.h"

#ifdef AT_LOG_WARNING
#undef AT_LOG_WARNING
#endif
#define AT_LOG_WARNING(a) ((void)0)

#include "./libed25519/at_sha512.c"
#include "./libed25519/at_f25519.c"
#include "./libed25519/at_curve25519_scalar.c"
#if AT_HAS_AVX && !AT_HAS_AVX512_IFMA && !AT_HAS_AVX512_GENERAL
#include "./libed25519/avx2/at_r2526x10.c"
#include "./libed25519/avx2/at_curve25519.c"
#elif AT_HAS_AVX512_GENERAL
#include "./libed25519/avx512_general/at_r2526x8.c"
#include "./libed25519/at_curve25519.c"
#elif AT_HAS_AVX512_IFMA
#include "./libed25519/avx512_ifma/at_r43x6.c"
#include "./libed25519/avx512_ifma/at_r43x6_ge.c"
#include "./libed25519/avx512_ifma/at_f25519.c"
#include "./libed25519/at_curve25519.c"
#else
#include "./libed25519/at_curve25519.c"
#endif
#include "./libed25519/at_ed25519_user.c"

static void gtos_ed25519_init(void) {
	at_curve25519_init_constants();
}

static int gtos_ed25519_public_from_seed(unsigned char *public_key, const unsigned char *seed) {
	at_sha512_t sha_mem[1];
	at_sha512_t *sha = at_sha512_join(at_sha512_new(sha_mem));
	if (!sha) {
		return 0;
	}
	at_ed25519_public_from_private(public_key, seed, sha);
	if (!at_sha512_delete(at_sha512_leave(sha))) {
		return 0;
	}
	return 1;
}

static int gtos_ed25519_sign(unsigned char *sig,
	const unsigned char *msg,
	size_t msg_sz,
	const unsigned char *public_key,
	const unsigned char *seed) {
	at_sha512_t sha_mem[1];
	at_sha512_t *sha = at_sha512_join(at_sha512_new(sha_mem));
	if (!sha) {
		return 0;
	}
	at_ed25519_sign(sig, msg, (ulong)msg_sz, public_key, seed, sha);
	if (!at_sha512_delete(at_sha512_leave(sha))) {
		return 0;
	}
	return 1;
}

static int gtos_ed25519_verify(const unsigned char *msg,
	size_t msg_sz,
	const unsigned char *sig,
	const unsigned char *public_key) {
	at_sha512_t sha_mem[1];
	at_sha512_t *sha = at_sha512_join(at_sha512_new(sha_mem));
	if (!sha) {
		return 0;
	}
	int ok = at_ed25519_verify(msg, (ulong)msg_sz, sig, public_key, sha) == AT_ED25519_SUCCESS;
	if (!at_sha512_delete(at_sha512_leave(sha))) {
		return 0;
	}
	return ok;
}
*/
import "C"

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"unsafe"
)

func init() {
	C.gtos_ed25519_init()
}

func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	if rand == nil {
		rand = crand.Reader
	}
	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}
	priv := NewKeyFromSeed(seed)
	pub := PublicFromPrivate(priv)
	return pub, priv, nil
}

func NewKeyFromSeed(seed []byte) PrivateKey {
	if l := len(seed); l != SeedSize {
		panic(fmt.Sprintf("ed25519: bad seed length: %d", l))
	}
	privateKey := make([]byte, PrivateKeySize)
	copy(privateKey[:SeedSize], seed)
	if C.gtos_ed25519_public_from_seed(
		(*C.uchar)(unsafe.Pointer(&privateKey[SeedSize])),
		(*C.uchar)(unsafe.Pointer(&privateKey[0])),
	) == 0 {
		panic("ed25519: public key derivation failed")
	}
	return PrivateKey(privateKey)
}

func Sign(privateKey PrivateKey, message []byte) []byte {
	if l := len(privateKey); l != PrivateKeySize {
		panic(fmt.Sprintf("ed25519: bad private key length: %d", l))
	}
	seed := privateKey[:SeedSize]
	pub := privateKey[SeedSize:]
	sig := make([]byte, SignatureSize)
	if C.gtos_ed25519_sign(
		(*C.uchar)(unsafe.Pointer(&sig[0])),
		byteSlicePtr(message),
		C.size_t(len(message)),
		byteSlicePtr(pub),
		byteSlicePtr(seed),
	) == 0 {
		panic("ed25519: sign failed")
	}
	return sig
}

func Verify(publicKey PublicKey, message []byte, sig []byte) bool {
	if len(publicKey) != PublicKeySize || len(sig) != SignatureSize {
		return false
	}
	return C.gtos_ed25519_verify(
		byteSlicePtr(message),
		C.size_t(len(message)),
		byteSlicePtr(sig),
		byteSlicePtr(publicKey),
	) == 1
}

func PublicFromPrivate(privateKey PrivateKey) PublicKey {
	if len(privateKey) != PrivateKeySize {
		return nil
	}
	pub := make([]byte, PublicKeySize)
	copy(pub, privateKey[SeedSize:])
	return PublicKey(pub)
}

func byteSlicePtr(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}
