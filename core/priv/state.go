package priv

import (
	"encoding/binary"
	"errors"
	"math"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/crypto/ristretto255"
	cryptouno "github.com/tos-network/gtos/crypto/uno"
)

var (
	CommitmentSlot = crypto.Keccak256Hash([]byte("gtos.priv.commitment"))
	HandleSlot     = crypto.Keccak256Hash([]byte("gtos.priv.handle"))
	VersionSlot    = crypto.Keccak256Hash([]byte("gtos.priv.version"))
	NonceSlot      = crypto.Keccak256Hash([]byte("gtos.priv.nonce"))
)

func GetAccountState(db vm.StateDB, account common.Address) AccountState {
	var out AccountState
	copy(out.Ciphertext.Commitment[:], db.GetState(account, CommitmentSlot).Bytes())
	copy(out.Ciphertext.Handle[:], db.GetState(account, HandleSlot).Bytes())
	versionWord := db.GetState(account, VersionSlot)
	out.Version = binary.BigEndian.Uint64(versionWord[24:])
	nonceWord := db.GetState(account, NonceSlot)
	out.Nonce = binary.BigEndian.Uint64(nonceWord[24:])
	return out
}

func SetAccountState(db vm.StateDB, account common.Address, st AccountState) {
	db.SetState(account, CommitmentSlot, common.BytesToHash(st.Ciphertext.Commitment[:]))
	db.SetState(account, HandleSlot, common.BytesToHash(st.Ciphertext.Handle[:]))
	var versionWord common.Hash
	binary.BigEndian.PutUint64(versionWord[24:], st.Version)
	db.SetState(account, VersionSlot, versionWord)
	var nonceWord common.Hash
	binary.BigEndian.PutUint64(nonceWord[24:], st.Nonce)
	db.SetState(account, NonceSlot, nonceWord)
}

func GetPrivNonce(db vm.StateDB, account common.Address) uint64 {
	nonceWord := db.GetState(account, NonceSlot)
	return binary.BigEndian.Uint64(nonceWord[24:])
}

func IncrementPrivNonce(db vm.StateDB, account common.Address) uint64 {
	current := GetPrivNonce(db, account)
	next := current + 1
	var word common.Hash
	binary.BigEndian.PutUint64(word[24:], next)
	db.SetState(account, NonceSlot, word)
	return next
}

func IncrementVersion(db vm.StateDB, account common.Address) (uint64, error) {
	current := GetAccountState(db, account)
	if current.Version == math.MaxUint64 {
		return 0, ErrVersionOverflow
	}
	current.Version++
	SetAccountState(db, account, current)
	return current.Version, nil
}

func AddCiphertexts(a, b Ciphertext) (Ciphertext, error) {
	if out64, err := cryptouno.AddCompressedCiphertexts(ciphertextToCompressed(a), ciphertextToCompressed(b)); err == nil {
		return compressedToCiphertext(out64)
	} else if !errors.Is(err, cryptouno.ErrBackendUnavailable) {
		return Ciphertext{}, ErrInvalidPayload
	}

	ac := ristretto255.NewIdentityElement()
	if _, err := ac.SetCanonicalBytes(a.Commitment[:]); err != nil {
		return Ciphertext{}, ErrInvalidPayload
	}
	ah := ristretto255.NewIdentityElement()
	if _, err := ah.SetCanonicalBytes(a.Handle[:]); err != nil {
		return Ciphertext{}, ErrInvalidPayload
	}
	bc := ristretto255.NewIdentityElement()
	if _, err := bc.SetCanonicalBytes(b.Commitment[:]); err != nil {
		return Ciphertext{}, ErrInvalidPayload
	}
	bh := ristretto255.NewIdentityElement()
	if _, err := bh.SetCanonicalBytes(b.Handle[:]); err != nil {
		return Ciphertext{}, ErrInvalidPayload
	}

	sumC := ristretto255.NewIdentityElement().Add(ac, bc).Bytes()
	sumH := ristretto255.NewIdentityElement().Add(ah, bh).Bytes()
	var out Ciphertext
	copy(out.Commitment[:], sumC)
	copy(out.Handle[:], sumH)
	return out, nil
}

func SubCiphertexts(a, b Ciphertext) (Ciphertext, error) {
	if out64, err := cryptouno.SubCompressedCiphertexts(ciphertextToCompressed(a), ciphertextToCompressed(b)); err == nil {
		return compressedToCiphertext(out64)
	} else if !errors.Is(err, cryptouno.ErrBackendUnavailable) {
		return Ciphertext{}, ErrInvalidPayload
	}

	ac := ristretto255.NewIdentityElement()
	if _, err := ac.SetCanonicalBytes(a.Commitment[:]); err != nil {
		return Ciphertext{}, ErrInvalidPayload
	}
	ah := ristretto255.NewIdentityElement()
	if _, err := ah.SetCanonicalBytes(a.Handle[:]); err != nil {
		return Ciphertext{}, ErrInvalidPayload
	}
	bc := ristretto255.NewIdentityElement()
	if _, err := bc.SetCanonicalBytes(b.Commitment[:]); err != nil {
		return Ciphertext{}, ErrInvalidPayload
	}
	bh := ristretto255.NewIdentityElement()
	if _, err := bh.SetCanonicalBytes(b.Handle[:]); err != nil {
		return Ciphertext{}, ErrInvalidPayload
	}

	diffC := ristretto255.NewIdentityElement().Subtract(ac, bc).Bytes()
	diffH := ristretto255.NewIdentityElement().Subtract(ah, bh).Bytes()
	var out Ciphertext
	copy(out.Commitment[:], diffC)
	copy(out.Handle[:], diffH)
	return out, nil
}

// AddScalarToCiphertext adds a plaintext amount to a ciphertext via homomorphic
// scalar addition. This is used for fee refund: the amount is encoded as a
// scalar and added to the commitment component only (handle unchanged since
// scalar addition uses the generator point, not the recipient's public key).
func AddScalarToCiphertext(ct Ciphertext, amount uint64) (Ciphertext, error) {
	if out64, err := cryptouno.AddAmountCompressed(ciphertextToCompressed(ct), amount); err == nil {
		return compressedToCiphertext(out64)
	} else if !errors.Is(err, cryptouno.ErrBackendUnavailable) {
		return Ciphertext{}, ErrInvalidPayload
	}

	// Pure-Go fallback: amount * G added to commitment only.
	// Pedersen commitment: C' = C + amount*G, Handle unchanged.
	c := ristretto255.NewIdentityElement()
	if _, err := c.SetCanonicalBytes(ct.Commitment[:]); err != nil {
		return Ciphertext{}, ErrInvalidPayload
	}
	// Encode amount as a 32-byte little-endian scalar.
	var scalarBytes [32]byte
	binary.LittleEndian.PutUint64(scalarBytes[:8], amount)
	amountScalar := ristretto255.NewScalar()
	if _, err := amountScalar.SetCanonicalBytes(scalarBytes[:]); err != nil {
		return Ciphertext{}, ErrInvalidPayload
	}
	amountPoint := ristretto255.NewIdentityElement().ScalarBaseMult(amountScalar)
	newC := ristretto255.NewIdentityElement().Add(c, amountPoint).Bytes()
	var out Ciphertext
	copy(out.Commitment[:], newC)
	copy(out.Handle[:], ct.Handle[:])
	return out, nil
}

func ciphertextToCompressed(ct Ciphertext) []byte {
	out := make([]byte, 64)
	copy(out[:32], ct.Commitment[:])
	copy(out[32:], ct.Handle[:])
	return out
}

func compressedToCiphertext(in []byte) (Ciphertext, error) {
	if len(in) != 64 {
		return Ciphertext{}, ErrInvalidPayload
	}
	var out Ciphertext
	copy(out.Commitment[:], in[:32])
	copy(out.Handle[:], in[32:])
	return out, nil
}
