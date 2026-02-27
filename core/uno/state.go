package uno

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
	CommitmentSlot = crypto.Keccak256Hash([]byte("gtos.uno.ctCommitment"))
	HandleSlot     = crypto.Keccak256Hash([]byte("gtos.uno.ctHandle"))
	VersionSlot    = crypto.Keccak256Hash([]byte("gtos.uno.version"))
)

func GetAccountState(db vm.StateDB, account common.Address) AccountState {
	var out AccountState
	copy(out.Ciphertext.Commitment[:], db.GetState(account, CommitmentSlot).Bytes())
	copy(out.Ciphertext.Handle[:], db.GetState(account, HandleSlot).Bytes())
	versionWord := db.GetState(account, VersionSlot)
	out.Version = binary.BigEndian.Uint64(versionWord[24:])
	return out
}

func SetAccountState(db vm.StateDB, account common.Address, st AccountState) {
	db.SetState(account, CommitmentSlot, common.BytesToHash(st.Ciphertext.Commitment[:]))
	db.SetState(account, HandleSlot, common.BytesToHash(st.Ciphertext.Handle[:]))
	var word common.Hash
	binary.BigEndian.PutUint64(word[24:], st.Version)
	db.SetState(account, VersionSlot, word)
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

func AddCiphertextToAccount(db vm.StateDB, account common.Address, delta Ciphertext) error {
	current := GetAccountState(db, account)
	nextCiphertext, err := AddCiphertexts(current.Ciphertext, delta)
	if err != nil {
		return err
	}
	if current.Version == math.MaxUint64 {
		return ErrVersionOverflow
	}
	current.Ciphertext = nextCiphertext
	current.Version++
	SetAccountState(db, account, current)
	return nil
}

func SetCiphertextForAccount(db vm.StateDB, account common.Address, nextCiphertext Ciphertext) error {
	current := GetAccountState(db, account)
	if current.Version == math.MaxUint64 {
		return ErrVersionOverflow
	}
	current.Ciphertext = nextCiphertext
	current.Version++
	SetAccountState(db, account, current)
	return nil
}

func CiphertextEqual(a, b Ciphertext) bool {
	return a == b
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
