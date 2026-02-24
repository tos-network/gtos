// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	btcschnorr "github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/google/uuid"
	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
)

const (
	version = 3
)

type Key struct {
	Id uuid.UUID // Version 4 "random" for unique id not derived from key data
	// to simplify lookups we also store the address
	Address common.Address
	// signer type associated with this key material.
	// defaults to secp256k1 when empty.
	SignerType string
	// we only store privkey as pubkey/address can be derived from it
	// privkey in this struct is always in plaintext.
	PrivateKey *ecdsa.PrivateKey
	// Native ed25519 private key (64-byte expanded form). Nil for non-ed25519 accounts.
	Ed25519PrivateKey ed25519.PrivateKey
	// Native bls12-381 private key (32-byte scalar serialization).
	BLS12381PrivateKey []byte
}

type keyStore interface {
	// Loads and decrypts the key from disk.
	GetKey(addr common.Address, filename string, auth string) (*Key, error)
	// Writes and encrypts the key.
	StoreKey(filename string, k *Key, auth string) error
	// Joins filename with the key directory unless it is already absolute.
	JoinPath(filename string) string
}

type plainKeyJSON struct {
	Address    string `json:"address"`
	SignerType string `json:"signerType,omitempty"`
	PrivateKey string `json:"privatekey"`
	Id         string `json:"id"`
	Version    int    `json:"version"`
}

type encryptedKeyJSONV3 struct {
	Address    string     `json:"address"`
	Crypto     CryptoJSON `json:"crypto"`
	SignerType string     `json:"signerType,omitempty"`
	Id         string     `json:"id"`
	Version    int        `json:"version"`
}

type encryptedKeyJSONV1 struct {
	Address    string     `json:"address"`
	Crypto     CryptoJSON `json:"crypto"`
	SignerType string     `json:"signerType,omitempty"`
	Id         string     `json:"id"`
	Version    string     `json:"version"`
}

type CryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

func (k *Key) MarshalJSON() (j []byte, err error) {
	keyHex, err := k.privateKeyHex()
	if err != nil {
		return nil, err
	}
	jStruct := plainKeyJSON{
		hex.EncodeToString(k.Address[:]),
		canonicalSignerTypeOrDefault(k.SignerType),
		keyHex,
		k.Id.String(),
		version,
	}
	j, err = json.Marshal(jStruct)
	return j, err
}

func (k *Key) UnmarshalJSON(j []byte) (err error) {
	keyJSON := new(plainKeyJSON)
	err = json.Unmarshal(j, &keyJSON)
	if err != nil {
		return err
	}

	u := new(uuid.UUID)
	*u, err = uuid.Parse(keyJSON.Id)
	if err != nil {
		return err
	}
	k.Id = *u
	addr, err := hex.DecodeString(keyJSON.Address)
	if err != nil {
		return err
	}
	signerType := canonicalSignerTypeOrDefault(keyJSON.SignerType)
	switch signerType {
	case accountsigner.SignerTypeSecp256k1:
		privkey, decErr := crypto.HexToECDSA(keyJSON.PrivateKey)
		if decErr != nil {
			return decErr
		}
		k.PrivateKey = privkey
		k.Ed25519PrivateKey = nil
		k.BLS12381PrivateKey = nil
	case accountsigner.SignerTypeSchnorr:
		privkey, decErr := crypto.HexToECDSA(keyJSON.PrivateKey)
		if decErr != nil {
			return decErr
		}
		k.PrivateKey = privkey
		k.Ed25519PrivateKey = nil
		k.BLS12381PrivateKey = nil
	case accountsigner.SignerTypeEd25519:
		edPriv, decErr := decodeEd25519PrivateKeyHex(keyJSON.PrivateKey)
		if decErr != nil {
			return decErr
		}
		k.PrivateKey = nil
		k.Ed25519PrivateKey = edPriv
		k.BLS12381PrivateKey = nil
	case accountsigner.SignerTypeBLS12381:
		blsPriv, decErr := decodeBLS12381PrivateKeyHex(keyJSON.PrivateKey)
		if decErr != nil {
			return decErr
		}
		k.PrivateKey = nil
		k.Ed25519PrivateKey = nil
		k.BLS12381PrivateKey = blsPriv
	default:
		return fmt.Errorf("unsupported signer type in keystore key json: %s", signerType)
	}

	k.Address = common.BytesToAddress(addr)
	k.SignerType = signerType

	return nil
}

func newKeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey) *Key {
	id, err := uuid.NewRandom()
	if err != nil {
		panic(fmt.Sprintf("Could not create random uuid: %v", err))
	}
	key := &Key{
		Id:         id,
		Address:    crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),
		SignerType: accountsigner.SignerTypeSecp256k1,
		PrivateKey: privateKeyECDSA,
	}
	return key
}

func schnorrPubkeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey) ([]byte, error) {
	if privateKeyECDSA == nil || privateKeyECDSA.D == nil {
		return nil, fmt.Errorf("missing ecdsa private key")
	}
	priv, _ := btcec.PrivKeyFromBytes(crypto.FromECDSA(privateKeyECDSA))
	return btcschnorr.SerializePubKey(priv.PubKey()), nil
}

func newSchnorrKeyWithID(id uuid.UUID, privateKeyECDSA *ecdsa.PrivateKey) (*Key, error) {
	pub, err := schnorrPubkeyFromECDSA(privateKeyECDSA)
	if err != nil {
		return nil, err
	}
	addr, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeSchnorr, pub)
	if err != nil {
		return nil, err
	}
	return &Key{
		Id:         id,
		Address:    addr,
		SignerType: accountsigner.SignerTypeSchnorr,
		PrivateKey: privateKeyECDSA,
	}, nil
}

func newKeyFromSchnorrECDSA(privateKeyECDSA *ecdsa.PrivateKey) (*Key, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("could not create random uuid: %w", err)
	}
	return newSchnorrKeyWithID(id, privateKeyECDSA)
}

func newKeyFromEd25519(privateKeyED25519 ed25519.PrivateKey) (*Key, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("could not create random uuid: %w", err)
	}
	if len(privateKeyED25519) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size: %d", len(privateKeyED25519))
	}
	pub, ok := privateKeyED25519.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid ed25519 public key")
	}
	addr, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeEd25519, pub)
	if err != nil {
		return nil, err
	}
	key := &Key{
		Id:                id,
		Address:           addr,
		SignerType:        accountsigner.SignerTypeEd25519,
		PrivateKey:        nil,
		Ed25519PrivateKey: append(ed25519.PrivateKey(nil), privateKeyED25519...),
	}
	return key, nil
}

func newKeyFromBLS12381(privateKeyBLS []byte) (*Key, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("could not create random uuid: %w", err)
	}
	pub, err := accountsigner.PublicKeyFromBLS12381Private(privateKeyBLS)
	if err != nil {
		return nil, err
	}
	addr, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeBLS12381, pub)
	if err != nil {
		return nil, err
	}
	return &Key{
		Id:                 id,
		Address:            addr,
		SignerType:         accountsigner.SignerTypeBLS12381,
		PrivateKey:         nil,
		Ed25519PrivateKey:  nil,
		BLS12381PrivateKey: append([]byte(nil), privateKeyBLS...),
	}, nil
}

// NewKeyForDirectICAP generates a key whose address fits into < 155 bits so it can fit
// into the Direct ICAP spec. for simplicity and easier compatibility with other libs, we
// retry until the first byte is 0.
func NewKeyForDirectICAP(rand io.Reader) *Key {
	randBytes := make([]byte, 64)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic("key generation: could not read from random source: " + err.Error())
	}
	reader := bytes.NewReader(randBytes)
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), reader)
	if err != nil {
		panic("key generation: ecdsa.GenerateKey failed: " + err.Error())
	}
	key := newKeyFromECDSA(privateKeyECDSA)
	if !strings.HasPrefix(key.Address.Hex(), "0x00") {
		return NewKeyForDirectICAP(rand)
	}
	return key
}

func newKey(rand io.Reader) (*Key, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand)
	if err != nil {
		return nil, err
	}
	return newKeyFromECDSA(privateKeyECDSA), nil
}

func newEd25519Key(rand io.Reader) (*Key, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, err
	}
	return newKeyFromEd25519(ed25519.NewKeyFromSeed(seed))
}

func newSchnorrKey(rand io.Reader) (*Key, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand)
	if err != nil {
		return nil, err
	}
	return newKeyFromSchnorrECDSA(privateKeyECDSA)
}

func newBLS12381Key(rand io.Reader) (*Key, error) {
	priv, err := accountsigner.GenerateBLS12381PrivateKey(rand)
	if err != nil {
		return nil, err
	}
	return newKeyFromBLS12381(priv)
}

func storeNewKey(ks keyStore, rand io.Reader, auth string) (*Key, accounts.Account, error) {
	key, err := newKey(rand)
	if err != nil {
		return nil, accounts.Account{}, err
	}
	a := accounts.Account{
		Address: key.Address,
		URL:     accounts.URL{Scheme: KeyStoreScheme, Path: ks.JoinPath(keyFileName(key.Address))},
	}
	if err := ks.StoreKey(a.URL.Path, key, auth); err != nil {
		zeroKeyMaterial(key)
		return nil, a, err
	}
	return key, a, err
}

func storeNewEd25519Key(ks keyStore, rand io.Reader, auth string) (*Key, accounts.Account, error) {
	key, err := newEd25519Key(rand)
	if err != nil {
		return nil, accounts.Account{}, err
	}
	a := accounts.Account{
		Address: key.Address,
		URL:     accounts.URL{Scheme: KeyStoreScheme, Path: ks.JoinPath(keyFileName(key.Address))},
	}
	if err := ks.StoreKey(a.URL.Path, key, auth); err != nil {
		zeroKeyMaterial(key)
		return nil, a, err
	}
	return key, a, err
}

func storeNewSchnorrKey(ks keyStore, rand io.Reader, auth string) (*Key, accounts.Account, error) {
	key, err := newSchnorrKey(rand)
	if err != nil {
		return nil, accounts.Account{}, err
	}
	a := accounts.Account{
		Address: key.Address,
		URL:     accounts.URL{Scheme: KeyStoreScheme, Path: ks.JoinPath(keyFileName(key.Address))},
	}
	if err := ks.StoreKey(a.URL.Path, key, auth); err != nil {
		zeroKeyMaterial(key)
		return nil, a, err
	}
	return key, a, err
}

func storeNewBLS12381Key(ks keyStore, rand io.Reader, auth string) (*Key, accounts.Account, error) {
	key, err := newBLS12381Key(rand)
	if err != nil {
		return nil, accounts.Account{}, err
	}
	a := accounts.Account{
		Address: key.Address,
		URL:     accounts.URL{Scheme: KeyStoreScheme, Path: ks.JoinPath(keyFileName(key.Address))},
	}
	if err := ks.StoreKey(a.URL.Path, key, auth); err != nil {
		zeroKeyMaterial(key)
		return nil, a, err
	}
	return key, a, err
}

func canonicalSignerTypeOrDefault(signerType string) string {
	if signerType == "" {
		return accountsigner.SignerTypeSecp256k1
	}
	normalized, err := accountsigner.CanonicalSignerType(signerType)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(signerType))
	}
	return normalized
}

func decodeEd25519PrivateKeyHex(privHex string) (ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, err
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("invalid ed25519 private key size: %d", len(raw))
	}
}

func decodeBLS12381PrivateKeyHex(privHex string) ([]byte, error) {
	raw, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, err
	}
	if _, err := accountsigner.PublicKeyFromBLS12381Private(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func (k *Key) privateKeyHex() (string, error) {
	switch canonicalSignerTypeOrDefault(k.SignerType) {
	case accountsigner.SignerTypeSecp256k1:
		if k.PrivateKey == nil {
			return "", fmt.Errorf("missing ecdsa private key")
		}
		return hex.EncodeToString(crypto.FromECDSA(k.PrivateKey)), nil
	case accountsigner.SignerTypeSchnorr:
		if k.PrivateKey == nil {
			return "", fmt.Errorf("missing schnorr private key")
		}
		return hex.EncodeToString(crypto.FromECDSA(k.PrivateKey)), nil
	case accountsigner.SignerTypeEd25519:
		if len(k.Ed25519PrivateKey) != ed25519.PrivateKeySize {
			return "", fmt.Errorf("missing ed25519 private key")
		}
		return hex.EncodeToString(k.Ed25519PrivateKey.Seed()), nil
	case accountsigner.SignerTypeBLS12381:
		if _, err := accountsigner.PublicKeyFromBLS12381Private(k.BLS12381PrivateKey); err != nil {
			return "", fmt.Errorf("missing bls12-381 private key")
		}
		return hex.EncodeToString(k.BLS12381PrivateKey), nil
	default:
		return "", fmt.Errorf("unsupported signer type: %s", k.SignerType)
	}
}

func writeTemporaryKeyFile(file string, content []byte) (string, error) {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirPerm = 0700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return "", err
	}
	// Atomic write: create a temporary hidden file first
	// then move it into place. TempFile assigns mode 0600.
	f, err := os.CreateTemp(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	return f.Name(), nil
}

func writeKeyFile(file string, content []byte) error {
	name, err := writeTemporaryKeyFile(file, content)
	if err != nil {
		return err
	}
	return os.Rename(name, file)
}

// keyFileName implements the naming convention for keyfiles:
// UTC--<created_at UTC ISO8601>-<address hex>
func keyFileName(keyAddr common.Address) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
}

func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s",
		t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}
