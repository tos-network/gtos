package uno

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
)

func TestRequireElgamalSigner(t *testing.T) {
	st := newTestState(t)
	priv, err := accountsigner.GenerateElgamalPrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateElgamalPrivateKey: %v", err)
	}
	pub, err := accountsigner.PublicKeyFromElgamalPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromElgamalPrivate: %v", err)
	}

	addr, err := accountsigner.AddressFromSigner(accountsigner.SignerTypeElgamal, pub)
	if err != nil {
		t.Fatalf("AddressFromSigner: %v", err)
	}
	accountsigner.Set(st, addr, accountsigner.SignerTypeElgamal, hexutil.Encode(pub))

	got, err := RequireElgamalSigner(st, addr)
	if err != nil {
		t.Fatalf("RequireElgamalSigner: %v", err)
	}
	if !bytes.Equal(got, pub) {
		t.Fatalf("pub mismatch")
	}
}

func TestRequireElgamalSignerRejectsMissing(t *testing.T) {
	st := newTestState(t)
	if _, err := RequireElgamalSigner(st, common.HexToAddress("0x1234")); !errors.Is(err, ErrSignerNotConfigured) {
		t.Fatalf("expected ErrSignerNotConfigured, got %v", err)
	}
}

func TestRequireElgamalSignerRejectsWrongType(t *testing.T) {
	st := newTestState(t)
	addr := common.HexToAddress("0x9999")
	accountsigner.Set(st, addr, accountsigner.SignerTypeEd25519, hexutil.Encode(make([]byte, 32)))
	if _, err := RequireElgamalSigner(st, addr); !errors.Is(err, ErrSignerTypeMismatch) {
		t.Fatalf("expected ErrSignerTypeMismatch, got %v", err)
	}
}
