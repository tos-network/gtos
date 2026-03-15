package main

import (
	crand "crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/tos-network/gtos/accounts/keystore"
	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	cryptopriv "github.com/tos-network/gtos/crypto/priv"
)

func TestPrivKeygenWritesElgamalKeyfile(t *testing.T) {
	tmpdir := t.TempDir()
	passfile := filepath.Join(tmpdir, "pass.txt")
	keyfile := filepath.Join(tmpdir, "priv-key.json")
	if err := os.WriteFile(passfile, []byte("foobar\n"), 0600); err != nil {
		t.Fatalf("write passfile: %v", err)
	}

	keygen := runTOSkey(t, "priv-keygen", "--json", "--lightkdf", "--passwordfile", passfile, keyfile)
	_, matches := keygen.ExpectRegexp(`(?s)"address":\s*"(0x[0-9a-fA-F]{64})".*"signerType":\s*"elgamal".*"publicKey":\s*"([0-9a-f]+)".*"privateKey":\s*"([0-9a-f]+)".*"keyfile":\s*"` + regexp.QuoteMeta(keyfile) + `"`)
	keygen.ExpectExit()

	inspect := runTOSkey(t, "inspect", "--private", "--passwordfile", passfile, keyfile)
	_, inspectMatches := inspect.ExpectRegexp(`(?s)Address:\s+(0x[0-9a-fA-F]{64})\nSigner type:\s+elgamal\nPublic key:\s+([0-9a-f]+)\nPrivate key:\s+([0-9a-f]+)\n`)
	inspect.ExpectExit()

	if inspectMatches[1] != matches[1] {
		t.Fatalf("address mismatch: have %s want %s", inspectMatches[1], matches[1])
	}
	if inspectMatches[2] != matches[2] {
		t.Fatalf("public key mismatch: have %s want %s", inspectMatches[2], matches[2])
	}
	if inspectMatches[3] != matches[3] {
		t.Fatalf("private key mismatch: have %s want %s", inspectMatches[3], matches[3])
	}
}

func TestPrivBalanceDecryptsFromCiphertextFlag(t *testing.T) {
	tmpdir := t.TempDir()
	keyfile, passfile, pubkey, _, _ := writeTestElgamalKeyfile(t, tmpdir)

	const amount = uint64(37)
	ct64, err := cryptopriv.Encrypt(pubkey[:], amount)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	balance := runTOSkey(t, "priv-balance", "--json", "--passwordfile", passfile, "--ct", hexutil.Encode(ct64), "--max-balance", "100", keyfile)
	_, matches := balance.ExpectRegexp(`(?s)"plaintextBalance":\s*(\d+).*"source":\s*"flag"`)
	balance.ExpectExit()
	if matches[1] != "37" {
		t.Fatalf("plaintext balance = %s, want 37", matches[1])
	}
}

func TestPrivBalanceDecryptsFromRPC(t *testing.T) {
	tmpdir := t.TempDir()
	keyfile, passfile, pubkey, _, _ := writeTestElgamalKeyfile(t, tmpdir)

	const amount = uint64(42)
	ct64, err := cryptopriv.Encrypt(pubkey[:], amount)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	server := newPrivBalanceRPCServer(t, pubkey, ct64, 7, 3, 99)
	defer server.Close()

	balance := runTOSkey(t, "priv-balance", "--json", "--passwordfile", passfile, "--rpc", server.URL, "--max-balance", "100", keyfile)
	_, matches := balance.ExpectRegexp(`(?s)"plaintextBalance":\s*(\d+).*"version":\s*(\d+).*"privNonce":\s*(\d+).*"blockNumber":\s*(\d+).*"source":\s*"rpc"`)
	balance.ExpectExit()

	if matches[1] != "42" || matches[2] != "7" || matches[3] != "3" || matches[4] != "99" {
		t.Fatalf("unexpected rpc decrypt output: balance=%s version=%s nonce=%s block=%s", matches[1], matches[2], matches[3], matches[4])
	}
}

func writeTestElgamalKeyfile(t *testing.T, dir string) (keyfile string, passfile string, pubkey [32]byte, privkey [32]byte, address common.Address) {
	t.Helper()

	privBytes, err := accountsigner.GenerateElgamalPrivateKey(crand.Reader)
	if err != nil {
		t.Fatalf("GenerateElgamalPrivateKey: %v", err)
	}
	pubBytes, err := accountsigner.PublicKeyFromElgamalPrivate(privBytes)
	if err != nil {
		t.Fatalf("PublicKeyFromElgamalPrivate: %v", err)
	}
	address, err = accountsigner.AddressFromSigner(accountsigner.SignerTypeElgamal, pubBytes)
	if err != nil {
		t.Fatalf("AddressFromSigner: %v", err)
	}
	copy(pubkey[:], pubBytes)
	copy(privkey[:], privBytes)

	keyID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("uuid.NewRandom: %v", err)
	}
	keyjson, err := keystore.EncryptKey(&keystore.Key{
		Id:                keyID,
		Address:           address,
		SignerType:        accountsigner.SignerTypeElgamal,
		ElgamalPrivateKey: append([]byte(nil), privBytes...),
	}, "foobar", keystore.LightScryptN, keystore.LightScryptP)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}

	keyfile = filepath.Join(dir, "priv-key.json")
	passfile = filepath.Join(dir, "pass.txt")
	if err := os.WriteFile(keyfile, keyjson, 0600); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
	if err := os.WriteFile(passfile, []byte("foobar\n"), 0600); err != nil {
		t.Fatalf("write passfile: %v", err)
	}
	return keyfile, passfile, pubkey, privkey, address
}

func newPrivBalanceRPCServer(t *testing.T, pubkey [32]byte, ct64 []byte, version, privNonce, blockNumber uint64) *httptest.Server {
	t.Helper()

	type rpcRequest struct {
		ID json.RawMessage `json:"id"`
	}
	type rpcResponse struct {
		JSONRPC string               `json:"jsonrpc"`
		ID      json.RawMessage      `json:"id"`
		Result  rpcPrivBalanceResult `json:"result"`
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode rpc request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		resp := rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: rpcPrivBalanceResult{
				Pubkey:      hexutil.Bytes(pubkey[:]),
				Commitment:  hexutil.Bytes(ct64[:32]),
				Handle:      hexutil.Bytes(ct64[32:]),
				Version:     hexutil.Uint64(version),
				PrivNonce:   hexutil.Uint64(privNonce),
				BlockNumber: hexutil.Uint64(blockNumber),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode rpc response: %v", err)
		}
	}))
}
