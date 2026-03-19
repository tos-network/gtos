package priv

import (
	"fmt"
	"math/big"

	cryptopriv "github.com/tos-network/gtos/crypto/priv"
)

// decryptionTokenMaxAmount is the upper bound for the BSGS discrete-log
// search when building or verifying decryption tokens.  sqrt(2^32) ≈ 65 536
// baby steps, which completes in well under a second with pure-Go ristretto255.
const decryptionTokenMaxAmount = 1 << 32

// DecryptionToken bundles a decryption token with its DLEQ proof and metadata.
// The token allows a third party to decrypt a specific ciphertext, and the
// DLEQ proof proves the token was honestly generated using the account holder's
// private key.
type DecryptionToken struct {
	Pubkey      [32]byte
	Ciphertext  Ciphertext
	Token       [32]byte
	DLEQProof   [96]byte // reuses Phase 1 disclosure DLEQ
	BlockNumber uint64
}

// BuildDecryptionToken generates a decryption token with a DLEQ honesty proof.
// The DLEQ proof reuses the disclosure-exact construction to prove that the
// token was generated using the same private key that owns the account.
func BuildDecryptionToken(
	privkey, pubkey [32]byte,
	ct Ciphertext,
	chainID *big.Int,
	blockNum uint64,
) (*DecryptionToken, error) {
	// Generate raw token: sk * D
	token, err := cryptopriv.GenerateDecryptionToken(privkey[:], ct.Handle[:])
	if err != nil {
		return nil, err
	}

	// Decrypt with token to find amount (we need amount for the DLEQ proof)
	amountPoint, err := cryptopriv.DecryptWithToken(token, ct.Commitment[:])
	if err != nil {
		return nil, err
	}

	// Solve ECDLP to recover amount — needed for the DLEQ proof transcript
	amount, found, err := cryptopriv.SolveDiscreteLog(amountPoint, decryptionTokenMaxAmount)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrInvalidPayload
	}

	// Build DLEQ proof (reuses disclosure-exact construction)
	ctx := BuildDisclosureContext(chainID, pubkey, ct, blockNum)
	ct64 := make([]byte, 64)
	copy(ct64[:32], ct.Commitment[:])
	copy(ct64[32:], ct.Handle[:])
	proof, err := cryptopriv.ProveDisclosureExact(privkey[:], pubkey[:], ct64, amount, ctx)
	if err != nil {
		return nil, err
	}

	dt := &DecryptionToken{
		Pubkey:      pubkey,
		Ciphertext:  ct,
		BlockNumber: blockNum,
	}
	copy(dt.Token[:], token)
	copy(dt.DLEQProof[:], proof)
	return dt, nil
}

// VerifyDecryptionToken verifies that a decryption token was honestly generated.
// It decrypts the ciphertext using the token, recovers the amount, then verifies
// the DLEQ proof that the token was generated with the correct private key.
func VerifyDecryptionToken(dt *DecryptionToken, chainID *big.Int) error {
	// Decrypt using the token: amountPoint = C - token
	amountPoint, err := cryptopriv.DecryptWithToken(dt.Token[:], dt.Ciphertext.Commitment[:])
	if err != nil {
		return err
	}

	// Recover amount via ECDLP
	amount, found, err := cryptopriv.SolveDiscreteLog(amountPoint, decryptionTokenMaxAmount)
	if err != nil {
		return err
	}
	if !found {
		return ErrInvalidPayload
	}

	// Verify DLEQ proof: proves token = sk * D with correct sk
	ctx := BuildDisclosureContext(chainID, dt.Pubkey, dt.Ciphertext, dt.BlockNumber)
	ct64 := make([]byte, 64)
	copy(ct64[:32], dt.Ciphertext.Commitment[:])
	copy(ct64[32:], dt.Ciphertext.Handle[:])
	return cryptopriv.VerifyDisclosureExact(dt.Pubkey[:], ct64, amount, dt.DLEQProof[:], ctx)
}

// DecryptTokenAmount decrypts a ciphertext using a decryption token and
// recovers the plaintext amount via baby-step giant-step.
func DecryptTokenAmount(dt *DecryptionToken) (uint64, error) {
	amountPoint, err := cryptopriv.DecryptWithToken(dt.Token[:], dt.Ciphertext.Commitment[:])
	if err != nil {
		return 0, err
	}

	amount, found, err := cryptopriv.SolveDiscreteLog(amountPoint, decryptionTokenMaxAmount)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, ErrInvalidPayload
	}
	return amount, nil
}

// BuildDecryptionTokenBatch generates decryption tokens for multiple ciphertexts.
// All tokens use the same private key and chain parameters.
func BuildDecryptionTokenBatch(
	privkey, pubkey [32]byte,
	ciphertexts []Ciphertext,
	chainID *big.Int,
	blockNum uint64,
) ([]*DecryptionToken, error) {
	tokens := make([]*DecryptionToken, len(ciphertexts))
	for i, ct := range ciphertexts {
		dt, err := BuildDecryptionToken(privkey, pubkey, ct, chainID, blockNum)
		if err != nil {
			return nil, fmt.Errorf("token %d: %w", i, err)
		}
		tokens[i] = dt
	}
	return tokens, nil
}
