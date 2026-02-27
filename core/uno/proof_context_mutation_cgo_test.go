//go:build cgo && ed25519c

package uno

import (
	"errors"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	cryptouno "github.com/tos-network/gtos/crypto/uno"
)

// mutateByte flips all bits of ctx[pos] and returns a new slice.
func mutateByte(ctx []byte, pos int) []byte {
	out := append([]byte(nil), ctx...)
	out[pos] ^= 0xFF
	return out
}

// TestPayloadProofContextMutationRejection builds a real proof for each UNO
// action, then verifies that mutating individual bytes in the chain context
// (header fields + action-specific tail fields) causes verification to fail
// with ErrInvalidPayload.
//
// This provides evidence for §7.1 "transcript domain-separation tests" and
// §7.4 "proof-vector differential" in the implementation TODO.
//
// Run:
//
//	go test -tags cgo,ed25519c ./core/uno/... -run TestPayloadProofContextMutationRejection -v
func TestPayloadProofContextMutationRejection(t *testing.T) {
	t.Parallel()

	chainID := big.NewInt(1666)
	from := common.HexToAddress("0xAAAABBBBCCCCDDDDEEEEFF0011223344556677")
	to := common.HexToAddress("0x1122334455667788990011223344556677889900")
	nonce := uint64(9)

	senderPub, senderPriv, err := cryptouno.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair(sender): %v", err)
	}
	receiverPub, _, err := cryptouno.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair(receiver): %v", err)
	}

	// header byte positions that must be fully committed for every action:
	//   [0]      contextVersion
	//   [1..8]   chainId (big-endian uint64)
	//   [9]      actionTag
	//   [10]     nativeAssetTag
	//   [11..42] from address
	//   [43..74] to address (or zero for Shield)
	//   [75..82] nonce (big-endian uint64)
	type mut struct {
		pos  int
		name string
	}
	headerMuts := []mut{
		{0, "contextVersion"},
		{1, "chainId_hi"},
		{8, "chainId_lo"},
		{9, "actionTag"},
		{11, "from[0]"},
		{42, "from[31]"},
		{75, "nonce_hi"},
		{82, "nonce_lo"},
	}

	// verifyCtxMutRejects calls verify with each mutation of ctx and asserts
	// ErrInvalidPayload each time. verify must pass with the original ctx.
	verifyCtxMutRejects := func(t *testing.T, ctx []byte, positions []mut, verify func([]byte) error) {
		t.Helper()
		if err := verify(ctx); err != nil {
			t.Fatalf("baseline verify failed: %v", err)
		}
		for _, m := range positions {
			if m.pos >= len(ctx) {
				t.Fatalf("mutation pos %d out of range (ctx len %d)", m.pos, len(ctx))
			}
			mutCtx := mutateByte(ctx, m.pos)
			err := verify(mutCtx)
			if err == nil {
				t.Errorf("ctx[%d] (%s) mutation: expected ErrInvalidPayload, got nil", m.pos, m.name)
				continue
			}
			if !errors.Is(err, ErrInvalidPayload) {
				t.Errorf("ctx[%d] (%s): expected ErrInvalidPayload, got %v", m.pos, m.name, err)
			}
		}
	}

	t.Run("shield", func(t *testing.T) {
		t.Parallel()
		args := ShieldBuildArgs{
			ChainID:   chainID,
			From:      from,
			Nonce:     nonce,
			SenderOld: Ciphertext{},
			SenderPub: senderPub,
			Amount:    17,
		}
		payload, _, err := BuildShieldPayloadProof(args)
		if err != nil {
			t.Fatalf("BuildShieldPayloadProof: %v", err)
		}
		ctx := BuildUNOShieldTranscriptContext(args.ChainID, args.From, args.Nonce, payload.Amount, args.SenderOld, payload.NewSender)

		// Tail-specific mutations (after the 83-byte header):
		//   [83..90]    amount (uint64)
		//   [91..154]   senderOld ciphertext (commitment+handle)
		//   [155..218]  senderDelta ciphertext (commitment+handle)
		tailMuts := []mut{
			{83, "amount_hi"},
			{90, "amount_lo"},
			{91, "senderOld.commitment[0]"},
			{155, "senderDelta.commitment[0]"},
			{187, "senderDelta.handle[0]"},
		}
		allMuts := append(append([]mut(nil), headerMuts...), tailMuts...)

		// For Shield, to-address bytes (43..74) are zero in the context; mutating
		// any of them changes the context and must cause failure.
		allMuts = append(allMuts, mut{43, "to[0](zero_addr)"})

		verifyCtxMutRejects(t, ctx, allMuts, func(c []byte) error {
			return VerifyShieldProofBundleWithContext(
				payload.ProofBundle,
				payload.NewSender.Commitment[:],
				payload.NewSender.Handle[:],
				senderPub,
				payload.Amount,
				c,
			)
		})
	})

	t.Run("unshield", func(t *testing.T) {
		t.Parallel()
		senderOldRaw, err := cryptouno.Encrypt(senderPub, 40)
		if err != nil {
			t.Fatalf("Encrypt(senderOld): %v", err)
		}
		senderOld := ctFromCompressed(t, senderOldRaw)
		args := UnshieldBuildArgs{
			ChainID:    chainID,
			From:       from,
			To:         to,
			Nonce:      nonce,
			SenderOld:  senderOld,
			SenderPriv: senderPriv,
			Amount:     19,
		}
		payload, _, err := BuildUnshieldPayloadProof(args)
		if err != nil {
			t.Fatalf("BuildUnshieldPayloadProof: %v", err)
		}
		senderDelta, err := SubCiphertexts(senderOld, payload.NewSender)
		if err != nil {
			t.Fatalf("SubCiphertexts: %v", err)
		}
		ctx := BuildUNOUnshieldTranscriptContext(args.ChainID, args.From, args.To, args.Nonce, payload.Amount, senderOld, payload.NewSender)

		// Tail: [83..90] amount, [91..154] senderOld, [155..218] senderNew
		tailMuts := []mut{
			{43, "to[0]"},
			{74, "to[31]"},
			{83, "amount_hi"},
			{90, "amount_lo"},
			{91, "senderOld.commitment[0]"},
			{155, "senderNew.commitment[0]"},
			{187, "senderNew.handle[0]"},
		}
		allMuts := append(append([]mut(nil), headerMuts...), tailMuts...)

		verifyCtxMutRejects(t, ctx, allMuts, func(c []byte) error {
			return VerifyUnshieldProofBundleWithContext(payload.ProofBundle, senderDelta, senderPub, payload.Amount, c)
		})
	})

	t.Run("transfer", func(t *testing.T) {
		t.Parallel()
		senderOldRaw, err := cryptouno.Encrypt(senderPub, 60)
		if err != nil {
			t.Fatalf("Encrypt(senderOld): %v", err)
		}
		receiverOldRaw, err := cryptouno.Encrypt(receiverPub, 5)
		if err != nil {
			t.Fatalf("Encrypt(receiverOld): %v", err)
		}
		senderOld := ctFromCompressed(t, senderOldRaw)
		receiverOld := ctFromCompressed(t, receiverOldRaw)
		args := TransferBuildArgs{
			ChainID:     chainID,
			From:        from,
			To:          to,
			Nonce:       nonce,
			SenderOld:   senderOld,
			ReceiverOld: receiverOld,
			SenderPriv:  senderPriv,
			ReceiverPub: receiverPub,
			Amount:      13,
		}
		payload, _, err := BuildTransferPayloadProof(args)
		if err != nil {
			t.Fatalf("BuildTransferPayloadProof: %v", err)
		}
		senderDelta, err := SubCiphertexts(senderOld, payload.NewSender)
		if err != nil {
			t.Fatalf("SubCiphertexts(senderDelta): %v", err)
		}
		ctx := BuildUNOTransferTranscriptContext(args.ChainID, args.From, args.To, args.Nonce, senderOld, payload.NewSender, receiverOld, payload.ReceiverDelta)

		// Tail: [83..146] senderOld, [147..210] senderNew, [211..274] receiverOld, [275..338] receiverDelta
		tailMuts := []mut{
			{43, "to[0]"},
			{74, "to[31]"},
			{83, "senderOld.commitment[0]"},
			{115, "senderOld.handle[0]"},
			{147, "senderNew.commitment[0]"},
			{179, "senderNew.handle[0]"},
			{211, "receiverOld.commitment[0]"},
			{243, "receiverOld.handle[0]"},
			{275, "receiverDelta.commitment[0]"},
			{307, "receiverDelta.handle[0]"},
		}
		allMuts := append(append([]mut(nil), headerMuts...), tailMuts...)

		verifyCtxMutRejects(t, ctx, allMuts, func(c []byte) error {
			return VerifyTransferProofBundleWithContext(payload.ProofBundle, senderDelta, payload.ReceiverDelta, senderPub, receiverPub, c)
		})
	})
}
