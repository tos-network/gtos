package tosalign

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestPedersenBlindingPointVector(t *testing.T) {
	h, err := PedersenBlindingPointCompressed()
	if err != nil {
		t.Fatalf("pedersen blinding base: %v", err)
	}

	const expectedHex = "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134"
	if got := hex.EncodeToString(h[:]); got != expectedHex {
		t.Fatalf("unexpected H basepoint\nwant: %s\n got: %s", expectedHex, got)
	}
}

func TestKeyPairAndAddressMatchTOSVector(t *testing.T) {
	private := make([]byte, 32)
	private[0] = 1

	kp, err := KeyPairFromPrivateKeyBytes(private)
	if err != nil {
		t.Fatalf("keypair from private: %v", err)
	}
	pub := kp.PublicKey()

	const expectedPubHex = "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134"
	if got := hex.EncodeToString(pub[:]); got != expectedPubHex {
		t.Fatalf("unexpected compressed public key\nwant: %s\n got: %s", expectedPubHex, got)
	}

	mainAddr, err := pub.ToAddress(true).AsString()
	if err != nil {
		t.Fatalf("mainnet address: %v", err)
	}
	testAddr, err := pub.ToAddress(false).AsString()
	if err != nil {
		t.Fatalf("testnet address: %v", err)
	}

	const expectedMain = "tos13jfypdzk48ndcewrw7ssfrt5t722prxm0azvhntmgme5qjy8zy6qq83fpue"
	const expectedTest = "tst13jfypdzk48ndcewrw7ssfrt5t722prxm0azvhntmgme5qjy8zy6qqupqq54"
	if mainAddr != expectedMain {
		t.Fatalf("unexpected mainnet address\nwant: %s\n got: %s", expectedMain, mainAddr)
	}
	if testAddr != expectedTest {
		t.Fatalf("unexpected testnet address\nwant: %s\n got: %s", expectedTest, testAddr)
	}

	parsedMain, err := AddressFromString(expectedMain)
	if err != nil {
		t.Fatalf("parse mainnet address: %v", err)
	}
	if !parsedMain.IsMainnet() || parsedMain.Type() != AddressTypeNormal {
		t.Fatalf("unexpected parsed mainnet metadata")
	}
	if parsedMain.PublicKey() != pub {
		t.Fatalf("parsed mainnet key mismatch")
	}

	parsedTest, err := AddressFromString(expectedTest)
	if err != nil {
		t.Fatalf("parse testnet address: %v", err)
	}
	if parsedTest.IsMainnet() || parsedTest.Type() != AddressTypeNormal {
		t.Fatalf("unexpected parsed testnet metadata")
	}
	if parsedTest.PublicKey() != pub {
		t.Fatalf("parsed testnet key mismatch")
	}
}

func TestSignatureRoundTrip(t *testing.T) {
	kp, err := NewKeyPair()
	if err != nil {
		t.Fatalf("new keypair: %v", err)
	}

	msg := []byte("gtos/tos signature compatibility")
	sig, err := kp.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !sig.Verify(msg, kp.PublicKey()) {
		t.Fatalf("signature should verify")
	}
	if sig.Verify([]byte("mutated"), kp.PublicKey()) {
		t.Fatalf("signature should fail on mutated message")
	}

	encoded := sig.Bytes()
	decoded, err := SignatureFromBytes(encoded[:])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !decoded.Verify(msg, kp.PublicKey()) {
		t.Fatalf("decoded signature should verify")
	}

	encoded[0] ^= 0x01
	mutated, err := SignatureFromBytes(encoded[:])
	if err == nil && mutated.Verify(msg, kp.PublicKey()) {
		t.Fatalf("mutated signature should not verify")
	}
}

func TestSignatureVectorFromTOS(t *testing.T) {
	msgHex := "67746f732063726f73732d6c616e6775616765207369676e20766563746f72"
	pubHex := "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134"
	sigHex := "473abd64c4ea59b76c1daf019871e231115ff7c94b7240323c6ec743345ea20e09161498f5a447dcfa17910973b72dd9ba765d33b29d3e21b4af98f6ee337e05"

	msg, err := hex.DecodeString(msgHex)
	if err != nil {
		t.Fatalf("decode msg hex: %v", err)
	}
	pubRaw, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatalf("decode pub hex: %v", err)
	}
	key, err := CompressedPublicKeyFromBytes(pubRaw)
	if err != nil {
		t.Fatalf("pub key from bytes: %v", err)
	}
	sigRaw, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("decode signature hex: %v", err)
	}
	sig, err := SignatureFromBytes(sigRaw)
	if err != nil {
		t.Fatalf("signature from bytes: %v", err)
	}
	if !sig.Verify(msg, key) {
		t.Fatalf("rust-generated signature vector should verify")
	}
}

func TestDataAddressRoundTrip(t *testing.T) {
	kp, err := NewKeyPair()
	if err != nil {
		t.Fatalf("new keypair: %v", err)
	}

	rawData := []byte{0xaa, 0xbb, 0xcc, 0x01, 0x02}
	addr := NewDataAddress(true, kp.PublicKey(), rawData)
	encoded, err := addr.AsString()
	if err != nil {
		t.Fatalf("encode data address: %v", err)
	}

	decoded, err := AddressFromString(encoded)
	if err != nil {
		t.Fatalf("decode data address: %v", err)
	}
	if decoded.Type() != AddressTypeData {
		t.Fatalf("expected data address type")
	}
	if decoded.PublicKey() != kp.PublicKey() {
		t.Fatalf("public key mismatch")
	}
	if !bytes.Equal(decoded.RawData(), rawData) {
		t.Fatalf("data payload mismatch")
	}
}

func TestHashVector(t *testing.T) {
	h := HashBytes([]byte("abc"))
	const expected = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
	if got := hex.EncodeToString(h[:]); got != expected {
		t.Fatalf("unexpected blake3 hash\nwant: %s\n got: %s", expected, got)
	}
}
