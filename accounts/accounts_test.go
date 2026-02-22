package accounts

import (
	"bytes"
	"testing"

	"github.com/tos-network/gtos/common/hexutil"
)

func TestTextHash(t *testing.T) {
	hash := TextHash([]byte("Hello Joe"))
	want := hexutil.MustDecode("0xc979467d526852fe9b1efe8966ac5177aec46a474c134fc8b918c9117c8d1b6a")
	if !bytes.Equal(hash, want) {
		t.Fatalf("wrong hash: %x", hash)
	}
}
