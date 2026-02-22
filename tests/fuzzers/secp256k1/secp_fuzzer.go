// build +gofuzz

package secp256k1

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	fuzz "github.com/google/gofuzz"
	"github.com/tos-network/gtos/crypto/secp256k1"
)

func Fuzz(input []byte) int {
	var (
		fuzzer = fuzz.NewFromGoFuzz(input)
		curveA = secp256k1.S256()
		curveB = btcec.S256()
		dataP1 []byte
		dataP2 []byte
	)
	// first point
	fuzzer.Fuzz(&dataP1)
	x1, y1 := curveB.ScalarBaseMult(dataP1)
	// second point
	fuzzer.Fuzz(&dataP2)
	x2, y2 := curveB.ScalarBaseMult(dataP2)
	resAX, resAY := curveA.Add(x1, y1, x2, y2)
	resBX, resBY := curveB.Add(x1, y1, x2, y2)
	if resAX.Cmp(resBX) != 0 || resAY.Cmp(resBY) != 0 {
		fmt.Printf("%s %s %s %s\n", x1, y1, x2, y2)
		panic(fmt.Sprintf("Addition failed: gtos: %s %s btcd: %s %s", resAX, resAY, resBX, resBY))
	}
	return 0
}
