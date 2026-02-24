package main

import (
	"crypto/ecdsa"
	stded25519 "crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	gtosed25519 "github.com/tos-network/gtos/crypto/ed25519"
)

type result struct {
	name      string
	signUS    float64
	verifyUS  float64
	signOps   float64
	verifyOps float64
}

func bench(n int, fn func()) time.Duration {
	start := time.Now()
	for i := 0; i < n; i++ {
		fn()
	}
	return time.Since(start)
}

func perOpUS(d time.Duration, n int) float64 {
	return float64(d.Microseconds()) / float64(n)
}

func perSecOps(d time.Duration, n int) float64 {
	return float64(n) / d.Seconds()
}

func main() {
	signOps := flag.Int("sign-ops", 5000, "number of sign operations")
	verifyOps := flag.Int("verify-ops", 5000, "number of verify operations")
	flag.Parse()

	if *signOps <= 0 || *verifyOps <= 0 {
		panic("sign-ops and verify-ops must be > 0")
	}

	hash := common.HexToHash("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	out := make([]result, 0, 6)

	// secp256k1
	{
		key, err := crypto.GenerateKey()
		if err != nil {
			panic(err)
		}
		pub := crypto.FromECDSAPub(&key.PublicKey)
		sig, err := crypto.Sign(hash[:], key)
		if err != nil {
			panic(err)
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:64])

		dSign := bench(*signOps, func() {
			if _, err := crypto.Sign(hash[:], key); err != nil {
				panic(err)
			}
		})
		dVerify := bench(*verifyOps, func() {
			if !accountsigner.VerifyRawSignature(accountsigner.SignerTypeSecp256k1, pub, hash, r, s) {
				panic("secp256k1 verify failed")
			}
		})
		out = append(out, result{
			name:      "secp256k1",
			signUS:    perOpUS(dSign, *signOps),
			verifyUS:  perOpUS(dVerify, *verifyOps),
			signOps:   perSecOps(dSign, *signOps),
			verifyOps: perSecOps(dVerify, *verifyOps),
		})
	}

	// secp256r1
	{
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		pub := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
		r0, s0, err := ecdsa.Sign(rand.Reader, key, hash[:])
		if err != nil {
			panic(err)
		}

		dSign := bench(*signOps, func() {
			if _, _, err := ecdsa.Sign(rand.Reader, key, hash[:]); err != nil {
				panic(err)
			}
		})
		dVerify := bench(*verifyOps, func() {
			if !accountsigner.VerifyRawSignature(accountsigner.SignerTypeSecp256r1, pub, hash, r0, s0) {
				panic("secp256r1 verify failed")
			}
		})
		out = append(out, result{
			name:      "secp256r1",
			signUS:    perOpUS(dSign, *signOps),
			verifyUS:  perOpUS(dVerify, *verifyOps),
			signOps:   perSecOps(dSign, *signOps),
			verifyOps: perSecOps(dVerify, *verifyOps),
		})
	}

	// ed25519 (stdlib)
	{
		pub, priv, err := stded25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		sig := stded25519.Sign(priv, hash[:])

		dSign := bench(*signOps, func() {
			_ = stded25519.Sign(priv, hash[:])
		})
		dVerify := bench(*verifyOps, func() {
			if !stded25519.Verify(pub, hash[:], sig) {
				panic("ed25519 std verify failed")
			}
		})
		out = append(out, result{
			name:      "ed25519std",
			signUS:    perOpUS(dSign, *signOps),
			verifyUS:  perOpUS(dVerify, *verifyOps),
			signOps:   perSecOps(dSign, *signOps),
			verifyOps: perSecOps(dVerify, *verifyOps),
		})
	}

	// ed25519 (GTOS backend: may be pure-Go, cgo, or ed25519native based on build tags)
	{
		pub, priv, err := gtosed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		sig := gtosed25519.Sign(priv, hash[:])

		label := "ed25519gtos"
		if gtosed25519.NativeAccelerated() {
			label = "ed25519native"
		}

		dSign := bench(*signOps, func() {
			_ = gtosed25519.Sign(priv, hash[:])
		})
		dVerify := bench(*verifyOps, func() {
			if !gtosed25519.Verify(pub, hash[:], sig) {
				panic("ed25519 gtos verify failed")
			}
		})
		out = append(out, result{
			name:      label,
			signUS:    perOpUS(dSign, *signOps),
			verifyUS:  perOpUS(dVerify, *verifyOps),
			signOps:   perSecOps(dSign, *signOps),
			verifyOps: perSecOps(dVerify, *verifyOps),
		})
	}

	// bls12-381
	{
		priv, err := accountsigner.GenerateBLS12381PrivateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		pub, err := accountsigner.PublicKeyFromBLS12381Private(priv)
		if err != nil {
			panic(err)
		}
		sig, err := accountsigner.SignBLS12381Hash(priv, hash)
		if err != nil {
			panic(err)
		}
		r, s, err := accountsigner.SplitBLS12381Signature(sig)
		if err != nil {
			panic(err)
		}

		dSign := bench(*signOps, func() {
			if _, err := accountsigner.SignBLS12381Hash(priv, hash); err != nil {
				panic(err)
			}
		})
		dVerify := bench(*verifyOps, func() {
			if !accountsigner.VerifyRawSignature(accountsigner.SignerTypeBLS12381, pub, hash, r, s) {
				panic("bls12-381 verify failed")
			}
		})
		out = append(out, result{
			name:      "bls12-381",
			signUS:    perOpUS(dSign, *signOps),
			verifyUS:  perOpUS(dVerify, *verifyOps),
			signOps:   perSecOps(dSign, *signOps),
			verifyOps: perSecOps(dVerify, *verifyOps),
		})
	}

	// elgamal (TOS ristretto variant)
	{
		priv, err := accountsigner.GenerateElgamalPrivateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		pub, err := accountsigner.PublicKeyFromElgamalPrivate(priv)
		if err != nil {
			panic(err)
		}
		sig, err := accountsigner.SignElgamalHash(priv, hash)
		if err != nil {
			panic(err)
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])

		dSign := bench(*signOps, func() {
			if _, err := accountsigner.SignElgamalHash(priv, hash); err != nil {
				panic(err)
			}
		})
		dVerify := bench(*verifyOps, func() {
			if !accountsigner.VerifyRawSignature(accountsigner.SignerTypeElgamal, pub, hash, r, s) {
				panic("elgamal verify failed")
			}
		})
		out = append(out, result{
			name:      "elgamal",
			signUS:    perOpUS(dSign, *signOps),
			verifyUS:  perOpUS(dVerify, *verifyOps),
			signOps:   perSecOps(dSign, *signOps),
			verifyOps: perSecOps(dVerify, *verifyOps),
		})
	}

	fmt.Printf("Signer benchmark on this machine (sign-ops=%d, verify-ops=%d)\n", *signOps, *verifyOps)
	fmt.Println("- Raw sign/verify only; no network or serialization overhead")
	fmt.Printf("%-14s %10s %12s %10s %12s\n", "Algorithm", "sign us", "sign ops/s", "verify us", "verify ops/s")
	for _, r := range out {
		fmt.Printf("%-14s %10.2f %12.0f %10.2f %12.0f\n", r.name, r.signUS, r.signOps, r.verifyUS, r.verifyOps)
	}

	bySign := append([]result(nil), out...)
	sort.Slice(bySign, func(i, j int) bool { return bySign[i].signUS < bySign[j].signUS })
	fmt.Print("\nSign speed rank (fast -> slow): ")
	for i, r := range bySign {
		if i > 0 {
			fmt.Print(" > ")
		}
		fmt.Print(r.name)
	}

	byVerify := append([]result(nil), out...)
	sort.Slice(byVerify, func(i, j int) bool { return byVerify[i].verifyUS < byVerify[j].verifyUS })
	fmt.Print("\nVerify speed rank (fast -> slow): ")
	for i, r := range byVerify {
		if i > 0 {
			fmt.Print(" > ")
		}
		fmt.Print(r.name)
	}
	fmt.Println()
}
