package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
)

func validatorSlot(addr common.Address, field string) common.Hash {
	key := make([]byte, 0, common.AddressLength+1+len(field))
	key = append(key, addr.Bytes()...)
	key = append(key, 0x00)
	key = append(key, field...)
	return common.BytesToHash(crypto.Keccak256(key))
}

var validatorCountSlot = common.BytesToHash(
	crypto.Keccak256([]byte("dpos\x00validatorCount")))

func validatorListSlot(i uint64) common.Hash {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], i)
	return common.BytesToHash(
		crypto.Keccak256(append([]byte("dpos\x00validatorList\x00"), idx[:]...)))
}

func uint64Hash(n uint64) common.Hash {
	var v common.Hash
	binary.BigEndian.PutUint64(v[common.HashLength-8:], n)
	return v
}

func main() {
	var validators []common.Address
	if len(os.Args) >= 2 {
		// Accept addresses as command-line arguments: gen_genesis_slots <addr1> [addr2] ...
		for _, arg := range os.Args[1:] {
			validators = append(validators, common.HexToAddress(arg))
		}
	} else {
		fmt.Fprintln(os.Stderr, "usage: gen_genesis_slots <addr1> [addr2] ...")
		os.Exit(1)
	}

	oneTOS := new(big.Int).Mul(big.NewInt(1e9), big.NewInt(1e9)) // 1e18 wei = 1 TOS

	storage := map[string]string{}

	storage[validatorCountSlot.Hex()] = uint64Hash(uint64(len(validators))).Hex()

	for i, addr := range validators {
		var v common.Hash
		copy(v[:], addr.Bytes())
		storage[validatorListSlot(uint64(i)).Hex()] = v.Hex()
	}

	for _, addr := range validators {
		storage[validatorSlot(addr, "selfStake").Hex()] = common.BigToHash(oneTOS).Hex()
		storage[validatorSlot(addr, "registered").Hex()] = uint64Hash(1).Hex()
		storage[validatorSlot(addr, "status").Hex()] = uint64Hash(1).Hex() // Active=1
	}

	out, _ := json.MarshalIndent(storage, "      ", "  ")
	fmt.Printf("      \"storage\": %s\n", out)
}
