package main

import (
	"fmt"
	"os"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <validator-address> <field>\n", os.Args[0])
		os.Exit(1)
	}
	addr := common.HexToAddress(os.Args[1])
	field := os.Args[2]
	key := make([]byte, 0, common.AddressLength+1+len(field))
	key = append(key, addr.Bytes()...)
	key = append(key, 0x00)
	key = append(key, []byte(field)...)
	fmt.Println(common.BytesToHash(crypto.Keccak256(key)).Hex())
}
