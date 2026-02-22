// Package deps contains the console JavaScript dependencies Go embedded.
package deps

import (
	_ "embed"
)

//go:embed web3.js
var Web3JS string

//go:embed bignumber.js
var BigNumberJS string
