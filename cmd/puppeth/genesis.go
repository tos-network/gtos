// Copyright 2017 The go-ehtereum Authors
// Copyright 2023 The Open System
// This file is part of tos.
//
// tos is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// tos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with tos. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"errors"
	"math"
	"math/big"
	"strings"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	math2 "github.com/tos-network/gtos/common/math"
	"github.com/tos-network/gtos/consensus/ethash"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/params"
)

// alethGenesisSpec represents the genesis specification format used by the
// C++ Tosnetwk implementation.
type alethGenesisSpec struct {
	SealEngine string `json:"sealEngine"`
	Params     struct {
		AccountStartNonce          math2.HexOrDecimal64   `json:"accountStartNonce"`
		MaximumExtraDataSize       hexutil.Uint64         `json:"maximumExtraDataSize"`
		HomesteadForkBlock         *hexutil.Big           `json:"homesteadForkBlock,omitempty"`
		DaoHardforkBlock           math2.HexOrDecimal64   `json:"daoHardforkBlock"`
		EIP150ForkBlock            *hexutil.Big           `json:"EIP150ForkBlock,omitempty"`
		EIP158ForkBlock            *hexutil.Big           `json:"EIP158ForkBlock,omitempty"`
		ByzantiumForkBlock         *hexutil.Big           `json:"byzantiumForkBlock,omitempty"`
		ConstantinopleForkBlock    *hexutil.Big           `json:"constantinopleForkBlock,omitempty"`
		ConstantinopleFixForkBlock *hexutil.Big           `json:"constantinopleFixForkBlock,omitempty"`
		IstanbulForkBlock          *hexutil.Big           `json:"istanbulForkBlock,omitempty"`
		MinGasLimit                hexutil.Uint64         `json:"minGasLimit"`
		MaxGasLimit                hexutil.Uint64         `json:"maxGasLimit"`
		TieBreakingGas             bool                   `json:"tieBreakingGas"`
		GasLimitBoundDivisor       math2.HexOrDecimal64   `json:"gasLimitBoundDivisor"`
		MinimumDifficulty          *hexutil.Big           `json:"minimumDifficulty"`
		DifficultyBoundDivisor     *math2.HexOrDecimal256 `json:"difficultyBoundDivisor"`
		DurationLimit              *math2.HexOrDecimal256 `json:"durationLimit"`
		BlockReward                *hexutil.Big           `json:"blockReward"`
		NetworkID                  hexutil.Uint64         `json:"networkID"`
		ChainID                    hexutil.Uint64         `json:"chainID"`
		AllowFutureBlocks          bool                   `json:"allowFutureBlocks"`
	} `json:"params"`

	Genesis struct {
		Nonce      types.BlockNonce `json:"nonce"`
		Difficulty *hexutil.Big     `json:"difficulty"`
		MixHash    common.Hash      `json:"mixHash"`
		Author     common.Address   `json:"author"`
		Timestamp  hexutil.Uint64   `json:"timestamp"`
		ParentHash common.Hash      `json:"parentHash"`
		ExtraData  hexutil.Bytes    `json:"extraData"`
		GasLimit   hexutil.Uint64   `json:"gasLimit"`
	} `json:"genesis"`

	Accounts map[common.UnprefixedAddress]*alethGenesisSpecAccount `json:"accounts"`
}

// alethGenesisSpecAccount is the prefunded genesis account and/or precompiled
// contract definition.
type alethGenesisSpecAccount struct {
	Balance     *math2.HexOrDecimal256   `json:"balance,omitempty"`
	Nonce       uint64                   `json:"nonce,omitempty"`
	Precompiled *alethGenesisSpecBuiltin `json:"precompiled,omitempty"`
}

// alethGenesisSpecBuiltin is the precompiled contract definition.
type alethGenesisSpecBuiltin struct {
	Name          string                         `json:"name,omitempty"`
	StartingBlock *hexutil.Big                   `json:"startingBlock,omitempty"`
	Linear        *alethGenesisSpecLinearPricing `json:"linear,omitempty"`
}

type alethGenesisSpecLinearPricing struct {
	Base uint64 `json:"base"`
	Word uint64 `json:"word"`
}

// newAlethGenesisSpec converts a tos genesis block into a Aleth-specific
// chain specification format.
func newAlethGenesisSpec(network string, genesis *core.Genesis) (*alethGenesisSpec, error) {
	// Only ethash is currently supported between tos and aleth
	if genesis.Config.Ethash == nil {
		return nil, errors.New("unsupported consensus engine")
	}
	// Reconstruct the chain spec in Aleth format
	spec := &alethGenesisSpec{
		SealEngine: "Ethash",
	}
	// Some defaults
	spec.Params.AccountStartNonce = 0
	spec.Params.TieBreakingGas = false
	spec.Params.AllowFutureBlocks = false

	// Dao hardfork block is a special one. The fork block is listed as 0 in the
	// config but aleth will sync with ETC clients up until the actual dao hard
	// fork block.
	spec.Params.DaoHardforkBlock = 0

	if num := genesis.Config.IstanbulBlock; num != nil {
		spec.Params.IstanbulForkBlock = (*hexutil.Big)(num)
	}
	spec.Params.NetworkID = (hexutil.Uint64)(genesis.Config.ChainID.Uint64())
	spec.Params.ChainID = (hexutil.Uint64)(genesis.Config.ChainID.Uint64())
	spec.Params.MaximumExtraDataSize = (hexutil.Uint64)(params.MaximumExtraDataSize)
	spec.Params.MinGasLimit = (hexutil.Uint64)(params.MinGasLimit)
	spec.Params.MaxGasLimit = (hexutil.Uint64)(math.MaxInt64)
	spec.Params.MinimumDifficulty = (*hexutil.Big)(params.MinimumDifficulty)
	spec.Params.DifficultyBoundDivisor = (*math2.HexOrDecimal256)(params.DifficultyBoundDivisor)
	spec.Params.GasLimitBoundDivisor = (math2.HexOrDecimal64)(params.GasLimitBoundDivisor)
	spec.Params.DurationLimit = (*math2.HexOrDecimal256)(params.DurationLimit)
	spec.Params.BlockReward = (*hexutil.Big)(ethash.FrontierBlockReward)

	spec.Genesis.Nonce = types.EncodeNonce(genesis.Nonce)
	spec.Genesis.MixHash = genesis.Mixhash
	spec.Genesis.Difficulty = (*hexutil.Big)(genesis.Difficulty)
	spec.Genesis.Author = genesis.Coinbase
	spec.Genesis.Timestamp = (hexutil.Uint64)(genesis.Timestamp)
	spec.Genesis.ParentHash = genesis.ParentHash
	spec.Genesis.ExtraData = genesis.ExtraData
	spec.Genesis.GasLimit = (hexutil.Uint64)(genesis.GasLimit)

	for address, account := range genesis.Alloc {
		spec.setAccount(address, account)
	}

	spec.setPrecompile(1, &alethGenesisSpecBuiltin{Name: "ecrecover",
		Linear: &alethGenesisSpecLinearPricing{Base: 3000}})
	spec.setPrecompile(2, &alethGenesisSpecBuiltin{Name: "sha256",
		Linear: &alethGenesisSpecLinearPricing{Base: 60, Word: 12}})
	spec.setPrecompile(3, &alethGenesisSpecBuiltin{Name: "ripemd160",
		Linear: &alethGenesisSpecLinearPricing{Base: 600, Word: 120}})
	spec.setPrecompile(4, &alethGenesisSpecBuiltin{Name: "identity",
		Linear: &alethGenesisSpecLinearPricing{Base: 15, Word: 3}})
	if genesis.Config.IstanbulBlock != nil {
		spec.setPrecompile(6, &alethGenesisSpecBuiltin{
			Name:          "alt_bn128_G1_add",
			StartingBlock: (*hexutil.Big)(genesis.Config.IstanbulBlock),
		}) // Aleth hardcoded the gas policy
		spec.setPrecompile(7, &alethGenesisSpecBuiltin{
			Name:          "alt_bn128_G1_mul",
			StartingBlock: (*hexutil.Big)(genesis.Config.IstanbulBlock),
		}) // Aleth hardcoded the gas policy
		spec.setPrecompile(9, &alethGenesisSpecBuiltin{
			Name:          "blake2_compression",
			StartingBlock: (*hexutil.Big)(genesis.Config.IstanbulBlock),
		})
	}
	return spec, nil
}

func (spec *alethGenesisSpec) setPrecompile(address byte, data *alethGenesisSpecBuiltin) {
	if spec.Accounts == nil {
		spec.Accounts = make(map[common.UnprefixedAddress]*alethGenesisSpecAccount)
	}
	addr := common.UnprefixedAddress(common.BytesToAddress([]byte{address}))
	if _, exist := spec.Accounts[addr]; !exist {
		spec.Accounts[addr] = &alethGenesisSpecAccount{}
	}
	spec.Accounts[addr].Precompiled = data
}

func (spec *alethGenesisSpec) setAccount(address common.Address, account core.GenesisAccount) {
	if spec.Accounts == nil {
		spec.Accounts = make(map[common.UnprefixedAddress]*alethGenesisSpecAccount)
	}

	a, exist := spec.Accounts[common.UnprefixedAddress(address)]
	if !exist {
		a = &alethGenesisSpecAccount{}
		spec.Accounts[common.UnprefixedAddress(address)] = a
	}
	a.Balance = (*math2.HexOrDecimal256)(account.Balance)
	a.Nonce = account.Nonce

}

// parityChainSpec is the chain specification format used by Parity.
type parityChainSpec struct {
	Name    string `json:"name"`
	Datadir string `json:"dataDir"`
	Engine  struct {
		Ethash struct {
			Params struct {
				MinimumDifficulty      *hexutil.Big      `json:"minimumDifficulty"`
				DifficultyBoundDivisor *hexutil.Big      `json:"difficultyBoundDivisor"`
				DurationLimit          *hexutil.Big      `json:"durationLimit"`
				BlockReward            map[string]string `json:"blockReward"`
				DifficultyBombDelays   map[string]string `json:"difficultyBombDelays"`
				HomesteadTransition    hexutil.Uint64    `json:"homesteadTransition"`
				EIP100bTransition      hexutil.Uint64    `json:"eip100bTransition"`
			} `json:"params"`
		} `json:"Ethash"`
	} `json:"engine"`

	Params struct {
		AccountStartNonce     hexutil.Uint64       `json:"accountStartNonce"`
		MaximumExtraDataSize  hexutil.Uint64       `json:"maximumExtraDataSize"`
		MinGasLimit           hexutil.Uint64       `json:"minGasLimit"`
		GasLimitBoundDivisor  math2.HexOrDecimal64 `json:"gasLimitBoundDivisor"`
		NetworkID             hexutil.Uint64       `json:"networkID"`
		ChainID               hexutil.Uint64       `json:"chainID"`
		MaxCodeSize           hexutil.Uint64       `json:"maxCodeSize"`
		MaxCodeSizeTransition hexutil.Uint64       `json:"maxCodeSizeTransition"`
		EIP2028Transition     hexutil.Uint64       `json:"eip2028Transition"`
	} `json:"params"`

	Genesis struct {
		Seal struct {
			Tosnetwk struct {
				Nonce   types.BlockNonce `json:"nonce"`
				MixHash hexutil.Bytes    `json:"mixHash"`
			} `json:"tosnetwk"`
		} `json:"seal"`

		Difficulty *hexutil.Big   `json:"difficulty"`
		Author     common.Address `json:"author"`
		Timestamp  hexutil.Uint64 `json:"timestamp"`
		ParentHash common.Hash    `json:"parentHash"`
		ExtraData  hexutil.Bytes  `json:"extraData"`
		GasLimit   hexutil.Uint64 `json:"gasLimit"`
	} `json:"genesis"`

	Nodes    []string                                             `json:"nodes"`
	Accounts map[common.UnprefixedAddress]*parityChainSpecAccount `json:"accounts"`
}

// parityChainSpecAccount is the prefunded genesis account and/or precompiled
// contract definition.
type parityChainSpecAccount struct {
	Balance math2.HexOrDecimal256   `json:"balance"`
	Nonce   math2.HexOrDecimal64    `json:"nonce,omitempty"`
	Builtin *parityChainSpecBuiltin `json:"builtin,omitempty"`
}

// parityChainSpecBuiltin is the precompiled contract definition.
type parityChainSpecBuiltin struct {
	Name       string       `json:"name"`                  // Each builtin should has it own name
	Pricing    interface{}  `json:"pricing"`               // Each builtin should has it own price strategy
	ActivateAt *hexutil.Big `json:"activate_at,omitempty"` // ActivateAt can't be omitted if empty, default means no fork
}

// parityChainSpecPricing represents the different pricing models that builtin
// contracts might advertise using.
type parityChainSpecPricing struct {
	Linear *parityChainSpecLinearPricing `json:"linear,omitempty"`
	ModExp *parityChainSpecModExpPricing `json:"modexp,omitempty"`

	// Before the https://github.com/paritytech/parity-tosnetwk/pull/11039,
	// Parity uses this format to config bn pairing price policy.
	AltBnPairing *parityChainSepcAltBnPairingPricing `json:"alt_bn128_pairing,omitempty"`

	// Blake2F is the price per round of Blake2 compression
	Blake2F *parityChainSpecBlakePricing `json:"blake2_f,omitempty"`
}

type parityChainSpecLinearPricing struct {
	Base uint64 `json:"base"`
	Word uint64 `json:"word"`
}

type parityChainSpecModExpPricing struct {
	Divisor uint64 `json:"divisor"`
}

// parityChainSpecAltBnConstOperationPricing defines the price
// policy for bn const operation(used after istanbul)
type parityChainSpecAltBnConstOperationPricing struct {
	Price uint64 `json:"price"`
}

// parityChainSepcAltBnPairingPricing defines the price policy
// for bn pairing.
type parityChainSepcAltBnPairingPricing struct {
	Base uint64 `json:"base"`
	Pair uint64 `json:"pair"`
}

// parityChainSpecBlakePricing defines the price policy for blake2 f
// compression.
type parityChainSpecBlakePricing struct {
	GasPerRound uint64 `json:"gas_per_round"`
}

type parityChainSpecAlternativePrice struct {
	AltBnConstOperationPrice *parityChainSpecAltBnConstOperationPricing `json:"alt_bn128_const_operations,omitempty"`
	AltBnPairingPrice        *parityChainSepcAltBnPairingPricing        `json:"alt_bn128_pairing,omitempty"`
}

// parityChainSpecVersionedPricing represents a single version price policy.
type parityChainSpecVersionedPricing struct {
	Price *parityChainSpecAlternativePrice `json:"price,omitempty"`
	Info  string                           `json:"info,omitempty"`
}

// newParityChainSpec converts a tos genesis block into a Parity specific
// chain specification format.
func newParityChainSpec(network string, genesis *core.Genesis, bootnodes []string) (*parityChainSpec, error) {
	// Only ethash is currently supported between tos and Parity
	if genesis.Config.Ethash == nil {
		return nil, errors.New("unsupported consensus engine")
	}
	// Reconstruct the chain spec in Parity's format
	spec := &parityChainSpec{
		Name:    network,
		Nodes:   bootnodes,
		Datadir: strings.ToLower(network),
	}
	spec.Engine.Ethash.Params.BlockReward = make(map[string]string)
	spec.Engine.Ethash.Params.DifficultyBombDelays = make(map[string]string)
	// Frontier
	spec.Engine.Ethash.Params.MinimumDifficulty = (*hexutil.Big)(params.MinimumDifficulty)
	spec.Engine.Ethash.Params.DifficultyBoundDivisor = (*hexutil.Big)(params.DifficultyBoundDivisor)
	spec.Engine.Ethash.Params.DurationLimit = (*hexutil.Big)(params.DurationLimit)
	spec.Engine.Ethash.Params.BlockReward["0x0"] = hexutil.EncodeBig(ethash.FrontierBlockReward)

	// Istanbul
	if num := genesis.Config.IstanbulBlock; num != nil {
		spec.setIstanbul(num)
	}
	spec.Params.MaximumExtraDataSize = (hexutil.Uint64)(params.MaximumExtraDataSize)
	spec.Params.MinGasLimit = (hexutil.Uint64)(params.MinGasLimit)
	spec.Params.GasLimitBoundDivisor = (math2.HexOrDecimal64)(params.GasLimitBoundDivisor)
	spec.Params.NetworkID = (hexutil.Uint64)(genesis.Config.ChainID.Uint64())
	spec.Params.ChainID = (hexutil.Uint64)(genesis.Config.ChainID.Uint64())
	spec.Params.MaxCodeSize = params.MaxCodeSize
	// gtos has it set from zero
	spec.Params.MaxCodeSizeTransition = 0

	spec.Genesis.Seal.Tosnetwk.Nonce = types.EncodeNonce(genesis.Nonce)
	spec.Genesis.Seal.Tosnetwk.MixHash = (genesis.Mixhash[:])
	spec.Genesis.Difficulty = (*hexutil.Big)(genesis.Difficulty)
	spec.Genesis.Author = genesis.Coinbase
	spec.Genesis.Timestamp = (hexutil.Uint64)(genesis.Timestamp)
	spec.Genesis.ParentHash = genesis.ParentHash
	spec.Genesis.ExtraData = genesis.ExtraData
	spec.Genesis.GasLimit = (hexutil.Uint64)(genesis.GasLimit)

	spec.Accounts = make(map[common.UnprefixedAddress]*parityChainSpecAccount)
	for address, account := range genesis.Alloc {
		bal := math2.HexOrDecimal256(*account.Balance)

		spec.Accounts[common.UnprefixedAddress(address)] = &parityChainSpecAccount{
			Balance: bal,
			Nonce:   math2.HexOrDecimal64(account.Nonce),
		}
	}
	spec.setPrecompile(1, &parityChainSpecBuiltin{Name: "ecrecover",
		Pricing: &parityChainSpecPricing{Linear: &parityChainSpecLinearPricing{Base: 3000}}})

	spec.setPrecompile(2, &parityChainSpecBuiltin{
		Name: "sha256", Pricing: &parityChainSpecPricing{Linear: &parityChainSpecLinearPricing{Base: 60, Word: 12}},
	})
	spec.setPrecompile(3, &parityChainSpecBuiltin{
		Name: "ripemd160", Pricing: &parityChainSpecPricing{Linear: &parityChainSpecLinearPricing{Base: 600, Word: 120}},
	})
	spec.setPrecompile(4, &parityChainSpecBuiltin{
		Name: "identity", Pricing: &parityChainSpecPricing{Linear: &parityChainSpecLinearPricing{Base: 15, Word: 3}},
	})
	if genesis.Config.IstanbulBlock != nil {
		spec.setPrecompile(5, &parityChainSpecBuiltin{
			Name:       "modexp",
			ActivateAt: (*hexutil.Big)(genesis.Config.IstanbulBlock),
			Pricing: &parityChainSpecPricing{
				ModExp: &parityChainSpecModExpPricing{Divisor: 20},
			},
		})
		spec.setPrecompile(6, &parityChainSpecBuiltin{
			Name:       "alt_bn128_add",
			ActivateAt: (*hexutil.Big)(genesis.Config.IstanbulBlock),
			Pricing: &parityChainSpecPricing{
				Linear: &parityChainSpecLinearPricing{Base: 500, Word: 0},
			},
		})
		spec.setPrecompile(7, &parityChainSpecBuiltin{
			Name:       "alt_bn128_mul",
			ActivateAt: (*hexutil.Big)(genesis.Config.IstanbulBlock),
			Pricing: &parityChainSpecPricing{
				Linear: &parityChainSpecLinearPricing{Base: 40000, Word: 0},
			},
		})
		spec.setPrecompile(8, &parityChainSpecBuiltin{
			Name:       "alt_bn128_pairing",
			ActivateAt: (*hexutil.Big)(genesis.Config.IstanbulBlock),
			Pricing: &parityChainSpecPricing{
				AltBnPairing: &parityChainSepcAltBnPairingPricing{Base: 100000, Pair: 80000},
			},
		})
	}
	if genesis.Config.IstanbulBlock != nil {
		spec.setPrecompile(6, &parityChainSpecBuiltin{
			Name:       "alt_bn128_add",
			ActivateAt: (*hexutil.Big)(genesis.Config.IstanbulBlock),
			Pricing: map[*hexutil.Big]*parityChainSpecVersionedPricing{
				(*hexutil.Big)(big.NewInt(0)): {
					Price: &parityChainSpecAlternativePrice{
						AltBnConstOperationPrice: &parityChainSpecAltBnConstOperationPricing{Price: 500},
					},
				},
				(*hexutil.Big)(genesis.Config.IstanbulBlock): {
					Price: &parityChainSpecAlternativePrice{
						AltBnConstOperationPrice: &parityChainSpecAltBnConstOperationPricing{Price: 150},
					},
				},
			},
		})
		spec.setPrecompile(7, &parityChainSpecBuiltin{
			Name:       "alt_bn128_mul",
			ActivateAt: (*hexutil.Big)(genesis.Config.IstanbulBlock),
			Pricing: map[*hexutil.Big]*parityChainSpecVersionedPricing{
				(*hexutil.Big)(big.NewInt(0)): {
					Price: &parityChainSpecAlternativePrice{
						AltBnConstOperationPrice: &parityChainSpecAltBnConstOperationPricing{Price: 40000},
					},
				},
				(*hexutil.Big)(genesis.Config.IstanbulBlock): {
					Price: &parityChainSpecAlternativePrice{
						AltBnConstOperationPrice: &parityChainSpecAltBnConstOperationPricing{Price: 6000},
					},
				},
			},
		})
		spec.setPrecompile(8, &parityChainSpecBuiltin{
			Name:       "alt_bn128_pairing",
			ActivateAt: (*hexutil.Big)(genesis.Config.IstanbulBlock),
			Pricing: map[*hexutil.Big]*parityChainSpecVersionedPricing{
				(*hexutil.Big)(big.NewInt(0)): {
					Price: &parityChainSpecAlternativePrice{
						AltBnPairingPrice: &parityChainSepcAltBnPairingPricing{Base: 100000, Pair: 80000},
					},
				},
				(*hexutil.Big)(genesis.Config.IstanbulBlock): {
					Price: &parityChainSpecAlternativePrice{
						AltBnPairingPrice: &parityChainSepcAltBnPairingPricing{Base: 45000, Pair: 34000},
					},
				},
			},
		})
		spec.setPrecompile(9, &parityChainSpecBuiltin{
			Name:       "blake2_f",
			ActivateAt: (*hexutil.Big)(genesis.Config.IstanbulBlock),
			Pricing: &parityChainSpecPricing{
				Blake2F: &parityChainSpecBlakePricing{GasPerRound: 1},
			},
		})
	}
	return spec, nil
}

func (spec *parityChainSpec) setPrecompile(address byte, data *parityChainSpecBuiltin) {
	if spec.Accounts == nil {
		spec.Accounts = make(map[common.UnprefixedAddress]*parityChainSpecAccount)
	}
	a := common.UnprefixedAddress(common.BytesToAddress([]byte{address}))
	if _, exist := spec.Accounts[a]; !exist {
		spec.Accounts[a] = &parityChainSpecAccount{}
	}
	spec.Accounts[a].Builtin = data
}

func (spec *parityChainSpec) setIstanbul(num *big.Int) {
}

// pyTosnetwkGenesisSpec represents the genesis specification format used by the
// Python Tosnetwk implementation.
type pyTosnetwkGenesisSpec struct {
	Nonce      types.BlockNonce  `json:"nonce"`
	Timestamp  hexutil.Uint64    `json:"timestamp"`
	ExtraData  hexutil.Bytes     `json:"extraData"`
	GasLimit   hexutil.Uint64    `json:"gasLimit"`
	Difficulty *hexutil.Big      `json:"difficulty"`
	Mixhash    common.Hash       `json:"mixhash"`
	Coinbase   common.Address    `json:"coinbase"`
	Alloc      core.GenesisAlloc `json:"alloc"`
	ParentHash common.Hash       `json:"parentHash"`
}

// newPyTosnetwkGenesisSpec converts a tos genesis block into a Parity specific
// chain specification format.
func newPyTosnetwkGenesisSpec(network string, genesis *core.Genesis) (*pyTosnetwkGenesisSpec, error) {
	// Only ethash is currently supported between tos and pytosnetwk
	if genesis.Config.Ethash == nil {
		return nil, errors.New("unsupported consensus engine")
	}
	spec := &pyTosnetwkGenesisSpec{
		Nonce:      types.EncodeNonce(genesis.Nonce),
		Timestamp:  (hexutil.Uint64)(genesis.Timestamp),
		ExtraData:  genesis.ExtraData,
		GasLimit:   (hexutil.Uint64)(genesis.GasLimit),
		Difficulty: (*hexutil.Big)(genesis.Difficulty),
		Mixhash:    genesis.Mixhash,
		Coinbase:   genesis.Coinbase,
		Alloc:      genesis.Alloc,
		ParentHash: genesis.ParentHash,
	}
	return spec, nil
}
