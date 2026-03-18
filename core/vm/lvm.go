package vm

import (
	"bytes"
	"context"
	gosha256 "crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/tos-network/gtos/accounts/abi"
	"github.com/tos-network/gtos/agent"
	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/delegation"
	"github.com/tos-network/gtos/kyc"
	"github.com/tos-network/gtos/lease"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/referral"
	"github.com/tos-network/gtos/reputation"
	"github.com/tos-network/gtos/task"
	"github.com/tos-network/gtos/tns"
	lua "github.com/tos-network/tolang"
	goripemd160 "golang.org/x/crypto/ripemd160"
)

// Gas costs for Lua contract primitives.
// Charged in addition to the per-opcode VM gas (1 gas per opcode).
// Modelled loosely after EVM gas schedule but simplified for TOS.
const (
	gasSLoad       uint64 = 100     // per StateDB slot read
	gasSStore      uint64 = 5000    // per StateDB slot write
	gasBalance     uint64 = 400     // balance query
	gasCodeSize    uint64 = 700     // external code size check
	gasTransfer    uint64 = 2300    // value transfer base
	gasLogBase     uint64 = 375     // log emission base
	gasLogTopic    uint64 = 375     // per indexed topic (topics[1..3])
	gasLogByte     uint64 = 8       // per byte of log data
	gasDeploy      uint64 = 3200000 // CREATE base for legacy create/create2 deployment
	gasDeployByte  uint64 = 200     // per byte of deployed code
	gasCompileBase uint64 = 5000    // tos.compileBytecode base (parse + IR + encode)
	gasCompileByte uint64 = 50      // per byte of Lua source compiled
)

// maxCallDepth caps tos.call nesting to prevent stack-overflow DoS.
// Analogous to EVM call depth limit (1024); we use a smaller value since
// Lua call frames are heavier than EVM frames.
const maxCallDepth = 8

// lvmResultSentinelType is the unexported type used as the LUserData value
// for the clean-return signal raised by tos.result().  Its address is unique
// per binary; Lua contract code cannot construct a matching LUserData without
// access to this unexported pointer, preventing string-based spoofing.
type lvmResultSentinelType struct{}

// lvmResultSentinel is the package-level singleton used as the userdata value.
var lvmResultSentinel = new(lvmResultSentinelType)

// lvmRevertSentinelType is the unexported type used as the LUserData value
// for structured revert data raised by tos.revert("ErrorName", ...).
type lvmRevertSentinelType struct{}

// lvmRevertSentinel is the package-level singleton used as the revert userdata value.
var lvmRevertSentinel = new(lvmRevertSentinelType)

// isResultSignal reports whether err is the typed result signal raised by tos.result().
func isResultSignal(err error) bool {
	var apiErr *lua.ApiError
	if !errors.As(err, &apiErr) {
		return false
	}
	ud, ok := apiErr.Object.(*lua.LUserData)
	return ok && ud != nil && ud.Value == lvmResultSentinel
}

// isRevertSignal reports whether err is the typed revert signal raised by tos.revert().
func isRevertSignal(err error) bool {
	var apiErr *lua.ApiError
	if !errors.As(err, &apiErr) {
		return false
	}
	ud, ok := apiErr.Object.(*lua.LUserData)
	return ok && ud != nil && ud.Value == lvmRevertSentinel
}

// CallCtx is the per-invocation execution context for a Lua contract call.
// Top-level calls initialise it from StateTransition.msg; nested tos.call
// invocations override from/to/value/data while keeping txOrigin/txPrice
// constant (they belong to the transaction, not to each call frame).
type CallCtx struct {
	From     common.Address // msg.sender visible to this call
	To       common.Address // contract address being executed
	Value    *big.Int       // msg.value for this call (nil treated as zero)
	Data     []byte         // msg.data (calldata) for this call
	IsCreate bool           // true when executing init_code at deploy time
	Depth    int            // nesting depth (0 = top-level tx call)
	TxOrigin common.Address // tx.origin: the original EOA, constant across all levels
	TxPrice  *big.Int       // tx.gasprice: constant across all levels
	Readonly bool           // if true, all state-mutating primitives raise an error
	// (EVM STATICCALL semantics; propagates to nested calls)

	// UnoValue is the encrypted deposit (64-byte ciphertext as hex) attached
	// to a confidential contract call.  When non-empty, TOL exposes it as
	// msg.value (uno type).  Nil/empty for non-confidential calls.
	UnoValue string

	// GoCtx is the optional Go context from the originating RPC call.
	// When non-nil and the context is cancelled/timed-out, the Lua VM aborts
	// execution on the next instruction.  Nil for block-processing paths.
	// Propagated unchanged into all nested Execute calls.
	GoCtx context.Context
}

// ErrGasLimitExceeded is returned by Call/Create when the LVM runs out of gas.
var ErrGasLimitExceeded = errors.New("lvm: gas limit exceeded")

// callCreateDepth is the maximum nesting depth for Create calls, matching EVM semantics.
const callCreateDepth = 1024

// LVM is the Lua Virtual Machine for executing GTOS smart contracts.
type LVM struct {
	Context BlockContext
	TxContext
	StateDB     StateDB
	chainConfig *params.ChainConfig
	depth       int             // current call/create nesting depth
	goCtx       context.Context // RPC timeout context; nil for block-processing
}

// NewLVM creates a new LVM instance bound to the given block context, tx context, state, and chain config.
func NewLVM(blockCtx BlockContext, txCtx TxContext, stateDB StateDB, chainConfig *params.ChainConfig) *LVM {
	return &LVM{Context: blockCtx, TxContext: txCtx, StateDB: stateDB, chainConfig: chainConfig}
}

// SetGoCtx stores the caller's Go context so that LVM.Call and LVM.Create
// propagate it into Execute, enabling RPC timeout interrupts.
// This enables RPC timeout interrupts during contract execution.
func (l *LVM) SetGoCtx(goCtx context.Context) { l.goCtx = goCtx }

// ChainConfig returns the chain configuration.
func (l *LVM) ChainConfig() *params.ChainConfig { return l.chainConfig }

// Call executes the LVM contract code at addr with the given calldata and gas budget.
// Returns (returnData, leftOverGas, err). On failure the state is reverted.
func (l *LVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	if l.depth > callCreateDepth {
		return nil, gas, ErrDepth
	}
	l.depth++
	defer func() { l.depth-- }()

	callerAddr := caller.Address()
	snapshot := l.StateDB.Snapshot()

	currentBlock := uint64(0)
	if l.Context.BlockNumber != nil {
		currentBlock = l.Context.BlockNumber.Uint64()
	}
	if err := lease.CheckCallable(l.StateDB, addr, currentBlock, l.chainConfig); err != nil {
		return nil, gas, err
	}

	if !l.StateDB.Exist(addr) {
		l.StateDB.CreateAccount(addr)
	}

	if value != nil && value.Sign() > 0 {
		if !l.Context.CanTransfer(l.StateDB, callerAddr, value) {
			return nil, gas, fmt.Errorf("lvm: insufficient balance at %v", callerAddr.Hex())
		}
		l.Context.Transfer(l.StateDB, callerAddr, addr, value)
	}

	ctx := CallCtx{
		From: callerAddr, To: addr, Value: value, Data: input,
		Depth: l.depth, TxOrigin: l.Origin, TxPrice: l.GasPrice,
		GoCtx: l.goCtx,
	}
	code := l.StateDB.GetCode(addr)
	gasUsed, returnData, _, execErr := Execute(l.StateDB, l.Context, l.chainConfig, ctx, code, gas)
	if execErr != nil {
		l.StateDB.RevertToSnapshot(snapshot)
		if !errors.Is(execErr, ErrExecutionReverted) {
			return nil, 0, execErr
		}
		consumed := gasUsed
		if consumed > gas {
			consumed = gas
		}
		return nil, gas - consumed, execErr
	}
	if gasUsed > gas {
		l.StateDB.RevertToSnapshot(snapshot)
		return nil, 0, ErrGasLimitExceeded
	}
	return returnData, gas - gasUsed, nil
}

// SplitDeployDataAndConstructorArgs splits deployment calldata into the .tor
// package bytes and the ABI-encoded constructor arguments that follow.
//
// Layout: [tor_zip_bytes][ctor_args_abi]
//
// The split point is determined by strict ZIP EOCD validation:
//  1. Search backward for EOCD signature within the ZIP spec window.
//  2. Validate EOCD fields (central directory bounds, comment length).
//  3. Confirm the candidate prefix passes DecodePackage.
//
// Returns an error if no valid .tor package is found at the start of data.
// ctorArgs is nil when no bytes follow the ZIP end.
func SplitDeployDataAndConstructorArgs(data []byte) (pkgBytes []byte, ctorArgs []byte, err error) {
	const (
		eocdSig    = uint32(0x06054b50) // PK\x05\x06 in little-endian
		eocdMinLen = 22
		maxComment = 65535
	)
	n := len(data)
	if n < eocdMinLen {
		return nil, nil, fmt.Errorf("lvm: deploy data too short to contain a valid .tor package")
	}
	searchFrom := n - eocdMinLen
	searchTo := n - eocdMinLen - maxComment
	if searchTo < 0 {
		searchTo = 0
	}
	for i := searchFrom; i >= searchTo; i-- {
		if binary.LittleEndian.Uint32(data[i:]) != eocdSig {
			continue
		}
		if i+eocdMinLen > n {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(data[i+20:]))
		eocdEnd := i + eocdMinLen + commentLen
		if eocdEnd > n {
			continue
		}
		// Validate central directory lies before EOCD.
		cdSize := int(binary.LittleEndian.Uint32(data[i+12:]))
		cdOffset := int(binary.LittleEndian.Uint32(data[i+16:]))
		if cdOffset < 0 || cdSize < 0 || cdOffset+cdSize > i {
			continue
		}
		candidate := data[:eocdEnd]
		if _, decErr := lua.DecodePackage(candidate); decErr != nil {
			continue
		}
		rest := data[eocdEnd:]
		if len(rest) == 0 {
			rest = nil
		}
		return candidate, rest, nil
	}
	return nil, nil, fmt.Errorf("lvm: deploy data does not contain a valid .tor package (no valid ZIP EOCD found)")
}

// Create deploys a .tor package archive to a new contract address.
//
// If the deploy package manifest contains both `main_contract` and `init_code`
// fields, the init_code artifact is executed once with IsCreate=true and
// constructorArgs (Ethereum-style constructor). On failure, the snapshot is
// fully reverted.
//
// The full original deploy package (including init_code and signature fields)
// is stored on-chain via SetCode, allowing auditors to reconstruct and verify
// the original publisher signature at any time.
//
// Only .tor packages are accepted; raw .toc bytecode deployment is rejected.
// nonce must be the pre-tx sender nonce (msg.Nonce()).
func (l *LVM) Create(caller ContractRef, pkgBytes []byte, constructorArgs []byte, gas uint64, value *big.Int, nonce uint64) (contractAddr common.Address, leftOverGas uint64, err error) {
	return l.createPackage(caller, pkgBytes, constructorArgs, gas, value, nonce, gasDeployByte)
}

// CreateLease deploys a .tor package archive using the lease-specific code-install gas schedule.
func (l *LVM) CreateLease(caller ContractRef, pkgBytes []byte, constructorArgs []byte, gas uint64, value *big.Int, nonce uint64) (contractAddr common.Address, leftOverGas uint64, err error) {
	return l.createPackage(caller, pkgBytes, constructorArgs, gas, value, nonce, params.LeaseDeployByteGas)
}

func (l *LVM) createPackage(caller ContractRef, pkgBytes []byte, constructorArgs []byte, gas uint64, value *big.Int, nonce uint64, codeGasPerByte uint64) (contractAddr common.Address, leftOverGas uint64, err error) {
	if l.depth > callCreateDepth {
		return common.Address{}, gas, ErrDepth
	}

	callerAddr := caller.Address()

	if nonce+1 < nonce {
		return common.Address{}, gas, ErrNonceUintOverflow
	}

	contractAddr = crypto.CreateAddress(callerAddr, nonce)

	if !lua.IsPackage(pkgBytes) {
		return common.Address{}, 0, fmt.Errorf("lvm: only .tor package archives may be deployed; raw .toc bytecode is not accepted")
	}
	if uint64(len(pkgBytes)) > params.MaxCodeSize {
		return common.Address{}, gas, fmt.Errorf("lvm: .tor package size %d exceeds limit %d", len(pkgBytes), params.MaxCodeSize)
	}

	codeHash := l.StateDB.GetCodeHash(contractAddr)
	emptyCodeHash := crypto.Keccak256Hash(nil)
	if lease.HasTombstone(l.StateDB, contractAddr) ||
		l.StateDB.GetNonce(contractAddr) != 0 ||
		(codeHash != (common.Hash{}) && codeHash != emptyCodeHash) {
		return common.Address{}, gas, ErrContractAddressCollision
	}

	// Decode and validate manifest.
	pkg, decErr := lua.DecodePackage(pkgBytes)
	if decErr != nil {
		return common.Address{}, gas, fmt.Errorf("lvm: invalid .tor package: %w", decErr)
	}
	var deployManifest struct {
		MainContract string `json:"main_contract"`
		InitCode     string `json:"init_code"`
		Contracts    []struct {
			Name     string `json:"name"`
			Artifact string `json:"toc"`
		} `json:"contracts"`
	}
	if err := json.Unmarshal(pkg.ManifestJSON, &deployManifest); err != nil {
		return common.Address{}, gas, fmt.Errorf("lvm: .tor manifest decode: %w", err)
	}

	// Validate dispatch tag uniqueness.
	seenTags := make(map[[4]byte]string, len(deployManifest.Contracts))
	for _, c := range deployManifest.Contracts {
		var tag [4]byte
		copy(tag[:], crypto.Keccak256([]byte("pkg:" + c.Name))[:4])
		if prev, conflict := seenTags[tag]; conflict {
			return common.Address{}, gas, fmt.Errorf("lvm: dispatch tag collision between %q and %q in package", prev, c.Name)
		}
		seenTags[tag] = c.Name
	}

	// Determine whether this package uses the init/runtime split.
	hasInitRuntime := deployManifest.MainContract != "" && deployManifest.InitCode != ""

	var initArtifactBytecode []byte

	if hasInitRuntime {
		// Validate main_contract exists in contracts.
		mainFound := false
		for _, c := range deployManifest.Contracts {
			if c.Name == deployManifest.MainContract {
				mainFound = true
				if c.Artifact == "" {
					return common.Address{}, gas, fmt.Errorf("lvm: main_contract %q has no toc entry in manifest", deployManifest.MainContract)
				}
				break
			}
		}
		if !mainFound {
			return common.Address{}, gas, fmt.Errorf("lvm: main_contract %q not found in contracts", deployManifest.MainContract)
		}
		// Validate init_code exists and is not listed in contracts.
		for _, c := range deployManifest.Contracts {
			if c.Artifact == deployManifest.InitCode {
				return common.Address{}, gas, fmt.Errorf("lvm: init_code %q must not be listed in contracts", deployManifest.InitCode)
			}
		}
		initArtifactBytes, ok := pkg.Files[deployManifest.InitCode]
		if !ok {
			return common.Address{}, gas, fmt.Errorf("lvm: init_code file %q not found in package", deployManifest.InitCode)
		}
		initArt, err := lua.DecodeArtifact(initArtifactBytes)
		if err != nil {
			return common.Address{}, gas, fmt.Errorf("lvm: init_code decode: %w", err)
		}
		initArtifactBytecode = initArt.Bytecode
	}

	// Charge code storage gas based on full deploy package size.
	codeGas := uint64(len(pkgBytes)) * codeGasPerByte
	if gas < codeGas {
		return common.Address{}, 0, ErrGasLimitExceeded
	}
	gas -= codeGas

	if value != nil && value.Sign() > 0 {
		if !l.Context.CanTransfer(l.StateDB, callerAddr, value) {
			return common.Address{}, gas, fmt.Errorf("lvm: insufficient balance at %v", callerAddr.Hex())
		}
	}

	l.depth++
	defer func() { l.depth-- }()

	snapshot := l.StateDB.Snapshot()
	if value != nil && value.Sign() > 0 {
		l.Context.Transfer(l.StateDB, callerAddr, contractAddr, value)
	}

	l.StateDB.CreateAccount(contractAddr)
	l.StateDB.SetNonce(contractAddr, 1)
	l.StateDB.SetCode(contractAddr, pkgBytes)
	l.StateDB.SetNonce(callerAddr, nonce+1)

	if hasInitRuntime {
		// Execute constructor (init_code) at deploy time — mirrors EVM initcode.
		ctorCtx := CallCtx{
			From:     callerAddr,
			To:       contractAddr,
			Value:    value,
			Data:     constructorArgs,
			IsCreate: true,
			TxOrigin: l.Origin,
			TxPrice:  l.GasPrice,
			GoCtx:    l.goCtx,
		}
		ctorGasUsed, _, _, ctorErr := Execute(l.StateDB, l.Context, l.chainConfig, ctorCtx, initArtifactBytecode, gas)
		if ctorErr != nil {
			l.StateDB.RevertToSnapshot(snapshot)
			// LVM-3 fix: same as LVM.Call — no strings.Contains for OOG classification.
			consumed := ctorGasUsed
			if consumed > gas {
				consumed = gas
			}
			return contractAddr, gas - consumed, ctorErr
		}
		if ctorGasUsed > gas {
			l.StateDB.RevertToSnapshot(snapshot)
			return contractAddr, 0, ErrGasLimitExceeded
		}
		gas -= ctorGasUsed
	}

	return contractAddr, gas, nil
}

// executePackage routes a call to a named contract within a .tor package.
//
// Calldata layout (agreed between tolang lowering and gtos):
//
//	[0:4]  = keccak256("pkg:" + contractName)[:4]   — package dispatch tag
//	[4:]   = selector + abi.encode(args...)          — passed to the contract as-is
//
// executePackage decodes the .tor archive, finds the contract whose dispatch tag
// matches the first 4 calldata bytes, loads its .toc bytecode, strips the dispatch
// tag, and calls Execute recursively.
func executePackage(stateDB StateDB, blockCtx BlockContext, chainConfig *params.ChainConfig, ctx CallCtx, pkgBytes []byte, gasLimit uint64) (uint64, []byte, []byte, error) {
	if len(ctx.Data) < 4 {
		return 0, nil, nil, fmt.Errorf("package call: calldata must be at least 4 bytes (dispatch tag + selector)")
	}
	dispatchTag := ctx.Data[:4]

	pkg, err := lua.DecodePackage(pkgBytes)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("package call: decode .tor: %w", err)
	}

	var manifest struct {
		Contracts []struct {
			Name     string `json:"name"`
			Artifact string `json:"toc"`
		} `json:"contracts"`
	}
	if err := json.Unmarshal(pkg.ManifestJSON, &manifest); err != nil {
		return 0, nil, nil, fmt.Errorf("package call: manifest decode: %w", err)
	}

	for _, c := range manifest.Contracts {
		if c.Artifact == "" {
			continue
		}
		tag := crypto.Keccak256([]byte("pkg:" + c.Name))[:4]
		if !bytes.Equal(tag, dispatchTag) {
			continue
		}
		artifactBytes, ok := pkg.Files[c.Artifact]
		if !ok {
			return 0, nil, nil, fmt.Errorf("package call: .toc file %q not found for contract %q", c.Artifact, c.Name)
		}
		art, err := lua.DecodeArtifact(artifactBytes)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("package call: decode .toc for %q: %w", c.Name, err)
		}
		// Strip the 4-byte dispatch tag; the contract receives selector+args only.
		childCtx := ctx
		childCtx.Data = ctx.Data[4:]
		return Execute(stateDB, blockCtx, chainConfig, childCtx, art.Bytecode, gasLimit)
	}

	return 0, nil, nil, fmt.Errorf("package call: no contract found for dispatch tag %x", dispatchTag)
}

// parseBigInt extracts a non-negative *big.Int from Lua argument n.
// Accepts LUint256 or LString. Raises a Lua error on bad input.
func parseBigInt(L *lua.LState, n int) *big.Int {
	var s string
	switch v := L.CheckAny(n).(type) {
	case lua.LUint256:
		s = v.String()
	case lua.LString:
		s = string(v)
	default:
		L.ArgError(n, "expected number or numeric string")
		return nil
	}
	bi, ok := new(big.Int).SetString(s, 10)
	if !ok {
		L.ArgError(n, "invalid integer")
		return nil
	}
	return bi
}

// parseUint256Value parses an LValue as a non-negative uint256 integer.
// Accepts LUint256 or numeric LString.
func parseUint256Value(v lua.LValue) (*big.Int, error) {
	var s string
	switch x := v.(type) {
	case lua.LUint256:
		s = x.String()
	case lua.LString:
		s = string(x)
	default:
		return nil, fmt.Errorf("value must be a number or numeric string")
	}
	bi, ok := new(big.Int).SetString(s, 10)
	if !ok || bi.Sign() < 0 {
		return nil, fmt.Errorf("invalid uint256 value")
	}
	return bi, nil
}

// StorageSlot maps a Lua contract storage key to a deterministic EVM storage
// slot, namespaced under "gtos.lua.storage." to avoid collision with setCode
// metadata slots (gtos.setCode.*).
func StorageSlot(key string) common.Hash {
	return crypto.Keccak256Hash(append([]byte("gtos.lua.storage."), key...))
}

// StrLenSlot returns the slot that holds the byte-length of a string value.
// It is distinct from the uint256 storage namespace ("gtos.lua.storage.").
func StrLenSlot(key string) common.Hash {
	return crypto.Keccak256Hash(append([]byte("gtos.lua.str."), key...))
}

// StrChunkSlot returns the slot for chunk i (0-based) of a stored string.
// The slot is derived from the base (length) slot and the 4-byte chunk index,
// making it independent of any character in key (no delimiter injection risk).
func StrChunkSlot(base common.Hash, i int) common.Hash {
	var b [36]byte
	copy(b[:32], base[:])
	binary.BigEndian.PutUint32(b[32:], uint32(i))
	return crypto.Keccak256Hash(b[:])
}

// ArrLenSlot returns the slot holding the length of a dynamic uint256 array.
// Namespace "gtos.lua.arr." is distinct from the uint256 ("gtos.lua.storage.")
// and string ("gtos.lua.str.") namespaces.
func ArrLenSlot(key string) common.Hash {
	return crypto.Keccak256Hash(append([]byte("gtos.lua.arr."), key...))
}

// ArrElemSlot returns the slot for element i (0-based) of a dynamic array.
// Derived from the length-slot hash and an 8-byte big-endian index, so there
// is no delimiter-injection risk and the mapping is collision-free.
func ArrElemSlot(base common.Hash, i uint64) common.Hash {
	var b [40]byte
	copy(b[:32], base[:])
	binary.BigEndian.PutUint64(b[32:], i)
	return crypto.Keccak256Hash(b[:])
}

// MapSlot derives the storage slot for a uint256 value in a named mapping
// at the given key path (one or more keys for nested mappings).
//
// Slot derivation (injection-safe, Solidity-inspired):
//
//	base = keccak256("gtos.lua.map." || mapName)
//	slot = keccak256(keccak256(key_1) || base)              // 1 key
//	slot = keccak256(keccak256(key_2) || prev_slot)         // 2nd key applied on top
//	...
//
// Each key is keccak256-hashed before mixing, so no delimiter-injection is
// possible regardless of what characters the key contains.
// Namespace "gtos.lua.map." never collides with other namespaces.
func MapSlot(mapName string, keys []string) common.Hash {
	h := crypto.Keccak256Hash(append([]byte("gtos.lua.map."), mapName...))
	for _, key := range keys {
		keyHash := crypto.Keccak256([]byte(key))
		h = crypto.Keccak256Hash(append(keyHash, h[:]...))
	}
	return h
}

// MapStrLenSlot derives the length-slot for a string stored in a named
// mapping at the given key path.  Uses "gtos.lua.mapstr." namespace so it
// never collides with MapSlot (uint256) or StrLenSlot (direct strings).
func MapStrLenSlot(mapName string, keys []string) common.Hash {
	h := crypto.Keccak256Hash(append([]byte("gtos.lua.mapstr."), mapName...))
	for _, key := range keys {
		keyHash := crypto.Keccak256([]byte(key))
		h = crypto.Keccak256Hash(append(keyHash, h[:]...))
	}
	return h
}

// Execute runs Lua contract code `src` (either source or glua bytecode)
// in a fresh Lua state under the given call context, limited to `gasLimit` VM
// opcodes.
//
// Returns (total opcodes consumed including nested calls, return data, error).
// returnData is non-nil only when the callee called tos.result(); in that
// case err is nil (a clean return is not an error).
//
// Callers are responsible for StateDB snapshot/revert; this function does not
// modify snapshot state itself (tos.call takes its own inner snapshot for
// callee isolation).
func Execute(stateDB StateDB, blockCtx BlockContext, chainConfig *params.ChainConfig, ctx CallCtx, src []byte, gasLimit uint64) (uint64, []byte, []byte, error) {
	// .tor (ZIP package): route to the named contract via calldata dispatch tag.
	if lua.IsPackage(src) {
		return executePackage(stateDB, blockCtx, chainConfig, ctx, src, gasLimit)
	}
	// .toc (compiled TOL artifact): extract embedded Lua bytecode and execute it.
	if lua.IsArtifact(src) {
		art, err := lua.DecodeArtifact(src)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("lvm: decode .toc: %w", err)
		}
		src = art.Bytecode
	}

	contractAddr := ctx.To

	L := lua.NewState(lua.Options{SkipOpenLibs: false})
	defer L.Close()
	L.SetGasLimit(gasLimit)
	if ctx.GoCtx != nil {
		L.SetInterrupt(ctx.GoCtx.Done())
	}

	// totalChildGas accumulates opcodes consumed by all nested tos.call
	// invocations at this call level (not recursively — each level tracks its
	// own children separately).
	var totalChildGas uint64

	// primGasCharged accumulates gas charged by individual primitive calls
	// (tos.sstore, tos.sload, tos.emit, etc.) on top of per-opcode VM gas.
	var primGasCharged uint64

	// chargePrimGas deducts cost gas units for a single primitive invocation.
	// It adjusts the VM's opcode ceiling so that the combined budget
	// (VM opcodes + primitives + child calls) stays within gasLimit.
	// Raises "lua: gas limit exceeded" if insufficient budget remains.
	//
	// Invariant maintained: L.GasLimit() == gasLimit - totalChildGas - primGasCharged
	chargePrimGas := func(cost uint64) {
		vmUsed := L.GasUsed()
		remaining := gasLimit - vmUsed - totalChildGas - primGasCharged
		if cost > remaining {
			L.RaiseError("lua: gas limit exceeded")
			return
		}
		primGasCharged += cost
		// Shrink the VM opcode ceiling to prevent future opcodes from spending
		// gas already claimed by this primitive charge.
		newCeiling := gasLimit - totalChildGas - primGasCharged
		if vmUsed <= newCeiling {
			L.SetGasLimit(newCeiling)
		} else {
			// VM opcodes already consumed all remaining budget; next opcode OOGs.
			L.SetGasLimit(vmUsed)
		}
	}

	// capturedResult holds ABI-encoded return data set by tos.result().
	// hasResult gates the isResultSignal check — user code cannot set this
	// without calling the Go-level tos.result closure.
	var capturedResult []byte
	var hasResult bool

	// capturedRevertData holds structured ABI-encoded error data set by
	// tos.revert("ErrorName", "type", val, ...).  hasRevertData gates the
	// isRevertSignal check to prevent accidental matches.
	var capturedRevertData []byte
	var hasRevertData bool

	// ── "tos" module ──────────────────────────────────────────────────────────
	tosTable := L.NewTable()

	// tos.sload(key) → LUint256 | LNil
	//   Reads a uint256 value from contract storage.
	//   Returns nil if the slot has never been written (unset).
	//   TOL-compiled contracts access this via the __tol_sload wrapper, which
	//   converts nil → 0.  Stdlib and legacy raw-Lua code can use "or default"
	//   patterns directly (nil is falsy in Lua).
	L.SetField(tosTable, "sload", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		chargePrimGas(gasSLoad)
		val := stateDB.GetState(contractAddr, StorageSlot(key))
		if val == (common.Hash{}) {
			L.Push(lua.LNil)
			return 1
		}
		n := new(big.Int).SetBytes(val[:])
		L.Push(luBig(n))
		return 1
	}))

	// tos.sstore(key, value)
	//   TOL-generated __tol_sstore hook. Stores a uint256, bool, or agent hex
	//   string value into contract persistent storage.
	L.SetField(tosTable, "sstore", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.sstore: state modification not allowed in staticcall")
			return 0
		}
		chargePrimGas(gasSStore)
		key := L.CheckString(1)
		lv := L.CheckAny(2)
		var slot common.Hash
		switch v := lv.(type) {
		case lua.LUint256:
			n, ok := new(big.Int).SetString(v.String(), 10)
			if !ok || n.Sign() < 0 {
				L.RaiseError("tos.sstore: invalid uint256 value")
				return 0
			}
			n.FillBytes(slot[:])
		case lua.LBool:
			if bool(v) {
				slot[31] = 1
			}
		case lua.LString:
			s := strings.TrimSpace(string(v))
			if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
				// Agent / bytes32 hex address: right-align decoded bytes in 32-byte slot.
				b := common.FromHex(s)
				copy(slot[common.HashLength-len(b):], b)
			} else {
				// Decimal string: parse as u256.
				n, ok := new(big.Int).SetString(s, 10)
				if !ok || n.Sign() < 0 {
					L.RaiseError("tos.sstore: invalid decimal value %q", s)
					return 0
				}
				n.FillBytes(slot[:])
			}
		case *lua.LNilType:
			// Explicit nil / zero: leave slot as zero hash (clear).
		default:
			L.RaiseError("tos.sstore: unsupported value type %T", lv)
			return 0
		}
		stateDB.SetState(contractAddr, StorageSlot(key), slot)
		return 0
	}))

	// tos.transfer(toAddr, amount)
	//   Sends `amount` wei from the contract's balance to `toAddr`.
	L.SetField(tosTable, "transfer", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.transfer: value transfer not allowed in staticcall")
			return 0
		}
		chargePrimGas(gasTransfer)
		addrHex := L.CheckString(1)
		amountNum := L.CheckUint256(2)
		to := common.HexToAddress(addrHex)
		amount, ok := new(big.Int).SetString(amountNum.String(), 10)
		if !ok || amount.Sign() < 0 {
			L.RaiseError("tos.transfer: invalid amount")
		}
		if err := lease.RejectTombstoned(stateDB, to); err != nil {
			L.RaiseError("tos.transfer: %v", err)
			return 0
		}
		if !blockCtx.CanTransfer(stateDB, contractAddr, amount) {
			L.RaiseError("tos.transfer: insufficient contract balance")
		}
		blockCtx.Transfer(stateDB, contractAddr, to, amount)
		return 0
	}))

	// tos.send(toAddr, amount) → bool
	//   Soft-failure variant of tos.transfer.
	//   Returns true on success, false on any failure (insufficient balance,
	//   invalid amount, or readonly context).  Never reverts.
	//   Equivalent to Solidity's payable(addr).send(amount).
	//
	//   Example:
	//     if not tos.send(recipient, amount) then
	//         tos.revert("send failed")
	//     end
	L.SetField(tosTable, "send", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.Push(lua.LFalse)
			return 1
		}
		addrHex := L.CheckString(1)
		amountNum := L.CheckUint256(2)
		to := common.HexToAddress(addrHex)
		amount, ok := new(big.Int).SetString(amountNum.String(), 10)
		if !ok || amount.Sign() < 0 {
			L.Push(lua.LFalse)
			return 1
		}
		chargePrimGas(gasTransfer)
		if err := lease.RejectTombstoned(stateDB, to); err != nil {
			L.Push(lua.LFalse)
			return 1
		}
		if !blockCtx.CanTransfer(stateDB, contractAddr, amount) {
			L.Push(lua.LFalse)
			return 1
		}
		blockCtx.Transfer(stateDB, contractAddr, to, amount)
		L.Push(lua.LTrue)
		return 1
	}))

	// tos.balance(addr) → LNumber  (wei as uint256 string)
	L.SetField(tosTable, "balance", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasBalance)
		addrHex := L.CheckString(1)
		addr := common.HexToAddress(addrHex)
		bal := stateDB.GetBalance(addr)
		if bal == nil {
			L.Push(lua.LUint256Zero)
		} else {
			L.Push(luBig(bal))
		}
		return 1
	}))

	// ── Context properties ────────────────────────────────────────────────────
	//
	// All static for this call frame — pre-populated as Lua values, not
	// Go functions, so scripts read them as properties (no parentheses).

	// tos.caller  → string  (hex address of immediate msg.sender)
	L.SetField(tosTable, "caller", lua.LString(ctx.From.Hex()))

	// tos.value  → LNumber  (msg.value in wei)
	{
		v := ctx.Value
		if v == nil || v.Sign() == 0 {
			L.SetField(tosTable, "value", lua.LUint256Zero)
		} else {
			L.SetField(tosTable, "value", luBig(v))
		}
	}

	// tos.uno_value  → string  (encrypted deposit ciphertext as 128-char hex)
	//   TOL desugars msg.value in uno context to tos.uno_value.
	//   Returns encrypted zero when no deposit is attached (type closure:
	//   msg.value.add(x) always works without nil checks).
	if ctx.UnoValue != "" {
		L.SetField(tosTable, "uno_value", lua.LString(ctx.UnoValue))
	} else {
		L.SetField(tosTable, "uno_value", lua.LString(zeroCiphertextHex))
	}

	// tos.block  (sub-table — static block context values)
	blockTable := L.NewTable()
	L.SetField(blockTable, "number", luBig(blockCtx.BlockNumber))
	L.SetField(blockTable, "timestamp", luBig(blockCtx.Time))
	L.SetField(blockTable, "coinbase", lua.LString(blockCtx.Coinbase.Hex()))
	L.SetField(blockTable, "chainid", luBig(chainConfig.ChainID))
	L.SetField(blockTable, "gaslimit", lua.Lu256FromUint64(blockCtx.GasLimit))
	L.SetField(blockTable, "timestamp_ms", lua.Lu256FromUint64(blockCtx.Time.Uint64()*1000))
	if blockCtx.BaseFee != nil {
		L.SetField(blockTable, "basefee", luBig(blockCtx.BaseFee))
	} else {
		L.SetField(blockTable, "basefee", lua.LUint256Zero)
	}
	L.SetField(tosTable, "block", blockTable)

	// tos.tx  (sub-table — tx.origin is the original EOA, constant across frames)
	txTable := L.NewTable()
	L.SetField(txTable, "origin", lua.LString(ctx.TxOrigin.Hex()))
	if ctx.TxPrice != nil {
		L.SetField(txTable, "gasprice", luBig(ctx.TxPrice))
	} else {
		L.SetField(txTable, "gasprice", lua.LUint256Zero)
	}
	L.SetField(tosTable, "tx", txTable)

	// tos.msg  (sub-table — Solidity-compatible aliases)
	//   msg.sender == tos.caller     (immediate caller for this frame)
	//   msg.value  == tos.value      (value forwarded to this frame, public TOS)
	//   msg.uno_value → encrypted deposit ciphertext (hex) | nil
	//   msg.data   → calldata hex    (this call's calldata)
	//   msg.sig    → first 4 bytes   (function selector)
	//
	//   A transaction carries EITHER public value OR encrypted value, never both.
	//   TOL payable functions read msg.value; TOL payable(uno) functions read
	//   msg.uno_value.  The compiler enforces mutual exclusivity at the type level.
	msgTable := L.NewTable()
	L.SetField(msgTable, "sender", lua.LString(ctx.From.Hex()))
	{
		v := ctx.Value
		if v == nil || v.Sign() == 0 {
			L.SetField(msgTable, "value", lua.LUint256Zero)
		} else {
			L.SetField(msgTable, "value", luBig(v))
		}
	}
	// msg.uno_value: encrypted deposit attached to a confidential contract call.
	// Returns encrypted zero when no deposit (type closure, not nil).
	if ctx.UnoValue != "" {
		L.SetField(msgTable, "uno_value", lua.LString(ctx.UnoValue))
	} else {
		L.SetField(msgTable, "uno_value", lua.LString(zeroCiphertextHex))
	}
	// Extract proof bundle from calldata (if present).  The bundle is
	// appended after a "PBND" magic marker; strippedData is the original
	// ABI calldata without the bundle suffix.
	proofBundle, strippedData := ExtractProofBundle(ctx.Data)

	{
		d := strippedData
		var msgDataHex string
		if len(d) == 0 {
			msgDataHex = "0x"
		} else {
			msgDataHex = "0x" + common.Bytes2Hex(d)
		}
		L.SetField(msgTable, "data", lua.LString(msgDataHex))
		if len(d) >= 4 {
			L.SetField(msgTable, "sig", lua.LString("0x"+common.Bytes2Hex(d[:4])))
		} else {
			L.SetField(msgTable, "sig", lua.LString("0x"))
		}
	}
	L.SetField(tosTable, "msg", msgTable)

	// tos.calldata — full calldata as "0x..." hex string.
	// Read by TOL-generated ABI decode guards in constructors and dispatch branches.
	{
		var calldataHex string
		if len(strippedData) == 0 {
			calldataHex = "0x"
		} else {
			calldataHex = "0x" + hex.EncodeToString(strippedData)
		}
		L.SetField(tosTable, "calldata", lua.LString(calldataHex))
	}

	// ── Built-in module loader ────────────────────────────────────────────────

	// tos.import("moduleName") → table
	//   Loads a whitelisted built-in TOS standard library module.
	//   Unlike the removed stdlib require(), only pre-audited modules are available.
	//
	//   Available modules:
	//     "tos20"  — TOS-20 fungible token standard (see core/lua_stdlib.go)
	//
	//   Example:
	//     local T = tos.import("tos20")
	//     T.init("MyToken", "MTK", 18, 1000000)
	//     tos.dispatch(T.handlers)
	L.SetField(tosTable, "import", L.NewFunction(func(L *lua.LState) int {
		modName := L.CheckString(1)
		bc, ok := builtinModules[modName]
		if !ok {
			L.RaiseError("tos.import: unknown module %q (available: tos20)", modName)
			return 0
		}
		top := L.GetTop()
		fn, err := L.LoadBytecode(bc)
		if err != nil {
			L.RaiseError("tos.import: module %q load error: %v", modName, err)
			return 0
		}
		L.Push(fn)
		if err := L.PCall(0, lua.MultRet, nil); err != nil {
			L.RaiseError("tos.import: module %q: %v", modName, err)
			return 0
		}
		return L.GetTop() - top
	}))

	// tos.abi  (sub-table — Ethereum ABI encode/decode)
	abiTable := L.NewTable()
	L.SetField(abiTable, "encode", L.NewFunction(abiEncode))
	L.SetField(abiTable, "encodePacked", L.NewFunction(abiEncodePacked))
	L.SetField(abiTable, "decode", L.NewFunction(abiDecode))

	// tos.abi.decodeError(revertData, "type1", "type2", ...) → val1, val2, ...
	//   Convenience wrapper around tos.abi.decode that strips the leading 4-byte
	//   ABI error selector before decoding.  Use on the 2nd return value of
	//   tos.call when the callee used tos.revert("ErrorName", ...).
	//
	//   local ok, ret = tos.call(addr, 0, calldata)
	//   if not ok and ret then
	//       local avail, req = tos.abi.decodeError(ret, "uint256", "uint256")
	//   end
	L.SetField(abiTable, "decodeError", L.NewFunction(func(L *lua.LState) int {
		hexStr := L.CheckString(1)
		raw := strings.TrimPrefix(strings.TrimPrefix(hexStr, "0x"), "0X")
		if len(raw) < 8 {
			L.RaiseError("tos.abi.decodeError: data too short for 4-byte selector (got %d hex chars)", len(raw))
			return 0
		}
		// Replace arg 1 with the body (selector stripped); keep type args unchanged.
		L.Remove(1)
		L.Insert(lua.LString("0x"+raw[8:]), 1)
		return abiDecode(L)
	}))

	L.SetField(tosTable, "abi", abiTable)

	// tos.gasleft() → LNumber
	//   Returns remaining gas at call time, accounting for child gas and
	//   primitive charges consumed so far.
	//   Must be a function because the value changes each opcode.
	L.SetField(tosTable, "gasleft", L.NewFunction(func(L *lua.LState) int {
		used := L.GasUsed() + totalChildGas + primGasCharged
		var remaining uint64
		if used < gasLimit {
			remaining = gasLimit - used
		}
		L.Push(lua.Lu256FromUint64(remaining))
		return 1
	}))

	// tos.require(condition, msg)
	L.SetField(tosTable, "require", L.NewFunction(func(L *lua.LState) int {
		cond := L.CheckAny(1)
		message := L.OptString(2, "requirement failed")
		if cond == lua.LNil || cond == lua.LFalse {
			L.RaiseError("tos.require: %s", message)
		}
		return 0
	}))

	// tos.revert([msg])
	// tos.revert("ErrorName", "type1", val1, "type2", val2, ...)
	//
	// Plain form (1 arg or 0 args): raises a string error — same as before.
	//
	// Named-error form (3+ args with an even number of type+value pairs):
	//   Encodes as selector("ErrorName(type1,type2,...)") || abi.encode(val1, val2, ...)
	//   and makes this data available to the caller via the 2nd return of tos.call.
	//   Analogous to Solidity:
	//     error InsufficientBalance(uint256 available, uint256 required);
	//     revert InsufficientBalance(bal, needed);
	//
	//   Caller-side decoding:
	//     local ok, ret = tos.call(addr, 0, calldata)
	//     if not ok and ret then
	//         local avail, req = tos.abi.decodeError(ret, "uint256", "uint256")
	//     end
	L.SetField(tosTable, "revert", L.NewFunction(func(L *lua.LState) int {
		if L.GetTop() <= 1 {
			// Plain string revert (unchanged behaviour).
			message := L.OptString(1, "revert")
			L.RaiseError("tos.revert: %s", message)
			return 0
		}
		// Named error: arg1 = name, then alternating "type", value pairs.
		if (L.GetTop()-1)%2 != 0 {
			L.RaiseError("tos.revert: named error requires pairs of (type, value) after the name")
			return 0
		}
		errorName := L.CheckString(1)
		nPairs := (L.GetTop() - 1) / 2
		typeNames := make([]string, nPairs)
		for i := range typeNames {
			typeNames[i] = L.CheckString(2 + i*2)
		}
		sig := errorName + "(" + strings.Join(typeNames, ",") + ")"
		selector := crypto.Keccak256([]byte(sig))[:4]
		encoded, encErr := abiEncodeBytes(L, 2)
		if encErr != nil {
			L.RaiseError("tos.revert: ABI encode: %v", encErr)
			return 0
		}
		capturedRevertData = append(selector, encoded...)
		hasRevertData = true
		// Raise the typed revert sentinel (same approach as tos.result above).
		ud := L.NewUserData()
		ud.Value = lvmRevertSentinel
		L.Error(ud, 0)
		return 0
	}))

	// tos.keccak256(data) → string
	//
	// WARNING: data is treated as raw bytes, not as a hex string.
	// To hash ABI-encoded or hex data, convert first:
	//   local hash = tos.keccak256(tos.bytes.fromhex(tos.abi.encode("uint256", 42)))
	// To hash a hex-encoded input directly, use tos.keccak256hex(hexStr).
	L.SetField(tosTable, "keccak256", L.NewFunction(func(L *lua.LState) int {
		data := L.CheckString(1)
		chargePrimGas(1 + uint64(len(data))) // SEC-2: per-byte gas to prevent hash-DoS
		h := crypto.Keccak256Hash([]byte(data))
		L.Push(lua.LString(h.Hex()))
		return 1
	}))

	// tos.keccak256hex(hexStr) → string
	//
	// Convenience wrapper: decodes a "0x..."-prefixed hex string and returns the
	// keccak256 hash of the decoded bytes.  Equivalent to:
	//   tos.keccak256(tos.bytes.fromhex(hexStr))
	// but more concise.
	L.SetField(tosTable, "keccak256hex", L.NewFunction(func(L *lua.LState) int {
		hexStr := strings.TrimPrefix(L.CheckString(1), "0x")
		hexStr = strings.TrimPrefix(hexStr, "0X")
		if len(hexStr)%2 != 0 {
			L.RaiseError("tos.keccak256hex: odd-length hex string")
			return 0
		}
		b, err := hex.DecodeString(hexStr)
		if err != nil {
			L.RaiseError("tos.keccak256hex: invalid hex: %v", err)
			return 0
		}
		chargePrimGas(1 + uint64(len(b))) // SEC-2: per-byte gas
		h := crypto.Keccak256Hash(b)
		L.Push(lua.LString(h.Hex()))
		return 1
	}))

	// tos.sha256(data) → string
	L.SetField(tosTable, "sha256", L.NewFunction(func(L *lua.LState) int {
		data := L.CheckString(1)
		chargePrimGas(1 + uint64(len(data))) // SEC-2: per-byte gas to prevent hash-DoS
		h := gosha256.Sum256([]byte(data))
		L.Push(lua.LString("0x" + common.Bytes2Hex(h[:])))
		return 1
	}))

	// tos.ripemd160(data) → string  (20-byte "0x..." hex, zero-padded to 32 bytes like EVM)
	L.SetField(tosTable, "ripemd160", L.NewFunction(func(L *lua.LState) int {
		data := L.CheckString(1)
		chargePrimGas(1 + uint64(len(data))) // SEC-2: per-byte gas to prevent hash-DoS
		h := goripemd160.New()
		h.Write([]byte(data))
		result := h.Sum(nil) // 20 bytes
		// Left-pad to 32 bytes to match EVM precompile output convention.
		var padded [32]byte
		copy(padded[12:], result)
		L.Push(lua.LString("0x" + common.Bytes2Hex(padded[:])))
		return 1
	}))

	// tos.ecrecover(hash, v, r, s) → string | nil
	L.SetField(tosTable, "ecrecover", L.NewFunction(func(L *lua.LState) int {
		hashHex := L.CheckString(1)
		vNum := uint8(L.CheckInt(2))
		rHex := L.CheckString(3)
		sHex := L.CheckString(4)

		hashBytes := common.FromHex(hashHex)
		rBytes := common.FromHex(rHex)
		sBytes := common.FromHex(sHex)
		if len(hashBytes) != 32 || len(rBytes) != 32 || len(sBytes) != 32 {
			L.Push(lua.LNil)
			return 1
		}
		v := vNum
		if v >= 27 {
			v -= 27
		}
		if v != 0 && v != 1 {
			L.Push(lua.LNil)
			return 1
		}
		sig := make([]byte, 65)
		copy(sig[0:32], rBytes)
		copy(sig[32:64], sBytes)
		sig[64] = v

		pub, err := crypto.SigToPub(hashBytes, sig)
		if err != nil {
			L.Push(lua.LNil)
			return 1
		}
		addr := crypto.PubkeyToAddress(*pub)
		L.Push(lua.LString(addr.Hex()))
		return 1
	}))

	// ── Binary string utilities (tos.bytes.*) ────────────────────────────────
	//
	// These helpers bridge the gap between the two representations used in
	// TOS Lua contracts:
	//
	//   • "hex string"    — "0x1234abcd"  (returned by abi.encode, keccak256, etc.)
	//   • "binary string" — raw bytes     (accepted by keccak256, sha256, etc.)
	//
	// Example — hash ABI-encoded data:
	//
	//   local encoded = tos.abi.encode("uint256", 42)   -- "0x000...2a" hex
	//   local hash    = keccak256(tos.bytes.fromhex(encoded))  -- raw-binary input
	//
	// All functions operate on Lua strings.  No gas is charged (pure computation).
	bytesTable := L.NewTable()

	// tos.bytes.fromhex(hexStr) → binaryStr
	//   Decode a "0x..."-prefixed or bare hex string into a raw binary Lua string.
	//   Raises an error if the input is not valid hex.
	//
	//   Example:
	//     local bin = tos.bytes.fromhex("0xdeadbeef")  -- 4-byte binary string
	//     assert(#bin == 4)
	//     local hash = keccak256(tos.bytes.fromhex(tos.abi.encode("uint256", 42)))
	L.SetField(bytesTable, "fromhex", L.NewFunction(func(L *lua.LState) int {
		hexStr := strings.TrimPrefix(L.CheckString(1), "0x")
		hexStr = strings.TrimPrefix(hexStr, "0X")
		if len(hexStr)%2 != 0 {
			L.RaiseError("tos.bytes.fromhex: odd-length hex string")
			return 0
		}
		b, err := hex.DecodeString(hexStr)
		if err != nil {
			L.RaiseError("tos.bytes.fromhex: invalid hex: %v", err)
			return 0
		}
		chargePrimGas(1 + uint64(len(b))) // SEC-2: per-byte gas for decoded output
		L.Push(lua.LString(b))
		return 1
	}))

	// tos.bytes.tohex(binaryStr) → "0x..." hexStr
	//   Encode a raw binary Lua string into a lowercase "0x..."-prefixed hex string.
	//
	//   Example:
	//     local hex = tos.bytes.tohex("\xde\xad\xbe\xef")  -- "0xdeadbeef"
	L.SetField(bytesTable, "tohex", L.NewFunction(func(L *lua.LState) int {
		b := []byte(L.CheckString(1))
		chargePrimGas(1 + uint64(len(b))) // SEC-2: per-byte gas for encoding work
		L.Push(lua.LString("0x" + common.Bytes2Hex(b)))
		return 1
	}))

	// tos.bytes.len(binaryStr) → uint256
	//   Returns the byte length of the string.  Equivalent to the Lua # operator
	//   but explicit and safe for binary data.
	L.SetField(bytesTable, "len", L.NewFunction(func(L *lua.LState) int {
		s := L.CheckString(1)
		L.Push(lua.Lu256FromUint64(uint64(len(s))))
		return 1
	}))

	// tos.bytes.slice(binaryStr, offset [, length]) → binaryStr
	//   Extract a sub-string of bytes.  offset is 0-based (like Solidity / Python).
	//   If length is omitted, returns everything from offset to end.
	//   Raises an error if offset or offset+length is out of range.
	//
	//   Example — extract 4-byte function selector from binary calldata:
	//     local bin = tos.bytes.fromhex(msg.data)
	//     local sel = tos.bytes.slice(bin, 0, 4)   -- first 4 bytes
	//     local args = tos.bytes.slice(bin, 4)     -- remaining bytes
	L.SetField(bytesTable, "slice", L.NewFunction(func(L *lua.LState) int {
		s := []byte(L.CheckString(1))
		chargePrimGas(1 + uint64(len(s))) // SEC-2: per-byte gas proportional to input
		offsetBig := parseBigInt(L, 2)
		if !offsetBig.IsInt64() || offsetBig.Sign() < 0 {
			L.RaiseError("tos.bytes.slice: offset out of range")
			return 0
		}
		offset := int(offsetBig.Int64())
		if offset > len(s) {
			L.RaiseError("tos.bytes.slice: offset %d out of range (len=%d)", offset, len(s))
			return 0
		}
		var result []byte
		if L.GetTop() >= 3 {
			lengthBig := parseBigInt(L, 3)
			if !lengthBig.IsInt64() || lengthBig.Sign() < 0 {
				L.RaiseError("tos.bytes.slice: length out of range")
				return 0
			}
			length := int(lengthBig.Int64())
			if offset+length > len(s) {
				L.RaiseError("tos.bytes.slice: offset+length %d out of range (len=%d)", offset+length, len(s))
				return 0
			}
			result = s[offset : offset+length]
		} else {
			result = s[offset:]
		}
		L.Push(lua.LString(result))
		return 1
	}))

	// tos.bytes.fromUint256(n [, size]) → binaryStr
	//   Encode a uint256 as a big-endian binary string.
	//   size (default 32) specifies the output byte length; the number is zero-padded
	//   on the left.  Raises an error if the value does not fit in size bytes.
	//
	//   Example:
	//     local b = tos.bytes.fromUint256(255, 1)  -- "\xff"  (1 byte)
	//     local b = tos.bytes.fromUint256(255)     -- 32-byte zero-padded
	L.SetField(bytesTable, "fromUint256", L.NewFunction(func(L *lua.LState) int {
		n := parseBigInt(L, 1)
		if n == nil || n.Sign() < 0 {
			L.RaiseError("tos.bytes.fromUint256: value must be a non-negative integer")
			return 0
		}
		size := 32
		if L.GetTop() >= 2 {
			sizeBig := parseBigInt(L, 2)
			if !sizeBig.IsInt64() || sizeBig.Sign() <= 0 || sizeBig.Int64() > 32 {
				L.RaiseError("tos.bytes.fromUint256: size must be 1–32")
				return 0
			}
			size = int(sizeBig.Int64())
		}
		raw := n.Bytes() // minimal big-endian; no leading zeros
		if len(raw) > size {
			L.RaiseError("tos.bytes.fromUint256: value does not fit in %d bytes", size)
			return 0
		}
		buf := make([]byte, size)
		copy(buf[size-len(raw):], raw)
		L.Push(lua.LString(buf))
		return 1
	}))

	// tos.bytes.toUint256(binaryStr) → uint256
	//   Interpret a big-endian binary string as an unsigned integer.
	//   The input may be 1–32 bytes; longer inputs raise an error.
	//
	//   Example:
	//     local n = tos.bytes.toUint256("\x00\x01")  -- 256
	//     local n = tos.bytes.toUint256(tos.bytes.slice(data, 0, 32))
	L.SetField(bytesTable, "toUint256", L.NewFunction(func(L *lua.LState) int {
		b := []byte(L.CheckString(1))
		if len(b) > 32 {
			L.RaiseError("tos.bytes.toUint256: input must be ≤ 32 bytes, got %d", len(b))
			return 0
		}
		n := new(big.Int).SetBytes(b)
		L.Push(luBig(n))
		return 1
	}))

	L.SetField(tosTable, "bytes", bytesTable)

	// tos.addmod(x, y, k) → (x + y) % k
	L.SetField(tosTable, "addmod", L.NewFunction(func(L *lua.LState) int {
		x := parseBigInt(L, 1)
		y := parseBigInt(L, 2)
		k := parseBigInt(L, 3)
		if k.Sign() == 0 {
			L.RaiseError("addmod: modulus is zero")
		}
		result := new(big.Int).Add(x, y)
		result.Mod(result, k)
		L.Push(luBig(result))
		return 1
	}))

	// tos.mulmod(x, y, k) → (x * y) % k
	L.SetField(tosTable, "mulmod", L.NewFunction(func(L *lua.LState) int {
		x := parseBigInt(L, 1)
		y := parseBigInt(L, 2)
		k := parseBigInt(L, 3)
		if k.Sign() == 0 {
			L.RaiseError("mulmod: modulus is zero")
		}
		result := new(big.Int).Mul(x, y)
		result.Mod(result, k)
		L.Push(luBig(result))
		return 1
	}))

	// tos.blockhash(n) → string | nil
	L.SetField(tosTable, "blockhash", L.NewFunction(func(L *lua.LState) int {
		nNum := parseBigInt(L, 1)
		if nNum == nil || !nNum.IsUint64() {
			L.Push(lua.LNil)
			return 1
		}
		h := blockCtx.GetHash(nNum.Uint64())
		if h == (common.Hash{}) {
			L.Push(lua.LNil)
		} else {
			L.Push(lua.LString(h.Hex()))
		}
		return 1
	}))

	// tos.self → string  (this contract's own address)
	L.SetField(tosTable, "self", lua.LString(contractAddr.Hex()))

	// ── Agent-Native primitives ───────────────────────────────────────────────

	// tos.agentload(addr, field) → value | nil
	//   Reads a field from the Agent-Native registries for the given address.
	//   Gas cost: params.AgentLoadGas per call (equivalent to 1 SLOAD).
	//
	//   Supported fields:
	//     "stake"         → uint256 (locked stake in wei)
	//     "suspended"     → bool    (1 = suspended, 0 = not)
	//     "is_registered" → bool    (1 = registered)
	//     "capabilities"  → uint256 (capability bitmap)
	//     "reputation"    → uint256 (signed i256 as two's-complement uint256)
	//     "rating_count"  → uint256 (number of ratings received)
	L.SetField(tosTable, "agentload", L.NewFunction(func(L *lua.LState) int {
		addrHex := L.CheckString(1)
		field := L.CheckString(2)
		chargePrimGas(params.AgentLoadGas)
		addr := common.HexToAddress(addrHex)
		switch field {
		case "stake":
			L.Push(luBig(agent.ReadStake(stateDB, addr)))
		case "suspended":
			if agent.IsSuspended(stateDB, addr) {
				L.Push(lua.Lu256FromUint64(1))
			} else {
				L.Push(lua.Lu256FromUint64(0))
			}
		case "is_registered":
			if agent.IsRegistered(stateDB, addr) {
				L.Push(lua.Lu256FromUint64(1))
			} else {
				L.Push(lua.Lu256FromUint64(0))
			}
		case "capabilities":
			L.Push(luBig(capability.CapabilitiesOf(stateDB, addr)))
		case "reputation":
			// TotalScoreOf returns a signed *big.Int; convert to two's-complement uint256.
			score := reputation.TotalScoreOf(stateDB, addr)
			L.Push(bigIntToLU256(score))
		case "rating_count":
			L.Push(luBig(reputation.RatingCountOf(stateDB, addr)))
		default:
			L.Push(lua.LNil)
		}
		return 1
	}))

	// tos.hascapability(addr, bit) → bool
	//   Returns true if addr holds the capability identified by bit.
	//   Gas cost: params.AgentLoadGas.
	L.SetField(tosTable, "hascapability", L.NewFunction(func(L *lua.LState) int {
		addrHex := L.CheckString(1)
		bit := uint8(L.CheckInt(2))
		chargePrimGas(params.AgentLoadGas)
		addr := common.HexToAddress(addrHex)
		if capability.HasCapability(stateDB, addr, bit) {
			L.Push(lua.LTrue)
		} else {
			L.Push(lua.LFalse)
		}
		return 1
	}))

	// tos.capabilitybit(name) → uint256 | nil
	//   Resolves a capability name to its bit index.
	//   Returns nil if the name has not been registered.
	//   Gas cost: params.AgentLoadGas.
	L.SetField(tosTable, "capabilitybit", L.NewFunction(func(L *lua.LState) int {
		name := L.CheckString(1)
		chargePrimGas(params.AgentLoadGas)
		bit, ok := capability.CapabilityBit(stateDB, name)
		if !ok {
			L.Push(lua.LNil)
		} else {
			L.Push(lua.Lu256FromUint64(uint64(bit)))
		}
		return 1
	}))

	// tos.delegationused(principal, nonce) → bool
	//   Returns true if (principal, nonce) has been consumed.
	//   Gas cost: params.AgentLoadGas.
	L.SetField(tosTable, "delegationused", L.NewFunction(func(L *lua.LState) int {
		principalHex := L.CheckString(1)
		nonceBig := parseBigInt(L, 2)
		chargePrimGas(params.AgentLoadGas)
		principal := common.HexToAddress(principalHex)
		if delegation.IsUsed(stateDB, principal, nonceBig) {
			L.Push(lua.LTrue)
		} else {
			L.Push(lua.LFalse)
		}
		return 1
	}))

	// tos.delegationmarkused(principal, nonce)
	//   Marks (principal, nonce) as consumed, preventing future use.
	//   Only the principal may consume their own nonces (enforced by the system action handler;
	//   here we enforce it at the VM level too: caller must be msg.sender == principal).
	//   Gas cost: gasSStore (state write).
	L.SetField(tosTable, "delegationmarkused", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.delegationmarkused: state modification not allowed in staticcall")
			return 0
		}
		principalHex := L.CheckString(1)
		nonceBig := parseBigInt(L, 2)
		chargePrimGas(gasSStore)
		principal := common.HexToAddress(principalHex)
		// Security: only the principal (= immediate caller for this frame) may consume their own nonces.
		if ctx.From != principal {
			L.RaiseError("tos.delegationmarkused: caller is not principal")
			return 0
		}
		if delegation.IsUsed(stateDB, principal, nonceBig) {
			L.RaiseError("tos.delegationmarkused: nonce already used")
			return 0
		}
		delegation.MarkUsed(stateDB, principal, nonceBig)
		return 0
	}))

	// tos.delegationrevoke(principal, nonce)
	//   Revokes (principal, nonce) by marking it as consumed.
	//   Semantically identical to delegationmarkused but communicates revocation intent.
	//   Only the principal may revoke their own delegations.
	//   Gas cost: gasSStore.
	L.SetField(tosTable, "delegationrevoke", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.delegationrevoke: state modification not allowed in staticcall")
			return 0
		}
		principalHex := L.CheckString(1)
		nonceBig := parseBigInt(L, 2)
		chargePrimGas(gasSStore)
		principal := common.HexToAddress(principalHex)
		if ctx.From != principal {
			L.RaiseError("tos.delegationrevoke: caller is not principal")
			return 0
		}
		delegation.Revoke(stateDB, principal, nonceBig)
		return 0
	}))

	// tos.totaleligible(bit) → uint256
	//   Returns the count of addresses that hold capability bit.
	//   Used by vote<T> to snapshot the eligible voter count at ballot creation time.
	//   Gas cost: gasSLoad.
	L.SetField(tosTable, "totaleligible", L.NewFunction(func(L *lua.LState) int {
		bit := uint8(L.CheckInt(1))
		chargePrimGas(gasSLoad)
		count := capability.TotalEligible(stateDB, bit)
		L.Push(luBig(count))
		return 1
	}))

	// tos.delegationverify(hash, v, r, s, principal, scope_hash, expiry_ms, nonce) → bool
	//   Verifies a delegation signature and checks replay protection + expiry.
	//   Does NOT consume the nonce (call tos.delegationmarkused separately to consume it).
	//
	//   Arguments:
	//     hash       — bytes32 hex: keccak256 of the typed delegation payload
	//     v          — integer 0/1 (or 27/28 — normalised internally)
	//     r          — bytes32 hex
	//     s          — bytes32 hex
	//     principal  — address hex: claimed signer
	//     scope_hash — bytes32 hex: must match what was signed
	//     expiry_ms  — uint256: Unix timestamp in ms; 0 = no expiry
	//     nonce      — uint256: the nonce included in the signed payload
	//
	//   Returns true iff:
	//     1. ecrecover(hash, v, r, s) == principal
	//     2. nonce has not been consumed
	//     3. block.timestamp_ms < expiry_ms OR expiry_ms == 0
	//
	//   Gas cost: 3000 (ecrecover equivalent) + gasSLoad (nonce check).
	L.SetField(tosTable, "delegationverify", L.NewFunction(func(L *lua.LState) int {
		hashHex := L.CheckString(1)
		vNum := uint8(L.CheckInt(2))
		rHex := L.CheckString(3)
		sHex := L.CheckString(4)
		principalHex := L.CheckString(5)
		// scope_hash (arg 6) is already embedded in hash; passed for documentation only
		_ = L.CheckString(6)
		expiryBig := parseBigInt(L, 7)
		nonceBig := parseBigInt(L, 8)

		chargePrimGas(3000 + gasSLoad)

		// 1. ecrecover
		hashBytes := common.FromHex(hashHex)
		rBytes := common.FromHex(rHex)
		sBytes := common.FromHex(sHex)
		if len(hashBytes) != 32 || len(rBytes) != 32 || len(sBytes) != 32 {
			L.Push(lua.LFalse)
			return 1
		}
		v := vNum
		if v >= 27 {
			v -= 27
		}
		if v != 0 && v != 1 {
			L.Push(lua.LFalse)
			return 1
		}
		sig := make([]byte, 65)
		copy(sig[0:32], rBytes)
		copy(sig[32:64], sBytes)
		sig[64] = v
		pub, err := crypto.SigToPub(hashBytes, sig)
		if err != nil {
			L.Push(lua.LFalse)
			return 1
		}
		recovered := crypto.PubkeyToAddress(*pub)
		principal := common.HexToAddress(principalHex)
		if recovered != principal {
			L.Push(lua.LFalse)
			return 1
		}

		// 2. Replay protection
		if delegation.IsUsed(stateDB, principal, nonceBig) {
			L.Push(lua.LFalse)
			return 1
		}

		// 3. Expiry check (blockCtx.Time is in seconds; expiry_ms is milliseconds)
		if expiryBig != nil && expiryBig.Sign() > 0 {
			// blockCtx.Time is seconds; convert to ms for comparison
			blockMs := new(big.Int).Mul(blockCtx.Time, big.NewInt(1000))
			if blockMs.Cmp(expiryBig) >= 0 {
				L.Push(lua.LFalse)
				return 1
			}
		}

		L.Push(lua.LTrue)
		return 1
	}))

	// ── Escrow primitives ─────────────────────────────────────────────────────
	//
	// Escrow slots are namespaced under the calling contract address:
	//   key = keccak256("tol.escrow." || contractAddr[20] || agentAddr[20] || purpose_u8)
	//
	// This means each contract manages its own escrow pool; there is no
	// global escrow — a contract can only escrow/release its own balance.

	escrowSlot := func(agentAddr common.Address, purpose uint8) common.Hash {
		key := append([]byte("tol.escrow."), contractAddr.Bytes()...)
		key = append(key, agentAddr.Bytes()...)
		key = append(key, purpose)
		return common.BytesToHash(crypto.Keccak256(key))
	}

	// tos.escrowbalanceof(agentAddr, purpose_bit) → uint256
	//   Returns the escrow balance held by this contract for (agentAddr, purpose_bit).
	//   Gas cost: gasSLoad.
	L.SetField(tosTable, "escrowbalanceof", L.NewFunction(func(L *lua.LState) int {
		agentHex := L.CheckString(1)
		purpose := uint8(L.CheckInt(2))
		chargePrimGas(gasSLoad)
		agentAddr := common.HexToAddress(agentHex)
		raw := stateDB.GetState(contractAddr, escrowSlot(agentAddr, purpose))
		L.Push(luBig(raw.Big()))
		return 1
	}))

	// tos.escrow(agentAddr, amount, purpose_bit)
	//   Locks `amount` from this contract's balance into escrow for agentAddr.
	//   Gas cost: gasSLoad + gasSStore.
	L.SetField(tosTable, "escrow", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.escrow: state modification not allowed in staticcall")
			return 0
		}
		agentHex := L.CheckString(1)
		amount := parseBigInt(L, 2)
		purpose := uint8(L.CheckInt(3))
		chargePrimGas(gasSLoad + gasSStore)
		if amount == nil || amount.Sign() <= 0 {
			L.RaiseError("tos.escrow: amount must be positive")
			return 0
		}
		if !blockCtx.CanTransfer(stateDB, contractAddr, amount) {
			L.RaiseError("tos.escrow: insufficient contract balance")
			return 0
		}
		agentAddr := common.HexToAddress(agentHex)
		slot := escrowSlot(agentAddr, purpose)
		current := stateDB.GetState(contractAddr, slot).Big()
		stateDB.SubBalance(contractAddr, amount)
		stateDB.SetState(contractAddr, slot, common.BigToHash(new(big.Int).Add(current, amount)))
		return 0
	}))

	// tos.release(agentAddr, amount, purpose_bit)
	//   Releases `amount` from escrow and transfers it to agentAddr.
	//   Gas cost: gasSLoad + gasSStore + gasTransfer.
	L.SetField(tosTable, "release", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.release: state modification not allowed in staticcall")
			return 0
		}
		agentHex := L.CheckString(1)
		amount := parseBigInt(L, 2)
		purpose := uint8(L.CheckInt(3))
		chargePrimGas(gasSLoad + gasSStore + gasTransfer)
		if amount == nil || amount.Sign() <= 0 {
			L.RaiseError("tos.release: amount must be positive")
			return 0
		}
		agentAddr := common.HexToAddress(agentHex)
		slot := escrowSlot(agentAddr, purpose)
		current := stateDB.GetState(contractAddr, slot).Big()
		if current.Cmp(amount) < 0 {
			L.RaiseError("tos.release: escrow balance insufficient")
			return 0
		}
		stateDB.SetState(contractAddr, slot, common.BigToHash(new(big.Int).Sub(current, amount)))
		stateDB.AddBalance(agentAddr, amount)
		return 0
	}))

	// tos.slash(agentAddr, amount, recipientAddr, purpose_bit)
	//   Slashes `amount` from agentAddr's escrow and transfers it to recipientAddr.
	//   Gas cost: gasSLoad + gasSStore + gasTransfer.
	L.SetField(tosTable, "slash", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.slash: state modification not allowed in staticcall")
			return 0
		}
		agentHex := L.CheckString(1)
		amount := parseBigInt(L, 2)
		recipientHex := L.CheckString(3)
		purpose := uint8(L.CheckInt(4))
		chargePrimGas(gasSLoad + gasSStore + gasTransfer)
		if amount == nil || amount.Sign() <= 0 {
			L.RaiseError("tos.slash: amount must be positive")
			return 0
		}
		agentAddr := common.HexToAddress(agentHex)
		recipientAddr := common.HexToAddress(recipientHex)
		slot := escrowSlot(agentAddr, purpose)
		current := stateDB.GetState(contractAddr, slot).Big()
		if current.Cmp(amount) < 0 {
			L.RaiseError("tos.slash: escrow balance insufficient")
			return 0
		}
		stateDB.SetState(contractAddr, slot, common.BigToHash(new(big.Int).Sub(current, amount)))
		stateDB.AddBalance(recipientAddr, amount)
		return 0
	}))

	// ── KYC primitives ────────────────────────────────────────────────────────

	// tos.kyc(addr, field) → value | nil
	//   Reads a KYC field for addr. Gas cost: params.KYCLoadGas (100, one SLOAD).
	//   Fields:
	//     "level"  → uint256 (u16 bitmask of verified tiers)
	//     "tier"   → uint256 (tier number 0–8)
	//     "active" → bool (true iff status == KycActive)
	L.SetField(tosTable, "kyc", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(params.KYCLoadGas)
		addrStr := L.CheckString(1)
		field := L.CheckString(2)
		addr := common.HexToAddress(addrStr)
		switch field {
		case "level":
			L.Push(luBig(new(big.Int).SetUint64(uint64(kyc.ReadLevel(stateDB, addr)))))
		case "tier":
			L.Push(luBig(new(big.Int).SetUint64(uint64(kyc.TierOf(kyc.ReadLevel(stateDB, addr))))))
		case "active":
			if kyc.ReadStatus(stateDB, addr) == kyc.KycActive {
				L.Push(lua.LTrue)
			} else {
				L.Push(lua.LFalse)
			}
		default:
			L.Push(lua.LNil)
		}
		return 1
	}))

	// tos.meetskyclevel(addr, required) → bool
	//   Returns true if addr has Active KYC and level bitmask includes all bits in required.
	//   Gas cost: params.KYCLoadGas.
	L.SetField(tosTable, "meetskyclevel", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(params.KYCLoadGas)
		addrStr := L.CheckString(1)
		requiredBig := L.CheckUserData(2)
		addr := common.HexToAddress(addrStr)
		var required uint16
		if b, ok := requiredBig.Value.(*big.Int); ok {
			required = uint16(b.Uint64())
		}
		if kyc.MeetsLevel(stateDB, addr, required) {
			L.Push(lua.LTrue)
		} else {
			L.Push(lua.LFalse)
		}
		return 1
	}))

	// ── TNS primitives ────────────────────────────────────────────────────────

	// tos.tnsresolve(nameHashHex) → addrHex | nil
	//   Resolves a name hash (hex string) to the registered address.
	//   Gas cost: params.TNSLoadGas (200).
	L.SetField(tosTable, "tnsresolve", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(params.TNSLoadGas)
		hashHex := L.CheckString(1)
		nameHash := common.HexToHash(hashHex)
		addr := tns.Resolve(stateDB, nameHash)
		if addr == (common.Address{}) {
			L.Push(lua.LNil)
		} else {
			L.Push(lua.LString(addr.Hex()))
		}
		return 1
	}))

	// tos.tnsreverse(addrHex) → nameHashHex | nil
	//   Returns the name hash for addr, or nil if no name registered.
	//   Gas cost: params.TNSLoadGas.
	L.SetField(tosTable, "tnsreverse", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(params.TNSLoadGas)
		addrStr := L.CheckString(1)
		addr := common.HexToAddress(addrStr)
		h := tns.Reverse(stateDB, addr)
		if h == (common.Hash{}) {
			L.Push(lua.LNil)
		} else {
			L.Push(lua.LString(h.Hex()))
		}
		return 1
	}))

	// tos.tnshasname(addrHex) → bool
	//   Returns true if addr has a registered TNS name.
	//   Gas cost: params.TNSLoadGas.
	L.SetField(tosTable, "tnshasname", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(params.TNSLoadGas)
		addrStr := L.CheckString(1)
		addr := common.HexToAddress(addrStr)
		if tns.HasName(stateDB, addr) {
			L.Push(lua.LTrue)
		} else {
			L.Push(lua.LFalse)
		}
		return 1
	}))

	// ── Referral primitives ───────────────────────────────────────────────────

	// tos.hasreferrer(addrHex) → bool
	L.SetField(tosTable, "hasreferrer", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(params.ReferralLoadGas)
		addr := common.HexToAddress(L.CheckString(1))
		if referral.HasReferrer(stateDB, addr) {
			L.Push(lua.LTrue)
		} else {
			L.Push(lua.LFalse)
		}
		return 1
	}))

	// tos.getreferrer(addrHex) → addrHex | nil
	L.SetField(tosTable, "getreferrer", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(params.ReferralLoadGas)
		addr := common.HexToAddress(L.CheckString(1))
		ref := referral.ReadReferrer(stateDB, addr)
		if ref == (common.Address{}) {
			L.Push(lua.LNil)
		} else {
			L.Push(lua.LString(ref.Hex()))
		}
		return 1
	}))

	// tos.getuplines(addrHex, levels) → table of addrHex strings (up to levels ancestors)
	//   Gas cost: ReferralLoadGas + ReferralLoadGas * levels (one SLOAD per ancestor).
	L.SetField(tosTable, "getuplines", L.NewFunction(func(L *lua.LState) int {
		addr := common.HexToAddress(L.CheckString(1))
		levels := uint8(L.CheckInt(2))
		if levels > params.MaxReferralDepth {
			levels = params.MaxReferralDepth
		}
		chargePrimGas(params.ReferralLoadGas + params.ReferralLoadGas*uint64(levels))
		uplines := referral.GetUplines(stateDB, addr, levels)
		tbl := L.NewTable()
		for i, a := range uplines {
			L.RawSetInt(tbl, i+1, lua.LString(a.Hex()))
		}
		L.Push(tbl)
		return 1
	}))

	// tos.getdirectcount(addrHex) → uint256
	L.SetField(tosTable, "getdirectcount", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(params.ReferralLoadGas)
		addr := common.HexToAddress(L.CheckString(1))
		n := referral.ReadDirectCount(stateDB, addr)
		L.Push(luBig(new(big.Int).SetUint64(uint64(n))))
		return 1
	}))

	// tos.getteamsize(addrHex) → uint256
	L.SetField(tosTable, "getteamsize", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(params.ReferralLoadGas)
		addr := common.HexToAddress(L.CheckString(1))
		n := referral.ReadTeamSize(stateDB, addr)
		L.Push(luBig(new(big.Int).SetUint64(n)))
		return 1
	}))

	// tos.getreferrallevel(addrHex) → uint256 (depth in referral tree, 0 = root)
	//   Gas cost: ReferralLoadGas + ReferralLoadGas * actual_depth (one SLOAD per hop).
	L.SetField(tosTable, "getreferrallevel", L.NewFunction(func(L *lua.LState) int {
		addr := common.HexToAddress(L.CheckString(1))
		depth := referral.GetReferralDepth(stateDB, addr)
		chargePrimGas(params.ReferralLoadGas + params.ReferralLoadGas*uint64(depth))
		L.Push(luBig(new(big.Int).SetUint64(uint64(depth))))
		return 1
	}))

	// tos.isdownline(ancestorHex, descendantHex, maxDepth) → bool
	//   Gas cost: ReferralLoadGas + ReferralLoadGas * maxDepth (worst-case SLOADs).
	L.SetField(tosTable, "isdownline", L.NewFunction(func(L *lua.LState) int {
		ancestor := common.HexToAddress(L.CheckString(1))
		descendant := common.HexToAddress(L.CheckString(2))
		maxDepth := uint8(L.CheckInt(3))
		if maxDepth > params.MaxReferralDepth {
			maxDepth = params.MaxReferralDepth
		}
		chargePrimGas(params.ReferralLoadGas + params.ReferralLoadGas*uint64(maxDepth))
		if referral.IsDownline(stateDB, ancestor, descendant, maxDepth) {
			L.Push(lua.LTrue)
		} else {
			L.Push(lua.LFalse)
		}
		return 1
	}))

	// tos.addteamvolume(addrHex, amount, levels) → uint256 (levels actually updated)
	//   Adds amount to the per-contract team_volume for each upline of addr up to levels.
	//   Also increments the per-contract direct_volume of the immediate referrer.
	//   Volume is namespaced under the calling contract address — each LVM contract
	//   maintains isolated counters for the same referral tree (no cross-contract mixing).
	//   Gas cost: gasSStore * levels (one SSTORE per upline level updated).
	//   Write primitive — fails in staticcall.
	L.SetField(tosTable, "addteamvolume", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.addteamvolume: state modification not allowed in staticcall")
			return 0
		}
		addr := common.HexToAddress(L.CheckString(1))
		amountUD := L.CheckUserData(2)
		amount, ok := amountUD.Value.(*big.Int)
		if !ok || amount.Sign() <= 0 {
			L.RaiseError("tos.addteamvolume: amount must be a positive uint256")
			return 0
		}
		levels := uint8(L.CheckInt(3))
		if levels > params.MaxReferralDepth {
			levels = params.MaxReferralDepth
		}
		chargePrimGas(gasSStore * uint64(levels))
		updated := referral.AddTeamVolumeFor(stateDB, contractAddr, addr, amount, levels)
		L.Push(luBig(new(big.Int).SetUint64(uint64(updated))))
		return 1
	}))

	// tos.getteamvolume(addrHex) → uint256
	//   Returns team_volume accumulated by THIS contract for addr (per-contract namespace).
	L.SetField(tosTable, "getteamvolume", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(params.ReferralLoadGas)
		addr := common.HexToAddress(L.CheckString(1))
		L.Push(luBig(referral.ReadTeamVolumeFor(stateDB, contractAddr, addr)))
		return 1
	}))

	// tos.getdirectvolume(addrHex) → uint256
	//   Returns direct_volume accumulated by THIS contract for addr (per-contract namespace).
	L.SetField(tosTable, "getdirectvolume", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(params.ReferralLoadGas)
		addr := common.HexToAddress(L.CheckString(1))
		L.Push(luBig(referral.ReadDirectVolumeFor(stateDB, contractAddr, addr)))
		return 1
	}))

	// ── Scheduled tasks ───────────────────────────────────────────────────────

	// tos.TASK_SCHEDULER — the canonical address of the on-chain task scheduler.
	L.SetField(tosTable, "TASK_SCHEDULER", lua.LString(params.TaskSchedulerAddress.Hex()))

	// tos.schedule(target, selector, taskData, gasLimit, delayBlocks, intervalBlocks, maxRuns)
	//   Schedules a future call to target:selector(taskData) on behalf of the
	//   calling contract. A gas deposit is deducted from the contract's balance.
	//   Returns the task ID as a hex string, or nil on any validation failure.
	//   Write primitive — fails in staticcall.
	L.SetField(tosTable, "schedule", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.schedule: state modification not allowed in staticcall")
			return 0
		}
		chargePrimGas(params.TaskScheduleGas)

		targetAddr := common.HexToAddress(L.CheckString(1))
		selectorHex := L.CheckString(2)
		taskDataHex := L.CheckString(3)
		gasLimit := uint64(L.CheckInt64(4))
		delayBlocks := uint64(L.CheckInt64(5))
		intervalBlocks := uint64(L.CheckInt64(6))
		maxRuns := uint64(L.CheckInt64(7))

		if gasLimit < params.TaskMinGasLimit || gasLimit > params.TaskMaxGasLimit {
			L.Push(lua.LNil)
			return 1
		}
		if delayBlocks < 1 || delayBlocks > params.TaskMaxHorizonBlocks {
			L.Push(lua.LNil)
			return 1
		}
		if intervalBlocks != 0 && intervalBlocks < params.TaskMinIntervalBlocks {
			L.Push(lua.LNil)
			return 1
		}
		if task.ReadActiveCount(stateDB, contractAddr) >= params.TaskMaxPerContract {
			L.Push(lua.LNil)
			return 1
		}

		deposit := new(big.Int).Mul(
			new(big.Int).SetUint64(gasLimit),
			big.NewInt(params.TxPriceWei),
		)
		if stateDB.GetBalance(contractAddr).Cmp(deposit) < 0 {
			L.Push(lua.LNil)
			return 1
		}
		stateDB.SubBalance(contractAddr, deposit)
		stateDB.AddBalance(params.TaskSchedulerAddress, deposit)

		targetBlock := blockCtx.BlockNumber.Uint64() + delayBlocks
		nonce := task.IncrementContractNonce(stateDB, contractAddr)
		taskId := task.NewTaskID(contractAddr, targetBlock, nonce)

		selBytes := common.FromHex(selectorHex)
		var selector [4]byte
		copy(selector[:], selBytes)

		taskDataBytes := common.FromHex(taskDataHex)
		var taskData common.Hash
		copy(taskData[:], taskDataBytes)

		rec := &task.TaskRecord{
			Scheduler:      contractAddr,
			Target:         targetAddr,
			Selector:       selector,
			TaskData:       taskData,
			GasLimit:       gasLimit,
			TargetBlock:    targetBlock,
			IntervalBlocks: intervalBlocks,
			MaxRuns:        maxRuns,
			Runs:           0,
			Status:         task.TaskPending,
		}
		task.WriteTask(stateDB, taskId, rec)
		task.EnqueueTask(stateDB, targetBlock, taskId)
		task.AdjustActiveCount(stateDB, contractAddr, +1)

		// Emit TaskScheduled(taskId, scheduler, target, targetBlock).
		var logData [96]byte
		copy(logData[:32], contractAddr[:])
		copy(logData[32:64], targetAddr[:])
		binary.BigEndian.PutUint64(logData[88:], targetBlock)
		stateDB.AddLog(&types.Log{
			Address: params.TaskSchedulerAddress,
			Topics:  []common.Hash{task.TaskScheduledTopic, taskId},
			Data:    logData[:],
		})

		L.Push(lua.LString(taskId.Hex()))
		return 1
	}))

	// tos.canceltask(taskIdHex) → bool
	//   Cancels a pending task created by this contract and refunds the deposit.
	//   Returns true on success, false if not found, already done, or caller is not the scheduler.
	//   Write primitive — fails in staticcall.
	L.SetField(tosTable, "canceltask", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.canceltask: state modification not allowed in staticcall")
			return 0
		}
		chargePrimGas(params.TaskCancelGas)

		taskId := common.HexToHash(L.CheckString(1))
		rec, ok := task.ReadTask(stateDB, taskId)
		if !ok || rec.Status != task.TaskPending {
			L.Push(lua.LFalse)
			return 1
		}
		if contractAddr != rec.Scheduler {
			L.Push(lua.LFalse)
			return 1
		}

		deposit := new(big.Int).Mul(
			new(big.Int).SetUint64(rec.GasLimit),
			big.NewInt(params.TxPriceWei),
		)
		stateDB.SubBalance(params.TaskSchedulerAddress, deposit)
		stateDB.AddBalance(rec.Scheduler, deposit)

		rec.Status = task.TaskCancelled
		task.WriteTask(stateDB, taskId, rec)
		task.AdjustActiveCount(stateDB, rec.Scheduler, -1)

		L.Push(lua.LTrue)
		return 1
	}))

	// tos.taskinfo(taskIdHex, field) → value | nil
	//   Returns a single field of a task record, or nil if the task does not exist.
	//   field is one of: "scheduler", "target", "status", "runs", "nextblock",
	//   "gaslimit", "interval", "maxruns".
	L.SetField(tosTable, "taskinfo", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(params.TaskInfoGas)

		taskId := common.HexToHash(L.CheckString(1))
		field := L.CheckString(2)

		rec, ok := task.ReadTask(stateDB, taskId)
		if !ok {
			L.Push(lua.LNil)
			return 1
		}
		switch field {
		case "scheduler":
			L.Push(lua.LString(rec.Scheduler.Hex()))
		case "target":
			L.Push(lua.LString(rec.Target.Hex()))
		case "status":
			L.Push(luBig(new(big.Int).SetUint64(uint64(rec.Status))))
		case "runs":
			L.Push(luBig(new(big.Int).SetUint64(rec.Runs)))
		case "nextblock":
			L.Push(luBig(new(big.Int).SetUint64(rec.TargetBlock)))
		case "gaslimit":
			L.Push(luBig(new(big.Int).SetUint64(rec.GasLimit)))
		case "interval":
			L.Push(luBig(new(big.Int).SetUint64(rec.IntervalBlocks)))
		case "maxruns":
			L.Push(luBig(new(big.Int).SetUint64(rec.MaxRuns)))
		default:
			L.Push(lua.LNil)
		}
		return 1
	}))

	// ── Address utilities + constants ─────────────────────────────────────────

	// tos.ZERO_ADDRESS  — the all-zeros 32-byte TOS address.
	// Equivalent to the zero-value address in GTOS.
	//
	//   require(to ~= tos.ZERO_ADDRESS, "transfer to zero address")
	L.SetField(tosTable, "ZERO_ADDRESS", lua.LString(common.Address{}.Hex()))

	// tos.MAX_UINT256  — 2^256 − 1 as a decimal string.
	// Equivalent to Solidity's type(uint256).max.
	//
	//   allow[owner][spender] = tos.MAX_UINT256  -- unlimited approval
	{
		max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
		L.SetField(tosTable, "MAX_UINT256", luBig(max))
	}

	// tos.isAddress(str) → bool
	//   Returns true if str is a syntactically valid TOS address:
	//   optional "0x"/"0X" prefix followed by exactly 64 hex characters.
	//   Does NOT check whether the address has deployed code or a non-zero balance.
	//
	//   require(tos.isAddress(to), "invalid address")
	L.SetField(tosTable, "isAddress", L.NewFunction(func(L *lua.LState) int {
		s := strings.TrimPrefix(L.CheckString(1), "0x")
		s = strings.TrimPrefix(s, "0X")
		// TOS addresses are 32 bytes = 64 hex chars (common.AddressLength == 32).
		if len(s) != 2*common.AddressLength {
			L.Push(lua.LFalse)
			return 1
		}
		for _, c := range s {
			if !('0' <= c && c <= '9') && !('a' <= c && c <= 'f') && !('A' <= c && c <= 'F') {
				L.Push(lua.LFalse)
				return 1
			}
		}
		L.Push(lua.LTrue)
		return 1
	}))

	// tos.toAddress(str) → string
	//   Normalise any hex string to a canonical checksum "0x"-prefixed 32-byte
	//   TOS address string. Short inputs are zero-padded on the left; extra
	//   leading bytes are truncated via common.HexToAddress semantics.
	//
	//   Useful to ensure consistent storage keys regardless of how callers format
	//   addresses:
	//
	//     local key = tos.toAddress(raw)
	//     tos.mapSet("balance", key, amount)
	L.SetField(tosTable, "toAddress", L.NewFunction(func(L *lua.LState) int {
		s := L.CheckString(1)
		addr := common.HexToAddress(s)
		L.Push(lua.LString(addr.Hex()))
		return 1
	}))

	// ── Constructor / one-time initializer ────────────────────────────────────

	// tos.oncreate(fn)
	//   Runs fn exactly once — on the very first call to the contract.
	L.SetField(tosTable, "oncreate", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.oncreate: state modification not allowed in staticcall")
			return 0
		}
		fn := L.CheckFunction(1)

		initSlot := StorageSlot("__oncreate__")
		chargePrimGas(gasSLoad) // read the init-flag slot
		if stateDB.GetState(contractAddr, initSlot) != (common.Hash{}) {
			return 0
		}

		chargePrimGas(gasSStore) // set the init-flag slot
		var one common.Hash
		one[31] = 1
		stateDB.SetState(contractAddr, initSlot, one)

		if err := L.CallByParam(lua.P{Fn: fn, NRet: 0, Protect: true}); err != nil {
			stateDB.SetState(contractAddr, initSlot, common.Hash{})
			L.RaiseError("%v", err)
		}
		return 0
	}))

	// ── Dynamic array storage ──────────────────────────────────────────────────

	// tos.arrLen(key) → LNumber
	L.SetField(tosTable, "arrLen", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasSLoad)
		key := L.CheckString(1)
		base := ArrLenSlot(key)
		raw := stateDB.GetState(contractAddr, base)
		n := new(big.Int).SetBytes(raw[:])
		L.Push(luBig(n))
		return 1
	}))

	// tos.arrGet(key, i) → LNumber | nil  (1-based)
	L.SetField(tosTable, "arrGet", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(2 * gasSLoad) // len slot + element slot
		key := L.CheckString(1)
		idxBI := parseBigInt(L, 2)
		if idxBI == nil {
			L.Push(lua.LNil)
			return 1
		}
		base := ArrLenSlot(key)
		raw := stateDB.GetState(contractAddr, base)
		length := new(big.Int).SetBytes(raw[:])
		one := big.NewInt(1)
		if idxBI.Cmp(one) < 0 || idxBI.Cmp(length) > 0 {
			L.Push(lua.LNil)
			return 1
		}
		i0 := new(big.Int).Sub(idxBI, one).Uint64()
		elemSlot := ArrElemSlot(base, i0)
		val := stateDB.GetState(contractAddr, elemSlot)
		n := new(big.Int).SetBytes(val[:])
		L.Push(luBig(n))
		return 1
	}))

	// tos.arrSet(key, i, value)  (1-based; reverts if OOB)
	L.SetField(tosTable, "arrSet", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.arrSet: state modification not allowed in staticcall")
			return 0
		}
		chargePrimGas(gasSLoad + gasSStore) // len slot read + element write
		key := L.CheckString(1)
		idxBI := parseBigInt(L, 2)
		val := parseBigInt(L, 3)
		base := ArrLenSlot(key)
		raw := stateDB.GetState(contractAddr, base)
		length := new(big.Int).SetBytes(raw[:])
		one := big.NewInt(1)
		if idxBI == nil || idxBI.Cmp(one) < 0 || idxBI.Cmp(length) > 0 {
			L.RaiseError("tos.arrSet: index out of bounds (len=%s)", length.Text(10))
		}
		i0 := new(big.Int).Sub(idxBI, one).Uint64()
		var slot common.Hash
		val.FillBytes(slot[:])
		stateDB.SetState(contractAddr, ArrElemSlot(base, i0), slot)
		return 0
	}))

	// tos.arrPush(key, value)
	L.SetField(tosTable, "arrPush", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.arrPush: state modification not allowed in staticcall")
			return 0
		}
		chargePrimGas(gasSLoad + 2*gasSStore) // len read + elem write + new len write
		key := L.CheckString(1)
		val := parseBigInt(L, 2)
		base := ArrLenSlot(key)
		raw := stateDB.GetState(contractAddr, base)
		length := new(big.Int).SetBytes(raw[:]).Uint64()
		if length == math.MaxUint64 {
			L.RaiseError("tos.arrPush: array length overflow")
			return 0
		}

		var elemSlot common.Hash
		val.FillBytes(elemSlot[:])
		stateDB.SetState(contractAddr, ArrElemSlot(base, length), elemSlot)

		var lenSlot common.Hash
		new(big.Int).SetUint64(length + 1).FillBytes(lenSlot[:])
		stateDB.SetState(contractAddr, base, lenSlot)
		return 0
	}))

	// tos.arrPop(key) → LNumber | nil
	L.SetField(tosTable, "arrPop", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.arrPop: state modification not allowed in staticcall")
			return 0
		}
		chargePrimGas(gasSLoad + 2*gasSStore) // len read + elem clear + new len write
		key := L.CheckString(1)
		base := ArrLenSlot(key)
		raw := stateDB.GetState(contractAddr, base)
		length := new(big.Int).SetBytes(raw[:]).Uint64()
		if length == 0 {
			L.Push(lua.LNil)
			return 1
		}
		lastIdx := length - 1
		elemSlot := ArrElemSlot(base, lastIdx)
		val := stateDB.GetState(contractAddr, elemSlot)
		n := new(big.Int).SetBytes(val[:])

		stateDB.SetState(contractAddr, elemSlot, common.Hash{})
		var lenSlot common.Hash
		new(big.Int).SetUint64(lastIdx).FillBytes(lenSlot[:])
		stateDB.SetState(contractAddr, base, lenSlot)

		L.Push(luBig(n))
		return 1
	}))

	// ── Struct storage ────────────────────────────────────────────────────────

	// tos.struct("TypeName", "field1:type1", "field2:type2", ...) → accessor table
	//
	// Defines a named struct type and returns a table with four methods:
	//
	//   accessor.get(key)                     → Lua table {field1=v1, field2=v2, ...}
	//   accessor.set(key, tbl)                → write all present fields; absent ones unchanged
	//   accessor.getField(key, fieldName)     → single field value
	//   accessor.setField(key, fieldName, v)  → single field write
	//
	// Supported field types:
	//   uint256  — stored as a 32-byte big-endian slot; reads back as LNumber
	//   bool     — stored in a slot; 0 = false, nonzero = true; reads back as LBool
	//
	// Each field occupies its own StateDB slot, namespaced by struct type and key:
	//   slot = keccak256("gtos.lua.struct." || TypeName || NUL || key || NUL || fieldName)
	//
	// Namespace "gtos.lua.struct." never collides with "gtos.lua.storage.",
	// "gtos.lua.str.", "gtos.lua.arr.", or "gtos.lua.map.".
	//
	// Gas: each field read costs gasSLoad; each field write costs gasSStore.
	//
	// Example:
	//   local Account = tos.struct("Account", "balance:uint256", "locked:bool", "nonce:uint256")
	//   Account.set("alice", {balance=1000, locked=false, nonce=1})
	//   local a = Account.get("alice")
	//   Account.setField("alice", "balance", a.balance - 100)
	L.SetField(tosTable, "struct", L.NewFunction(func(L *lua.LState) int {
		if L.GetTop() < 2 {
			L.RaiseError("tos.struct: requires a type name and at least one field definition")
			return 0
		}
		structName := L.CheckString(1)

		type fieldDef struct {
			name string
			typ  string // "uint256" or "bool"
		}

		nArgs := L.GetTop()
		fields := make([]fieldDef, 0, nArgs-1)
		fieldIdx := make(map[string]int, nArgs-1)

		for i := 2; i <= nArgs; i++ {
			def := L.CheckString(i)
			parts := strings.SplitN(def, ":", 2)
			if len(parts) != 2 {
				L.RaiseError("tos.struct: invalid field definition %q (expected \"name:type\")", def)
				return 0
			}
			fname := strings.TrimSpace(parts[0])
			ftype := strings.TrimSpace(parts[1])
			if fname == "" {
				L.RaiseError("tos.struct: empty field name in %q", def)
				return 0
			}
			switch ftype {
			case "uint256", "bool":
			default:
				L.RaiseError("tos.struct: unsupported field type %q (supported: uint256, bool)", ftype)
				return 0
			}
			if _, dup := fieldIdx[fname]; dup {
				L.RaiseError("tos.struct: duplicate field name %q", fname)
				return 0
			}
			fieldIdx[fname] = len(fields)
			fields = append(fields, fieldDef{name: fname, typ: ftype})
		}

		// slotFor derives the StateDB slot for (structName, instanceKey, fieldName).
		// NUL bytes separate components so "a"+"bc" != "ab"+"c".
		slotFor := func(key, fieldName string) common.Hash {
			return crypto.Keccak256Hash(
				[]byte("gtos.lua.struct."),
				[]byte(structName), []byte{0},
				[]byte(key), []byte{0},
				[]byte(fieldName),
			)
		}

		readField := func(key string, f fieldDef) lua.LValue {
			raw := stateDB.GetState(contractAddr, slotFor(key, f.name))
			switch f.typ {
			case "bool":
				if raw == (common.Hash{}) {
					return lua.LFalse
				}
				return lua.LBool(raw[31] != 0)
			default: // uint256
				if raw == (common.Hash{}) {
					return lua.LUint256Zero
				}
				return luBig(new(big.Int).SetBytes(raw[:]))
			}
		}

		writeField := func(key string, f fieldDef, v lua.LValue) error {
			var h common.Hash
			switch f.typ {
			case "bool":
				if v != lua.LFalse && v != lua.LNil {
					h[31] = 1
				}
			default: // uint256
				bi, err := parseUint256Value(v)
				if err != nil {
					return fmt.Errorf("field %q: %v", f.name, err)
				}
				b := bi.Bytes()
				if len(b) > 32 {
					return fmt.Errorf("field %q: value overflows uint256", f.name)
				}
				copy(h[32-len(b):], b)
			}
			stateDB.SetState(contractAddr, slotFor(key, f.name), h)
			return nil
		}

		acc := L.NewTable()

		// acc.get(key) → table with all fields
		L.SetField(acc, "get", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			chargePrimGas(uint64(len(fields)) * gasSLoad)
			t := L.NewTable()
			for _, f := range fields {
				L.SetField(t, f.name, readField(key, f))
			}
			L.Push(t)
			return 1
		}))

		// acc.set(key, tbl) — write all fields present in tbl; absent fields unchanged
		L.SetField(acc, "set", L.NewFunction(func(L *lua.LState) int {
			if ctx.Readonly {
				L.RaiseError("struct.set: state modification not allowed in staticcall")
				return 0
			}
			key := L.CheckString(1)
			tbl := L.CheckTable(2)
			chargePrimGas(uint64(len(fields)) * gasSStore)
			for _, f := range fields {
				v := tbl.RawGetString(f.name)
				if v == lua.LNil {
					continue
				}
				if err := writeField(key, f, v); err != nil {
					L.RaiseError("struct.set: %v", err)
					return 0
				}
			}
			return 0
		}))

		// acc.getField(key, fieldName) → value
		L.SetField(acc, "getField", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			fname := L.CheckString(2)
			idx, ok := fieldIdx[fname]
			if !ok {
				L.RaiseError("struct.getField: unknown field %q in struct %q", fname, structName)
				return 0
			}
			chargePrimGas(gasSLoad)
			L.Push(readField(key, fields[idx]))
			return 1
		}))

		// acc.setField(key, fieldName, value) — write one field
		L.SetField(acc, "setField", L.NewFunction(func(L *lua.LState) int {
			if ctx.Readonly {
				L.RaiseError("struct.setField: state modification not allowed in staticcall")
				return 0
			}
			key := L.CheckString(1)
			fname := L.CheckString(2)
			v := L.CheckAny(3)
			idx, ok := fieldIdx[fname]
			if !ok {
				L.RaiseError("struct.setField: unknown field %q in struct %q", fname, structName)
				return 0
			}
			chargePrimGas(gasSStore)
			if err := writeField(key, fields[idx], v); err != nil {
				L.RaiseError("struct.setField: %v", err)
				return 0
			}
			return 0
		}))

		L.Push(acc)
		return 1
	}))

	// ── Cross-contract read API ───────────────────────────────────────────────

	// tos.codeAt(addr) → bool
	L.SetField(tosTable, "codeAt", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCodeSize)
		addrHex := L.CheckString(1)
		addr := common.HexToAddress(addrHex)
		L.Push(lua.LBool(stateDB.GetCodeSize(addr) > 0))
		return 1
	}))

	// tos.at(addr) → read-only proxy table
	L.SetField(tosTable, "at", L.NewFunction(func(L *lua.LState) int {
		addrHex := L.CheckString(1)
		target := common.HexToAddress(addrHex)

		proxy := L.NewTable()

		L.SetField(proxy, "get", L.NewFunction(func(L *lua.LState) int {
			chargePrimGas(gasSLoad)
			key := L.CheckString(1)
			val := stateDB.GetState(target, StorageSlot(key))
			if val == (common.Hash{}) {
				L.Push(lua.LNil)
				return 1
			}
			n := new(big.Int).SetBytes(val[:])
			L.Push(luBig(n))
			return 1
		}))

		L.SetField(proxy, "getStr", L.NewFunction(func(L *lua.LState) int {
			chargePrimGas(gasSLoad) // length slot
			key := L.CheckString(1)
			base := StrLenSlot(key)
			lenSlot := stateDB.GetState(target, base)
			if lenSlot == (common.Hash{}) {
				L.Push(lua.LNil)
				return 1
			}
			length := binary.BigEndian.Uint64(lenSlot[24:]) - 1
			if numChunks := uint64((int(length) + 31) / 32); numChunks > 0 {
				chargePrimGas(numChunks * gasSLoad) // data chunks
			}
			data := make([]byte, length)
			for i := 0; i < int(length); i += 32 {
				slot := stateDB.GetState(target, StrChunkSlot(base, i/32))
				copy(data[i:], slot[:])
			}
			L.Push(lua.LString(string(data)))
			return 1
		}))

		L.SetField(proxy, "arrLen", L.NewFunction(func(L *lua.LState) int {
			chargePrimGas(gasSLoad)
			key := L.CheckString(1)
			base := ArrLenSlot(key)
			raw := stateDB.GetState(target, base)
			n := new(big.Int).SetBytes(raw[:])
			L.Push(luBig(n))
			return 1
		}))

		L.SetField(proxy, "arrGet", L.NewFunction(func(L *lua.LState) int {
			chargePrimGas(2 * gasSLoad) // len slot + element slot
			key := L.CheckString(1)
			idxBI := parseBigInt(L, 2)
			if idxBI == nil {
				L.Push(lua.LNil)
				return 1
			}
			base := ArrLenSlot(key)
			raw := stateDB.GetState(target, base)
			length := new(big.Int).SetBytes(raw[:])
			one := big.NewInt(1)
			if idxBI.Cmp(one) < 0 || idxBI.Cmp(length) > 0 {
				L.Push(lua.LNil)
				return 1
			}
			i0 := new(big.Int).Sub(idxBI, one).Uint64()
			elemSlot := ArrElemSlot(base, i0)
			val := stateDB.GetState(target, elemSlot)
			n := new(big.Int).SetBytes(val[:])
			L.Push(luBig(n))
			return 1
		}))

		L.SetField(proxy, "balance", L.NewFunction(func(L *lua.LState) int {
			chargePrimGas(gasBalance)
			bal := stateDB.GetBalance(target)
			if bal == nil {
				L.Push(lua.LUint256Zero)
			} else {
				L.Push(luBig(bal))
			}
			return 1
		}))

		L.SetField(proxy, "mapGet", L.NewFunction(func(L *lua.LState) int {
			nArgs := L.GetTop()
			if nArgs < 2 {
				L.ArgError(1, "mapGet requires at least 2 arguments (mapName, key)")
				return 0
			}
			chargePrimGas(gasSLoad)
			mapName := L.CheckString(1)
			keys := make([]string, nArgs-1)
			for i := 2; i <= nArgs; i++ {
				keys[i-2] = L.CheckString(i)
			}
			val := stateDB.GetState(target, MapSlot(mapName, keys))
			if val == (common.Hash{}) {
				L.Push(lua.LNil)
				return 1
			}
			L.Push(luBig(new(big.Int).SetBytes(val[:])))
			return 1
		}))

		L.SetField(proxy, "mapGetStr", L.NewFunction(func(L *lua.LState) int {
			nArgs := L.GetTop()
			if nArgs < 2 {
				L.ArgError(1, "mapGetStr requires at least 2 arguments (mapName, key)")
				return 0
			}
			chargePrimGas(gasSLoad) // length slot
			mapName := L.CheckString(1)
			keys := make([]string, nArgs-1)
			for i := 2; i <= nArgs; i++ {
				keys[i-2] = L.CheckString(i)
			}
			base := MapStrLenSlot(mapName, keys)
			lenSlot := stateDB.GetState(target, base)
			if lenSlot == (common.Hash{}) {
				L.Push(lua.LNil)
				return 1
			}
			length := binary.BigEndian.Uint64(lenSlot[24:]) - 1
			if numChunks := uint64((int(length) + 31) / 32); numChunks > 0 {
				chargePrimGas(numChunks * gasSLoad)
			}
			data := make([]byte, length)
			for i := 0; i < int(length); i += 32 {
				chunk := stateDB.GetState(target, StrChunkSlot(base, i/32))
				copy(data[i:], chunk[:])
			}
			L.Push(lua.LString(string(data)))
			return 1
		}))

		// tos.at(addr).mapping(name) → read-only proxy for uint256 named mappings
		L.SetField(proxy, "mapping", L.NewFunction(func(L *lua.LState) int {
			mapName := L.CheckString(1)
			innerProxy := L.NewTable()
			innerMt := L.NewTable()
			L.SetField(innerMt, "__index", L.NewFunction(func(L *lua.LState) int {
				key := L.CheckString(2)
				chargePrimGas(gasSLoad)
				val := stateDB.GetState(target, MapSlot(mapName, []string{key}))
				if val == (common.Hash{}) {
					L.Push(lua.LNil)
				} else {
					L.Push(luBig(new(big.Int).SetBytes(val[:])))
				}
				return 1
			}))
			L.SetMetatable(innerProxy, innerMt)
			L.Push(innerProxy)
			return 1
		}))

		// tos.at(addr).mappingStr(name) → read-only proxy for string named mappings
		L.SetField(proxy, "mappingStr", L.NewFunction(func(L *lua.LState) int {
			mapName := L.CheckString(1)
			innerProxy := L.NewTable()
			innerMt := L.NewTable()
			L.SetField(innerMt, "__index", L.NewFunction(func(L *lua.LState) int {
				key := L.CheckString(2)
				chargePrimGas(gasSLoad) // length slot
				base := MapStrLenSlot(mapName, []string{key})
				lenSlot := stateDB.GetState(target, base)
				if lenSlot == (common.Hash{}) {
					L.Push(lua.LNil)
					return 1
				}
				length := binary.BigEndian.Uint64(lenSlot[24:]) - 1
				if numChunks := uint64((int(length) + 31) / 32); numChunks > 0 {
					chargePrimGas(numChunks * gasSLoad)
				}
				data := make([]byte, length)
				for i := 0; i < int(length); i += 32 {
					chunk := stateDB.GetState(target, StrChunkSlot(base, i/32))
					copy(data[i:], chunk[:])
				}
				L.Push(lua.LString(string(data)))
				return 1
			}))
			L.SetMetatable(innerProxy, innerMt)
			L.Push(innerProxy)
			return 1
		}))

		L.Push(proxy)
		return 1
	}))

	// ── Inter-contract call ────────────────────────────────────────────────────

	// tos.call(addr [, value [, calldata]]) → bool, string|nil
	//
	// Calls another Lua contract with optional value forwarding and calldata.
	// Returns two values:
	//   ok       (bool)        — true on success, false if callee reverts
	//   retdata  (string|nil)  — ABI-encoded hex set by callee's tos.result(),
	//                            or nil if callee did not call tos.result()
	//
	// Semantics (Solidity low-level call equivalent):
	//   • Callee's code runs in a new Lua VM with its own gas budget.
	//   • msg.sender inside callee = this contract's address (not tx.origin).
	//   • msg.value inside callee = forwarded value.
	//   • State changes by callee are isolated: callee revert undoes only
	//     callee's changes; caller's changes before tos.call are preserved.
	//   • Gas consumed by callee is deducted from caller's remaining budget.
	//   • Nesting limited to maxCallDepth (8) levels; deeper calls revert.
	//
	// If the target address has no code, tos.call acts as a plain TOS transfer
	// (returns true/nil on success, false/nil if caller's balance is insufficient).
	//
	// Example:
	//   local ok, data = tos.call(tokenAddr, 0, calldata)
	//   tos.require(ok, "token call failed")
	//   local bal = tos.abi.decode(data, "uint256")
	L.SetField(tosTable, "call", L.NewFunction(func(L *lua.LState) int {
		if ctx.Depth >= maxCallDepth {
			L.RaiseError("tos.call: max call depth (%d) exceeded", maxCallDepth)
			return 0
		}

		addrHex := L.CheckString(1)
		calleeAddr := common.HexToAddress(addrHex)
		currentBlock := uint64(0)
		if blockCtx.BlockNumber != nil {
			currentBlock = blockCtx.BlockNumber.Uint64()
		}
		if err := lease.CheckCallable(stateDB, calleeAddr, currentBlock, chainConfig); err != nil {
			L.Push(lua.LFalse)
			L.Push(lua.LNil)
			return 2
		}

		var callValue *big.Int
		if L.GetTop() >= 2 && L.Get(2) != lua.LNil {
			callValue = parseBigInt(L, 2)
		} else {
			callValue = new(big.Int)
		}

		// Value transfers are not allowed in a readonly (staticcall) context.
		// Return false (soft failure) so callers can handle it with if/else,
		// consistent with Solidity CALL-within-STATICCALL semantics.
		if ctx.Readonly && callValue.Sign() > 0 {
			L.Push(lua.LFalse)
			L.Push(lua.LNil)
			return 2
		}

		var callData []byte
		if L.GetTop() >= 3 && L.Get(3) != lua.LNil {
			hexStr := L.CheckString(3)
			callData = common.FromHex(hexStr)
		}

		// Compute remaining gas budget for the child.
		// gasLimit is captured from the outer Execute parameter.
		parentUsedNow := L.GasUsed()
		totalUsed := parentUsedNow + totalChildGas + primGasCharged
		if totalUsed >= gasLimit {
			L.RaiseError("tos.call: out of gas")
			return 0
		}
		available := gasLimit - totalUsed
		childGasLimit := available - available/64 // keep 1/64 gas in parent frame

		// Guard check before snapshot: no state mutation, no snapshot leak.
		if callValue.Sign() > 0 && !blockCtx.CanTransfer(stateDB, contractAddr, callValue) {
			L.Push(lua.LFalse)
			L.Push(lua.LNil)
			return 2
		}

		// Inner snapshot: callee state changes are reverted on callee failure,
		// but caller state changes before this call are preserved.
		calleeSnap := stateDB.Snapshot()

		// Value transfer from calling contract to callee.
		if callValue.Sign() > 0 {
			blockCtx.Transfer(stateDB, contractAddr, calleeAddr, callValue)
		}

		// If no code, plain transfer succeeded (no return data).
		calleeCode := stateDB.GetCode(calleeAddr)
		if len(calleeCode) == 0 {
			L.Push(lua.LTrue)
			L.Push(lua.LNil)
			return 2
		}

		// Build child context: msg.sender = this contract, tx.origin unchanged.
		// readonly propagates: a call made from within a staticcall is also readonly.
		childCtx := CallCtx{
			From:     contractAddr, // callee sees caller contract as msg.sender
			To:       calleeAddr,
			Value:    callValue,
			Data:     callData,
			Depth:    ctx.Depth + 1,
			TxOrigin: ctx.TxOrigin,
			TxPrice:  ctx.TxPrice,
			Readonly: ctx.Readonly, // propagate staticcall constraint
			GoCtx:    ctx.GoCtx,    // propagate RPC timeout
		}

		childGasUsed, childReturnData, childRevertData, childErr := Execute(stateDB, blockCtx, chainConfig, childCtx, calleeCode, childGasLimit)
		totalChildGas += childGasUsed

		// Recalculate remaining and update parent gas limit so the parent
		// cannot use gas that the child already consumed.
		// Maintain invariant: L.GasLimit() == gasLimit - totalChildGas - primGasCharged.
		newTotalUsed := parentUsedNow + totalChildGas + primGasCharged
		if newTotalUsed < gasLimit {
			L.SetGasLimit(parentUsedNow + (gasLimit - newTotalUsed))
		} else {
			// Child consumed all remaining gas; freeze parent.
			L.SetGasLimit(parentUsedNow)
		}

		if childErr != nil {
			// Revert callee's state changes; caller's changes are preserved.
			stateDB.RevertToSnapshot(calleeSnap)
			L.Push(lua.LFalse)
			// Return structured revert data (selector + ABI) if the callee used
			// tos.revert("ErrorName", ...), otherwise nil.
			if len(childRevertData) > 0 {
				L.Push(lua.LString("0x" + common.Bytes2Hex(childRevertData)))
			} else {
				L.Push(lua.LNil)
			}
			return 2
		}

		L.Push(lua.LTrue)
		if len(childReturnData) > 0 {
			L.Push(lua.LString("0x" + common.Bytes2Hex(childReturnData)))
		} else {
			L.Push(lua.LNil)
		}
		return 2
	}))

	// tos.staticcall(addr [, calldata]) → bool, string|nil
	//
	// Read-only inter-contract call (EVM STATICCALL equivalent).
	// Identical to tos.call except:
	//   • No value forwarding (always zero).
	//   • Callee runs in readonly mode: tos.set / tos.setStr / tos.arrPush …
	//     tos.transfer / tos.emit / tos.oncreate all raise errors.
	//   • readonly propagates transitively: if callee calls tos.call(addr,v>0),
	//     that call also fails.
	//
	// Use when you need to query another contract's computed state without
	// risking accidental side effects.
	//
	// Example:
	//   local ok, data = tos.staticcall(tokenAddr, tos.selector("totalSupply()"))
	//   tos.require(ok, "query failed")
	//   local supply = tos.abi.decode(data, "uint256")
	L.SetField(tosTable, "staticcall", L.NewFunction(func(L *lua.LState) int {
		if ctx.Depth >= maxCallDepth {
			L.RaiseError("tos.staticcall: max call depth (%d) exceeded", maxCallDepth)
			return 0
		}

		addrHex := L.CheckString(1)
		calleeAddr := common.HexToAddress(addrHex)
		currentBlock := uint64(0)
		if blockCtx.BlockNumber != nil {
			currentBlock = blockCtx.BlockNumber.Uint64()
		}
		if err := lease.CheckCallable(stateDB, calleeAddr, currentBlock, chainConfig); err != nil {
			L.Push(lua.LFalse)
			L.Push(lua.LNil)
			return 2
		}

		var callData []byte
		if L.GetTop() >= 2 && L.Get(2) != lua.LNil {
			callData = common.FromHex(L.CheckString(2))
		}

		// Compute child gas budget.
		parentUsedNow := L.GasUsed()
		totalUsed := parentUsedNow + totalChildGas + primGasCharged
		if totalUsed >= gasLimit {
			L.RaiseError("tos.staticcall: out of gas")
			return 0
		}
		available := gasLimit - totalUsed
		childGasLimit := available - available/64 // keep 1/64 gas in parent frame

		// Defense-in-depth snapshot: even though staticcall should not
		// mutate state, a buggy callee could attempt writes before the
		// readonly guard fires. Snapshot/revert guarantees rollback.
		calleeSnap := stateDB.Snapshot()

		// No value transfer for staticcall.
		calleeCode := stateDB.GetCode(calleeAddr)
		if len(calleeCode) == 0 {
			// No code: nothing to call; return true with nil data.
			L.Push(lua.LTrue)
			L.Push(lua.LNil)
			return 2
		}

		childCtx := CallCtx{
			From:     contractAddr,
			To:       calleeAddr,
			Value:    new(big.Int), // always zero for staticcall
			Data:     callData,
			Depth:    ctx.Depth + 1,
			TxOrigin: ctx.TxOrigin,
			TxPrice:  ctx.TxPrice,
			Readonly: true,      // the defining property of staticcall
			GoCtx:    ctx.GoCtx, // propagate RPC timeout
		}

		childGasUsed, childReturnData, childRevertData, childErr := Execute(stateDB, blockCtx, chainConfig, childCtx, calleeCode, childGasLimit)
		totalChildGas += childGasUsed

		// Maintain invariant: L.GasLimit() == gasLimit - totalChildGas - primGasCharged.
		newTotalUsed := parentUsedNow + totalChildGas + primGasCharged
		if newTotalUsed < gasLimit {
			L.SetGasLimit(parentUsedNow + (gasLimit - newTotalUsed))
		} else {
			L.SetGasLimit(parentUsedNow)
		}

		if childErr != nil {
			// Revert any state changes (defense-in-depth for readonly).
			stateDB.RevertToSnapshot(calleeSnap)
			L.Push(lua.LFalse)
			if len(childRevertData) > 0 {
				L.Push(lua.LString("0x" + common.Bytes2Hex(childRevertData)))
			} else {
				L.Push(lua.LNil)
			}
			return 2
		}

		L.Push(lua.LTrue)
		if len(childReturnData) > 0 {
			L.Push(lua.LString("0x" + common.Bytes2Hex(childReturnData)))
		} else {
			L.Push(lua.LNil)
		}
		return 2
	}))

	// tos.delegatecall(addr [, calldata]) → bool, string|nil
	//   Executes the code stored at `addr` in the CURRENT contract's storage
	//   context.  Analogous to EVM DELEGATECALL.
	//
	//   Semantics differ from tos.call in three critical ways:
	//     • Storage — All tos.sstore / tos.sload / tos.mapSet … inside the called code
	//       operate on the CALLING contract's slots, not on addr's slots.
	//     • tos.self  — reports the calling contract's address (not addr).
	//     • tos.caller — preserved from the outer call (original msg.sender).
	//     • tos.value  — preserved from the outer call (original msg.value).
	//     • No value transfer at the delegatecall boundary.
	//
	//   Returns (true, returnData|nil) on success.
	//   Returns (false, revertData|nil) on failure; storage changes are reverted.
	//
	//   Principal use case — upgradeable proxy:
	//     -- proxy contract
	//     local impl = tos.getStr("impl")          -- address of logic contract
	//     local ok, ret = tos.delegatecall(impl, tos.msg.data)
	//     require(ok, "proxy: delegatecall failed")
	//
	//   This lets you upgrade behaviour by pointing "impl" to a new contract
	//   address while all state stays in the proxy's storage slots.
	L.SetField(tosTable, "delegatecall", L.NewFunction(func(L *lua.LState) int {
		if ctx.Depth >= maxCallDepth {
			L.RaiseError("tos.delegatecall: max call depth (%d) exceeded", maxCallDepth)
			return 0
		}

		implAddrHex := L.CheckString(1)
		implAddr := common.HexToAddress(implAddrHex)
		currentBlock := uint64(0)
		if blockCtx.BlockNumber != nil {
			currentBlock = blockCtx.BlockNumber.Uint64()
		}
		if err := lease.CheckCallable(stateDB, implAddr, currentBlock, chainConfig); err != nil {
			L.Push(lua.LFalse)
			L.Push(lua.LNil)
			return 2
		}

		var callData []byte
		if L.GetTop() >= 2 && L.Get(2) != lua.LNil {
			callData = common.FromHex(L.CheckString(2))
		}

		// Compute remaining gas for the implementation.
		parentUsedNow := L.GasUsed()
		totalUsed := parentUsedNow + totalChildGas + primGasCharged
		if totalUsed >= gasLimit {
			L.RaiseError("tos.delegatecall: out of gas")
			return 0
		}
		available := gasLimit - totalUsed
		childGasLimit := available - available/64 // keep 1/64 gas in parent frame

		// Fetch the implementation code; no-code address is a no-op (success).
		implCode := stateDB.GetCode(implAddr)
		if len(implCode) == 0 {
			L.Push(lua.LTrue)
			L.Push(lua.LNil)
			return 2
		}

		// Snapshot so implementation writes can be rolled back on failure.
		// (Writes go to contractAddr's slots — not implAddr's — so this snapshot
		// guards the caller's own storage.)
		snap := stateDB.Snapshot()

		// The delegatecall context:
		//   to:    contractAddr  — storage target = calling contract
		//   from:  ctx.From      — msg.sender preserved (not the proxy)
		//   value: ctx.Value     — msg.value preserved
		childCtx := CallCtx{
			From:     ctx.From,     // preserve original msg.sender
			To:       contractAddr, // run in THIS contract's storage namespace
			Value:    ctx.Value,    // preserve msg.value
			Data:     callData,
			Depth:    ctx.Depth + 1,
			TxOrigin: ctx.TxOrigin,
			TxPrice:  ctx.TxPrice,
			Readonly: ctx.Readonly, // propagate staticcall constraint
			GoCtx:    ctx.GoCtx,    // propagate RPC timeout
		}

		childGasUsed, childReturnData, childRevertData, childErr := Execute(stateDB, blockCtx, chainConfig, childCtx, implCode, childGasLimit)
		totalChildGas += childGasUsed

		// Update parent's gas ceiling.
		newTotalUsed := parentUsedNow + totalChildGas + primGasCharged
		if newTotalUsed < gasLimit {
			L.SetGasLimit(parentUsedNow + (gasLimit - newTotalUsed))
		} else {
			L.SetGasLimit(parentUsedNow)
		}

		if childErr != nil {
			// Revert all storage writes the implementation made to contractAddr.
			stateDB.RevertToSnapshot(snap)
			L.Push(lua.LFalse)
			if len(childRevertData) > 0 {
				L.Push(lua.LString("0x" + common.Bytes2Hex(childRevertData)))
			} else {
				L.Push(lua.LNil)
			}
			return 2
		}

		L.Push(lua.LTrue)
		if len(childReturnData) > 0 {
			L.Push(lua.LString("0x" + common.Bytes2Hex(childReturnData)))
		} else {
			L.Push(lua.LNil)
		}
		return 2
	}))

	// ── Contract deployment ────────────────────────────────────────────────────

	deriveRawDeployAddress := func(op string, code []byte, salt *[32]byte) (uint64, common.Address) {
		deployerNonce := stateDB.GetNonce(contractAddr)
		if deployerNonce+1 < deployerNonce {
			L.RaiseError("%s: deployer nonce overflow", op)
			return 0, common.Address{}
		}

		var newAddr common.Address
		if salt == nil {
			newAddr = crypto.CreateAddress(contractAddr, deployerNonce)
		} else {
			newAddr = crypto.CreateAddress2(contractAddr, *salt, crypto.Keccak256(code))
		}
		if lease.HasTombstone(stateDB, newAddr) || stateDB.GetNonce(newAddr) != 0 || len(stateDB.GetCode(newAddr)) != 0 {
			L.RaiseError("%s: address collision at %s", op, newAddr.Hex())
			return 0, common.Address{}
		}
		return deployerNonce, newAddr
	}

	deployRawContract := func(op string, deployerNonce uint64, newAddr common.Address, code []byte, deployValue *big.Int, deposit *big.Int, leaseOwner common.Address, leaseBlocks uint64) {
		if deployValue == nil {
			deployValue = new(big.Int)
		}
		if deposit == nil {
			deposit = new(big.Int)
		}

		totalCost := new(big.Int).Set(deployValue)
		totalCost.Add(totalCost, deposit)
		if stateDB.GetBalance(contractAddr).Cmp(totalCost) < 0 {
			if deposit.Sign() > 0 {
				L.RaiseError("%s: insufficient balance for lease deposit and value transfer", op)
			} else {
				L.RaiseError("%s: insufficient balance for value transfer", op)
			}
			return
		}

		snapshot := stateDB.Snapshot()
		stateDB.SetNonce(contractAddr, deployerNonce+1)
		if deposit.Sign() > 0 {
			stateDB.SubBalance(contractAddr, deposit)
			stateDB.AddBalance(params.LeaseRegistryAddress, deposit)
		}
		if deployValue.Sign() > 0 {
			blockCtx.Transfer(stateDB, contractAddr, newAddr, deployValue)
		}

		stateDB.CreateAccount(newAddr)
		stateDB.SetNonce(newAddr, 1)
		stateDB.SetCode(newAddr, common.CopyBytes(code))

		if leaseOwner != (common.Address{}) {
			currentBlock := uint64(0)
			if blockCtx.BlockNumber != nil {
				currentBlock = blockCtx.BlockNumber.Uint64()
			}
			if _, err := lease.Activate(stateDB, newAddr, leaseOwner, currentBlock, leaseBlocks, uint64(len(code)), deposit, chainConfig); err != nil {
				stateDB.RevertToSnapshot(snapshot)
				L.RaiseError("%s: %v", op, err)
				return
			}
		}
	}

	// tos.create(code [, value]) → string
	//   Deploys a new Lua contract and returns its address as "0x..." hex.
	//   Analogous to EVM CREATE.
	//
	//   Address derivation (deterministic):
	//     newAddr = keccak256(RLP(contractAddr, nonce))
	//   The deploying contract's nonce is incremented after each successful
	//   deploy, so successive tos.create calls from the same contract yield
	//   distinct addresses.
	//
	//   code:  Lua source string (must not be empty)
	//   value: optional TOS wei to transfer to the new contract on creation
	//
	//   Gas: gasDeploy (3 200 000 base) + gasDeployByte (200) × len(code)
	//
	//   Reverts on: staticcall context, call-depth exceeded, empty code,
	//               insufficient balance for value transfer.
	//
	//   Example — factory pattern:
	//     local child = tos.create([[
	//         tos.oncreate(function() tos.sstore("parent", tos.caller) end)
	//     ]])
	//     tos.sstore("child", child)
	L.SetField(tosTable, "create", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.create: contract deployment not allowed in staticcall")
			return 0
		}
		if ctx.Depth >= maxCallDepth {
			L.RaiseError("tos.create: max call depth (%d) exceeded", maxCallDepth)
			return 0
		}

		code := L.CheckString(1)
		if len(code) == 0 {
			L.RaiseError("tos.create: code must not be empty")
			return 0
		}
		if uint64(len(code)) > params.MaxCodeSize {
			L.RaiseError("tos.create: code size %d exceeds limit %d", len(code), params.MaxCodeSize)
			return 0
		}

		// Optional value transfer to the new contract.
		var deployValue *big.Int
		if L.GetTop() >= 2 {
			deployValue = parseBigInt(L, 2)
			if deployValue == nil || deployValue.Sign() < 0 {
				L.RaiseError("tos.create: invalid value")
				return 0
			}
		} else {
			deployValue = new(big.Int)
		}

		// Gas: base + per-byte of code (mirrors EVM CREATE cost model).
		chargePrimGas(gasDeploy + gasDeployByte*uint64(len(code)))

		codeBytes := []byte(code)
		deployerNonce, newAddr := deriveRawDeployAddress("tos.create", codeBytes, nil)
		deployRawContract("tos.create", deployerNonce, newAddr, codeBytes, deployValue, nil, common.Address{}, 0)

		L.Push(lua.LString(newAddr.Hex()))
		return 1
	}))

	// tos.create2(code, salt [, value]) → string
	//   Deploys a new Lua contract at a DETERMINISTIC address and returns it as
	//   "0x..." hex.  Analogous to EVM CREATE2.
	//
	//   Address derivation (collision-resistant):
	//     codeHash = keccak256(code)
	//     newAddr  = keccak256(0xff ++ contractAddr ++ salt ++ codeHash)[12:]
	//   The address depends only on the deployer, the salt, and the code — not
	//   on the deployer's nonce.  This lets callers predict child addresses
	//   off-chain and enables counterfactual instantiation.
	//
	//   code:  Lua source string or glua bytecode (must not be empty).
	//   salt:  32-byte value supplied as:
	//            • hex string "0x…"  (≤ 32 bytes, right-aligned in [32]byte)
	//            • decimal number    (uint256, big-endian [32]byte)
	//          To use a text label, pass tos.keccak256("label") as the salt.
	//   value: optional TOS wei to send to the new contract.
	//
	//   Gas: gasDeploy (3 200 000) + gasDeployByte (200) × len(code)
	//
	//   Reverts on: staticcall context, call-depth exceeded, empty code,
	//               invalid/oversized salt, address already has code,
	//               insufficient balance for value transfer.
	//
	//   Example — predict child address before deploying:
	//     local salt     = tos.keccak256("v1")
	//     local expected = tos.create2addr(tos.self, salt, childCode)
	//     local actual   = tos.create2(childCode, salt)
	//     assert(actual == expected)
	L.SetField(tosTable, "create2", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.create2: contract deployment not allowed in staticcall")
			return 0
		}
		if ctx.Depth >= maxCallDepth {
			L.RaiseError("tos.create2: max call depth (%d) exceeded", maxCallDepth)
			return 0
		}

		code := L.CheckString(1)
		if len(code) == 0 {
			L.RaiseError("tos.create2: code must not be empty")
			return 0
		}
		if uint64(len(code)) > params.MaxCodeSize {
			L.RaiseError("tos.create2: code size %d exceeds limit %d", len(code), params.MaxCodeSize)
			return 0
		}

		// Parse salt: hex "0x…" (right-aligned) or decimal uint256 (big-endian).
		saltRaw := L.CheckString(2)
		var salt [32]byte
		if strings.HasPrefix(saltRaw, "0x") || strings.HasPrefix(saltRaw, "0X") {
			b := common.FromHex(saltRaw)
			if len(b) > 32 {
				L.RaiseError("tos.create2: salt hex too long (%d bytes, max 32)", len(b))
				return 0
			}
			copy(salt[32-len(b):], b) // right-align (big-endian)
		} else {
			n, ok := new(big.Int).SetString(saltRaw, 10)
			if !ok || n.Sign() < 0 {
				L.RaiseError("tos.create2: invalid salt %q — use a decimal number, hex string, or tos.keccak256(...)", saltRaw)
				return 0
			}
			n.FillBytes(salt[:])
		}

		// Optional value transfer.
		var deployValue *big.Int
		if L.GetTop() >= 3 {
			deployValue = parseBigInt(L, 3)
			if deployValue == nil || deployValue.Sign() < 0 {
				L.RaiseError("tos.create2: invalid value")
				return 0
			}
		} else {
			deployValue = new(big.Int)
		}

		// Gas: same model as tos.create.
		chargePrimGas(gasDeploy + gasDeployByte*uint64(len(code)))

		codeBytes := []byte(code)
		deployerNonce, newAddr := deriveRawDeployAddress("tos.create2", codeBytes, &salt)
		deployRawContract("tos.create2", deployerNonce, newAddr, codeBytes, deployValue, nil, common.Address{}, 0)

		L.Push(lua.LString(newAddr.Hex()))
		return 1
	}))

	// tos.createx(code, leaseBlocks, leaseOwner [, value]) → string
	//   Deploys a lease contract using CREATE-style address derivation.
	L.SetField(tosTable, "createx", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.createx: contract deployment not allowed in staticcall")
			return 0
		}
		if ctx.Depth >= maxCallDepth {
			L.RaiseError("tos.createx: max call depth (%d) exceeded", maxCallDepth)
			return 0
		}

		code := L.CheckString(1)
		if len(code) == 0 {
			L.RaiseError("tos.createx: code must not be empty")
			return 0
		}
		if uint64(len(code)) > params.MaxCodeSize {
			L.RaiseError("tos.createx: code size %d exceeds limit %d", len(code), params.MaxCodeSize)
			return 0
		}

		leaseBlocks := uint64(L.CheckInt64(2))
		if err := lease.ValidateLeaseBlocks(leaseBlocks); err != nil {
			L.RaiseError("tos.createx: %v", err)
			return 0
		}

		ownerHex := L.CheckString(3)
		if !common.IsHexAddress(ownerHex) {
			L.RaiseError("tos.createx: invalid lease owner")
			return 0
		}
		leaseOwner := common.HexToAddress(ownerHex)
		if err := lease.RequireExplicitOwner(stateDB, leaseOwner); err != nil {
			L.RaiseError("tos.createx: %v", err)
			return 0
		}

		var deployValue *big.Int
		if L.GetTop() >= 4 {
			deployValue = parseBigInt(L, 4)
			if deployValue == nil || deployValue.Sign() < 0 {
				L.RaiseError("tos.createx: invalid value")
				return 0
			}
		} else {
			deployValue = new(big.Int)
		}

		deployGas, err := lease.CreateXGas(uint64(len(code)), leaseBlocks)
		if err != nil {
			L.RaiseError("tos.createx: %v", err)
			return 0
		}
		chargePrimGas(deployGas)

		deposit, err := lease.DepositFor(uint64(len(code)), leaseBlocks)
		if err != nil {
			L.RaiseError("tos.createx: %v", err)
			return 0
		}

		codeBytes := []byte(code)
		deployerNonce, newAddr := deriveRawDeployAddress("tos.createx", codeBytes, nil)
		deployRawContract("tos.createx", deployerNonce, newAddr, codeBytes, deployValue, deposit, leaseOwner, leaseBlocks)

		L.Push(lua.LString(newAddr.Hex()))
		return 1
	}))

	// tos.create2x(code, salt, leaseBlocks, leaseOwner [, value]) → string
	//   Deploys a lease contract using CREATE2-style deterministic addressing.
	L.SetField(tosTable, "create2x", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.create2x: contract deployment not allowed in staticcall")
			return 0
		}
		if ctx.Depth >= maxCallDepth {
			L.RaiseError("tos.create2x: max call depth (%d) exceeded", maxCallDepth)
			return 0
		}

		code := L.CheckString(1)
		if len(code) == 0 {
			L.RaiseError("tos.create2x: code must not be empty")
			return 0
		}
		if uint64(len(code)) > params.MaxCodeSize {
			L.RaiseError("tos.create2x: code size %d exceeds limit %d", len(code), params.MaxCodeSize)
			return 0
		}

		saltRaw := L.CheckString(2)
		var salt [32]byte
		if strings.HasPrefix(saltRaw, "0x") || strings.HasPrefix(saltRaw, "0X") {
			b := common.FromHex(saltRaw)
			if len(b) > 32 {
				L.RaiseError("tos.create2x: salt hex too long (%d bytes, max 32)", len(b))
				return 0
			}
			copy(salt[32-len(b):], b)
		} else {
			n, ok := new(big.Int).SetString(saltRaw, 10)
			if !ok || n.Sign() < 0 {
				L.RaiseError("tos.create2x: invalid salt %q", saltRaw)
				return 0
			}
			n.FillBytes(salt[:])
		}

		leaseBlocks := uint64(L.CheckInt64(3))
		if err := lease.ValidateLeaseBlocks(leaseBlocks); err != nil {
			L.RaiseError("tos.create2x: %v", err)
			return 0
		}

		ownerHex := L.CheckString(4)
		if !common.IsHexAddress(ownerHex) {
			L.RaiseError("tos.create2x: invalid lease owner")
			return 0
		}
		leaseOwner := common.HexToAddress(ownerHex)
		if err := lease.RequireExplicitOwner(stateDB, leaseOwner); err != nil {
			L.RaiseError("tos.create2x: %v", err)
			return 0
		}

		var deployValue *big.Int
		if L.GetTop() >= 5 {
			deployValue = parseBigInt(L, 5)
			if deployValue == nil || deployValue.Sign() < 0 {
				L.RaiseError("tos.create2x: invalid value")
				return 0
			}
		} else {
			deployValue = new(big.Int)
		}

		deployGas, err := lease.Create2XGas(uint64(len(code)), leaseBlocks)
		if err != nil {
			L.RaiseError("tos.create2x: %v", err)
			return 0
		}
		chargePrimGas(deployGas)

		deposit, err := lease.DepositFor(uint64(len(code)), leaseBlocks)
		if err != nil {
			L.RaiseError("tos.create2x: %v", err)
			return 0
		}

		codeBytes := []byte(code)
		deployerNonce, newAddr := deriveRawDeployAddress("tos.create2x", codeBytes, &salt)
		deployRawContract("tos.create2x", deployerNonce, newAddr, codeBytes, deployValue, deposit, leaseOwner, leaseBlocks)

		L.Push(lua.LString(newAddr.Hex()))
		return 1
	}))

	// tos.create2addr(deployer, salt, code) → string
	//   Pure address-prediction function: returns the CREATE2 address that
	//   tos.create2(code, salt) would produce when called from `deployer`,
	//   WITHOUT deploying any contract.  Useful for pre-computing child
	//   addresses in factory contracts.
	//
	//   deployer: hex address string of the contract that will call tos.create2.
	//   salt:     same format as tos.create2 (hex or decimal).
	//   code:     the same code string that will be passed to tos.create2.
	//
	//   Gas: gasSLoad (cheap read-equivalent; no state modification).
	L.SetField(tosTable, "create2addr", L.NewFunction(func(L *lua.LState) int {
		deployerHex := L.CheckString(1)
		deployer := common.HexToAddress(deployerHex)

		saltRaw := L.CheckString(2)
		var salt [32]byte
		if strings.HasPrefix(saltRaw, "0x") || strings.HasPrefix(saltRaw, "0X") {
			b := common.FromHex(saltRaw)
			if len(b) > 32 {
				L.RaiseError("tos.create2addr: salt hex too long (%d bytes, max 32)", len(b))
				return 0
			}
			copy(salt[32-len(b):], b)
		} else {
			n, ok := new(big.Int).SetString(saltRaw, 10)
			if !ok || n.Sign() < 0 {
				L.RaiseError("tos.create2addr: invalid salt %q", saltRaw)
				return 0
			}
			n.FillBytes(salt[:])
		}

		code := L.CheckString(3)
		chargePrimGas(gasSLoad)
		codeHash := crypto.Keccak256([]byte(code))
		addr := crypto.CreateAddress2(deployer, salt, codeHash)
		L.Push(lua.LString(addr.Hex()))
		return 1
	}))

	// tos.compileBytecode(src) → string
	//   Compiles a Lua source string to glua bytecode and returns it as a binary
	//   string.  The result can be passed directly to tos.create() for efficient
	//   factory patterns: source is parsed and compiled once here, then the
	//   resulting bytecode is stored on-chain and executed without re-parsing on
	//   every call to the child contract.
	//
	//   Gas: gasCompileBase (5 000) + gasCompileByte (50) × len(src)
	//
	//   Errors: any Lua syntax error in src causes an immediate revert.
	//   The bytecode format is validated by glua on load; it is safe to pass
	//   untrusted bytecode to tos.create because Execute calls LoadBytecode
	//   which validates opcode ranges and closure indices before execution.
	//
	//   Example — deploy a pre-compiled child contract:
	//     local bc = tos.compileBytecode([[
	//         tos.dispatch({
	//             ["add(uint256,uint256)"] = function(a, b)
	//                 tos.result("uint256", a + b)
	//             end,
	//         })
	//     ]])
	//     local child = tos.create(bc)
	//     tos.sstore("child", child)
	//
	//   Without tos.compileBytecode:
	//     local child = tos.create(luaSrc)   -- source re-parsed on every call
	//   With tos.compileBytecode:
	//     local child = tos.create(tos.compileBytecode(luaSrc))  -- bytecode stored
	L.SetField(tosTable, "compileBytecode", L.NewFunction(func(L *lua.LState) int {
		src := L.CheckString(1)
		chargePrimGas(gasCompileBase + gasCompileByte*uint64(len(src)))
		bc, err := lua.CompileSourceToBytecode([]byte(src), "<compileBytecode>")
		if err != nil {
			L.RaiseError("tos.compileBytecode: %v", err)
			return 0
		}
		L.Push(lua.LString(bc))
		return 1
	}))

	// ── Selector / Dispatch ────────────────────────────────────────────────────

	// tos.selector(sig) → string  (4-byte keccak selector as "0x" hex)
	L.SetField(tosTable, "selector", L.NewFunction(func(L *lua.LState) int {
		sig := L.CheckString(1)
		h := crypto.Keccak256([]byte(sig))
		L.Push(lua.LString("0x" + common.Bytes2Hex(h[:4])))
		return 1
	}))

	// tos.dispatch(handlers)
	//   Routes msg.data to the correct handler by ABI function selector.
	L.SetField(tosTable, "dispatch", L.NewFunction(func(L *lua.LState) int {
		handlers := L.CheckTable(1)

		var msgSig string
		var calldata []byte

		msgTable, ok := L.GetGlobal("msg").(*lua.LTable)
		if ok {
			if sv, ok2 := msgTable.RawGetString("sig").(lua.LString); ok2 {
				msgSig = string(sv)
			}
			if dv, ok2 := msgTable.RawGetString("data").(lua.LString); ok2 {
				raw := common.FromHex(string(dv))
				if len(raw) >= 4 {
					calldata = raw[4:]
				}
			}
		}

		type handlerEntry struct {
			fn        lua.LValue
			signature string
			types     []string
		}
		handlerMap := make(map[string]handlerEntry)
		var fallbackEntry *handlerEntry

		var parseErr error
		handlers.ForEach(func(k, v lua.LValue) {
			if parseErr != nil {
				return
			}
			sigStr, ok := k.(lua.LString)
			if !ok {
				parseErr = fmt.Errorf("tos.dispatch: handler key must be a string, got %T", k)
				return
			}
			name, types, err := abiParseSignature(string(sigStr))
			if err != nil {
				parseErr = fmt.Errorf("tos.dispatch: %v", err)
				return
			}
			if name == "fallback" {
				if fallbackEntry != nil {
					parseErr = fmt.Errorf("tos.dispatch: duplicate fallback definition: %q conflicts with existing %q", string(sigStr), fallbackEntry.signature)
					return
				}
				entry := handlerEntry{fn: v, signature: string(sigStr), types: nil}
				fallbackEntry = &entry
				return
			}
			h := crypto.Keccak256([]byte(string(sigStr)))
			sel := "0x" + common.Bytes2Hex(h[:4])
			if existing, dup := handlerMap[sel]; dup {
				parseErr = fmt.Errorf("tos.dispatch: selector collision %s between %q and %q", sel, existing.signature, string(sigStr))
				return
			}
			handlerMap[sel] = handlerEntry{fn: v, signature: string(sigStr), types: types}
		})
		if parseErr != nil {
			L.RaiseError("%v", parseErr)
			return 0
		}

		var entry *handlerEntry
		if len(msgSig) < 10 {
			if fallbackEntry != nil {
				entry = fallbackEntry
			}
		} else {
			if h, ok := handlerMap[msgSig]; ok {
				entry = &h
			} else if fallbackEntry != nil {
				entry = fallbackEntry
			} else {
				L.RaiseError("tos.dispatch: no handler for selector %s", msgSig)
				return 0
			}
		}

		if entry == nil {
			return 0
		}

		goVals, abiArgs, err := abiDecodeRawArgs(calldata, entry.types)
		if err != nil {
			L.RaiseError("tos.dispatch: decode args for %s: %v", msgSig, err)
			return 0
		}

		luaArgs := make([]lua.LValue, len(goVals))
		for i, gv := range goVals {
			lv, err := abiGoToLua(abiArgs[i].Type, gv)
			if err != nil {
				L.RaiseError("tos.dispatch: arg %d: %v", i+1, err)
				return 0
			}
			luaArgs[i] = lv
		}

		// Use Protect:true so that Lua errors from the handler (wrong args, etc.)
		// are caught here.  But tos.result() and tos.revert() raise typed LUserData
		// sentinels that must reach Execute's outer PCall unchanged so that
		// isResultSignal / isRevertSignal can detect them.  Re-raise those sentinels
		// as-is; convert everything else to a regular Lua error.
		callParams := lua.P{Fn: entry.fn, NRet: 0, Protect: true}
		if err := L.CallByParam(callParams, luaArgs...); err != nil {
			if isResultSignal(err) || isRevertSignal(err) {
				// Propagate sentinel unchanged so Execute sees it correctly.
				var apiErr *lua.ApiError
				if errors.As(err, &apiErr) {
					L.Error(apiErr.Object, 0)
				} else {
					panic("dispatch: sentinel err has unexpected type")
				}
				return 0
			}
			L.RaiseError("%v", err)
		}
		return 0
	}))

	// ── Events ────────────────────────────────────────────────────────────────

	// luaEncodeIndexedTopic encodes one indexed event parameter as a 32-byte
	// log topic following the Ethereum ABI event-encoding rules:
	//
	//   Value types (uint*, int*, bool, address, bytesN):
	//     ABI-encode → 32 bytes → topic.
	//
	//   Reference types (string, bytes, T[], T[N]):
	//     keccak256(ABI-encode(value)) → topic.
	//
	// This matches Solidity's behaviour for `indexed` event parameters.
	luaEncodeIndexedTopic := func(typStr string, val lua.LValue) (common.Hash, error) {
		typ, err := abi.NewType(typStr, "", nil)
		if err != nil {
			return common.Hash{}, fmt.Errorf("invalid type %q: %v", typStr, err)
		}
		goVal, err := abiLuaToGo(typ, val)
		if err != nil {
			return common.Hash{}, err
		}
		packed, err := (abi.Arguments{{Type: typ}}).Pack(goVal)
		if err != nil {
			return common.Hash{}, err
		}
		switch typ.T {
		case abi.StringTy, abi.BytesTy, abi.SliceTy, abi.ArrayTy:
			// Reference types: topic = keccak256(ABI-encoded bytes).
			return crypto.Keccak256Hash(packed), nil
		default:
			// Value types: ABI-encode yields exactly 32 bytes.
			if len(packed) != 32 {
				return common.Hash{}, fmt.Errorf("indexed topic: unexpected size %d for type %s", len(packed), typStr)
			}
			var h common.Hash
			copy(h[:], packed)
			return h, nil
		}
	}

	// tos.emit(eventName, ["type [indexed]", val, ...]...)
	//   Emits a receipt log following the Ethereum event log specification.
	//
	//   topic[0] = keccak256(canonicalSig)
	//     where canonicalSig = "EventName(type1,type2,...)"
	//
	//   Indexed parameters are marked by appending " indexed" to the type
	//   string (or prefixing "indexed "). They appear as topics[1..3].
	//   EVM allows at most 3 indexed parameters; exceeding this is an error.
	//
	//   Non-indexed parameters are ABI-encoded into the log's data field.
	//
	//   Examples:
	//     tos.emit("Ping")
	//     tos.emit("Transfer", "address", from, "uint256", amount)
	//     tos.emit("Transfer", "address indexed", from, "uint256", amount)
	//     tos.emit("Approval", "address indexed", owner,
	//                          "address indexed", spender, "uint256", value)
	L.SetField(tosTable, "emit", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.emit: log emission not allowed in staticcall")
			return 0
		}
		eventName := L.CheckString(1)

		// Parse alternating ("type [indexed]", val) pairs starting at arg 2.
		nargs := L.GetTop() - 1
		if nargs%2 != 0 {
			L.RaiseError("tos.emit: expected alternating type/value pairs, got %d extra args", nargs)
			return 0
		}

		type emitParam struct {
			typStr  string
			val     lua.LValue
			indexed bool
		}
		params := make([]emitParam, nargs/2)
		for i := range params {
			rawType := L.CheckString(2 + i*2)
			val := L.CheckAny(2 + i*2 + 1)
			isIndexed := false
			if strings.HasSuffix(rawType, " indexed") {
				isIndexed = true
				rawType = strings.TrimSuffix(rawType, " indexed")
			} else if strings.HasPrefix(rawType, "indexed ") {
				isIndexed = true
				rawType = strings.TrimPrefix(rawType, "indexed ")
			}
			params[i] = emitParam{typStr: strings.TrimSpace(rawType), val: val, indexed: isIndexed}
		}

		// Build canonical event signature "EventName(type1,type2,...)".
		// topic[0] = keccak256(canonicalSig) — matches Ethereum ABI spec.
		typeNames := make([]string, len(params))
		for i, p := range params {
			typeNames[i] = p.typStr
		}
		canonicalSig := eventName + "(" + strings.Join(typeNames, ",") + ")"
		topics := []common.Hash{crypto.Keccak256Hash([]byte(canonicalSig))}

		// Separate indexed params (→ topics[1..3]) from non-indexed (→ data).
		type nonIndexedPair struct {
			typStr string
			val    lua.LValue
		}
		var nonIndexed []nonIndexedPair
		for _, p := range params {
			if p.indexed {
				if len(topics) >= 4 {
					L.RaiseError("tos.emit: too many indexed parameters (EVM max is 3)")
					return 0
				}
				topic, err := luaEncodeIndexedTopic(p.typStr, p.val)
				if err != nil {
					L.RaiseError("tos.emit: indexed param %q: %v", p.typStr, err)
					return 0
				}
				topics = append(topics, topic)
			} else {
				nonIndexed = append(nonIndexed, nonIndexedPair{p.typStr, p.val})
			}
		}

		// ABI-encode non-indexed params into log data.
		var data []byte
		if len(nonIndexed) > 0 {
			abiArgs := make(abi.Arguments, len(nonIndexed))
			goVals := make([]interface{}, len(nonIndexed))
			for i, ni := range nonIndexed {
				typ, err := abi.NewType(ni.typStr, "", nil)
				if err != nil {
					L.RaiseError("tos.emit: invalid type %q: %v", ni.typStr, err)
					return 0
				}
				abiArgs[i] = abi.Argument{Type: typ}
				gv, err := abiLuaToGo(typ, ni.val)
				if err != nil {
					L.RaiseError("tos.emit: param %q: %v", ni.typStr, err)
					return 0
				}
				goVals[i] = gv
			}
			var err error
			data, err = abiArgs.Pack(goVals...)
			if err != nil {
				L.RaiseError("tos.emit: ABI encode: %v", err)
				return 0
			}
		}

		// Charge for log emission: base + per-indexed-topic + per-byte.
		numIndexedTopics := uint64(len(topics) - 1) // topics[0] is the event sig, not charged per-topic
		chargePrimGas(gasLogBase + numIndexedTopics*gasLogTopic + uint64(len(data))*gasLogByte)

		stateDB.AddLog(&types.Log{
			Address: contractAddr,
			Topics:  topics,
			Data:    data,
		})
		return 0
	}))

	// ── String storage ────────────────────────────────────────────────────────

	// tos.setStr(key, val)
	L.SetField(tosTable, "setStr", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.setStr: state modification not allowed in staticcall")
			return 0
		}
		key := L.CheckString(1)
		val := L.CheckString(2)
		data := []byte(val)

		numChunks := uint64((len(data) + 31) / 32)
		chargePrimGas(gasSStore + numChunks*gasSStore) // len slot + data chunks

		base := StrLenSlot(key)

		var lenSlot common.Hash
		binary.BigEndian.PutUint64(lenSlot[24:], uint64(len(data))+1)
		stateDB.SetState(contractAddr, base, lenSlot)

		for i := 0; i < len(data); i += 32 {
			chunk := data[i:]
			if len(chunk) > 32 {
				chunk = chunk[:32]
			}
			var slot common.Hash
			copy(slot[:], chunk)
			stateDB.SetState(contractAddr, StrChunkSlot(base, i/32), slot)
		}
		return 0
	}))

	// tos.getStr(key) → string | nil
	L.SetField(tosTable, "getStr", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasSLoad) // length slot
		key := L.CheckString(1)
		base := StrLenSlot(key)

		lenSlot := stateDB.GetState(contractAddr, base)
		if lenSlot == (common.Hash{}) {
			L.Push(lua.LNil)
			return 1
		}
		length := binary.BigEndian.Uint64(lenSlot[24:]) - 1
		if numChunks := uint64((int(length) + 31) / 32); numChunks > 0 {
			chargePrimGas(numChunks * gasSLoad) // data chunks
		}

		data := make([]byte, length)
		for i := 0; i < int(length); i += 32 {
			slot := stateDB.GetState(contractAddr, StrChunkSlot(base, i/32))
			copy(data[i:], slot[:])
		}
		L.Push(lua.LString(string(data)))
		return 1
	}))

	// ── Mapping storage ───────────────────────────────────────────────────────
	//
	// Named mappings provide collision-resistant multi-key storage.
	// They model Solidity mappings (including nested) without a type system.
	//
	//   Single-level:   tos.mapSet("balance", addr, amount)
	//                   tos.mapGet("balance", addr)
	//
	//   Nested (2-key): tos.mapSet("allowance", owner, spender, amount)
	//                   tos.mapGet("allowance", owner, spender)
	//
	// Keys are arbitrary strings (addresses, numbers, names).
	// The slot derivation is injection-safe: each key is keccak256-hashed
	// before mixing, so concatenation attacks are impossible.

	// tos.mapGet(mapName, key1 [, key2, ...]) → LNumber | nil
	//   Reads a uint256 value from a named mapping at the given key path.
	L.SetField(tosTable, "mapGet", L.NewFunction(func(L *lua.LState) int {
		nArgs := L.GetTop()
		if nArgs < 2 {
			L.ArgError(1, "mapGet requires at least 2 arguments (mapName, key)")
			return 0
		}
		chargePrimGas(gasSLoad)
		mapName := L.CheckString(1)
		keys := make([]string, nArgs-1)
		for i := 2; i <= nArgs; i++ {
			keys[i-2] = L.CheckString(i)
		}
		val := stateDB.GetState(contractAddr, MapSlot(mapName, keys))
		if val == (common.Hash{}) {
			L.Push(lua.LNil)
			return 1
		}
		L.Push(luBig(new(big.Int).SetBytes(val[:])))
		return 1
	}))

	// tos.mapSet(mapName, key1 [, key2, ...], value)
	//   Stores a uint256 value in a named mapping at the given key path.
	//   The last argument is always the value; all preceding args after
	//   mapName are treated as keys.
	L.SetField(tosTable, "mapSet", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.mapSet: state modification not allowed in staticcall")
			return 0
		}
		nArgs := L.GetTop()
		if nArgs < 3 {
			L.ArgError(1, "mapSet requires at least 3 arguments (mapName, key, value)")
			return 0
		}
		chargePrimGas(gasSStore)
		mapName := L.CheckString(1)
		keys := make([]string, nArgs-2)
		for i := 2; i <= nArgs-1; i++ {
			keys[i-2] = L.CheckString(i)
		}
		bi, err := parseUint256Value(L.CheckAny(nArgs))
		if err != nil {
			L.RaiseError("tos.mapSet: %s", err.Error())
			return 0
		}
		var slot common.Hash
		bi.FillBytes(slot[:])
		stateDB.SetState(contractAddr, MapSlot(mapName, keys), slot)
		return 0
	}))

	// tos.mapGetStr(mapName, key1 [, key2, ...]) → string | nil
	//   Reads a string value from a named mapping at the given key path.
	L.SetField(tosTable, "mapGetStr", L.NewFunction(func(L *lua.LState) int {
		nArgs := L.GetTop()
		if nArgs < 2 {
			L.ArgError(1, "mapGetStr requires at least 2 arguments (mapName, key)")
			return 0
		}
		chargePrimGas(gasSLoad) // length slot
		mapName := L.CheckString(1)
		keys := make([]string, nArgs-1)
		for i := 2; i <= nArgs; i++ {
			keys[i-2] = L.CheckString(i)
		}
		base := MapStrLenSlot(mapName, keys)
		lenSlot := stateDB.GetState(contractAddr, base)
		if lenSlot == (common.Hash{}) {
			L.Push(lua.LNil)
			return 1
		}
		length := binary.BigEndian.Uint64(lenSlot[24:]) - 1
		if numChunks := uint64((int(length) + 31) / 32); numChunks > 0 {
			chargePrimGas(numChunks * gasSLoad) // data chunks
		}
		data := make([]byte, length)
		for i := 0; i < int(length); i += 32 {
			chunk := stateDB.GetState(contractAddr, StrChunkSlot(base, i/32))
			copy(data[i:], chunk[:])
		}
		L.Push(lua.LString(string(data)))
		return 1
	}))

	// tos.mapSetStr(mapName, key1 [, key2, ...], value)
	//   Stores a string value in a named mapping at the given key path.
	//   The last argument is always the string value.
	L.SetField(tosTable, "mapSetStr", L.NewFunction(func(L *lua.LState) int {
		if ctx.Readonly {
			L.RaiseError("tos.mapSetStr: state modification not allowed in staticcall")
			return 0
		}
		nArgs := L.GetTop()
		if nArgs < 3 {
			L.ArgError(1, "mapSetStr requires at least 3 arguments (mapName, key, value)")
			return 0
		}
		mapName := L.CheckString(1)
		keys := make([]string, nArgs-2)
		for i := 2; i <= nArgs-1; i++ {
			keys[i-2] = L.CheckString(i)
		}
		val := L.CheckString(nArgs)
		data := []byte(val)
		numChunks := uint64((len(data) + 31) / 32)
		chargePrimGas(gasSStore + numChunks*gasSStore) // len slot + data chunks
		base := MapStrLenSlot(mapName, keys)
		var lenSlot common.Hash
		binary.BigEndian.PutUint64(lenSlot[24:], uint64(len(data))+1)
		stateDB.SetState(contractAddr, base, lenSlot)
		for i := 0; i < len(data); i += 32 {
			chunk := data[i:]
			if len(chunk) > 32 {
				chunk = chunk[:32]
			}
			var s common.Hash
			copy(s[:], chunk)
			stateDB.SetState(contractAddr, StrChunkSlot(base, i/32), s)
		}
		return 0
	}))

	// tos.mapping(name [, depth]) → read/write proxy table for uint256 values
	//   depth=1 (default):
	//     proxy[key]       → uint256 string or nil  (same slot as tos.mapGet(name, key))
	//     proxy[key] = val → stores uint256          (same slot as tos.mapSet(name, key, val))
	//   depth=2:
	//     proxy[k1][k2]       → uint256 string or nil
	//     proxy[k1][k2] = val → stores uint256
	//
	//   Enables idiomatic table syntax for on-chain named mappings:
	//
	//     local bal = tos.mapping("balance")
	//     bal["alice"] = 1000
	//     local v = bal["alice"]  -- v == "1000"
	//
	//     local allowance = tos.mapping("allowance", 2)
	//     allowance["owner"]["spender"] = 500
	//     local a = allowance["owner"]["spender"]  -- a == "500"
	//
	//   Slot derivation is identical to tos.mapGet/tos.mapSet — fully interchangeable.
	L.SetField(tosTable, "mapping", L.NewFunction(func(L *lua.LState) int {
		mapName := L.CheckString(1)
		depth := L.OptInt(2, 1)
		if depth != 1 && depth != 2 {
			L.RaiseError("tos.mapping: depth must be 1 or 2")
			return 0
		}

		// makeLevel2 creates the second-level proxy used by depth=2 mappings.
		makeLevel2 := func(key1 string) *lua.LTable {
			sub := L.NewTable()
			subMt := L.NewTable()
			L.SetField(subMt, "__index", L.NewFunction(func(L *lua.LState) int {
				key2 := L.CheckString(2)
				chargePrimGas(gasSLoad)
				val := stateDB.GetState(contractAddr, MapSlot(mapName, []string{key1, key2}))
				if val == (common.Hash{}) {
					L.Push(lua.LNil)
				} else {
					L.Push(luBig(new(big.Int).SetBytes(val[:])))
				}
				return 1
			}))
			L.SetField(subMt, "__newindex", L.NewFunction(func(L *lua.LState) int {
				if ctx.Readonly {
					L.RaiseError("mapping: state modification not allowed in staticcall")
					return 0
				}
				key2 := L.CheckString(2)
				bi, err := parseUint256Value(L.CheckAny(3))
				if err != nil {
					L.RaiseError("mapping.__newindex: %s", err.Error())
					return 0
				}
				chargePrimGas(gasSStore)
				var slot common.Hash
				bi.FillBytes(slot[:])
				stateDB.SetState(contractAddr, MapSlot(mapName, []string{key1, key2}), slot)
				return 0
			}))
			L.SetMetatable(sub, subMt)
			return sub
		}

		proxy := L.NewTable()
		mt := L.NewTable()
		if depth == 1 {
			L.SetField(mt, "__index", L.NewFunction(func(L *lua.LState) int {
				key := L.CheckString(2)
				chargePrimGas(gasSLoad)
				val := stateDB.GetState(contractAddr, MapSlot(mapName, []string{key}))
				if val == (common.Hash{}) {
					L.Push(lua.LNil)
				} else {
					L.Push(luBig(new(big.Int).SetBytes(val[:])))
				}
				return 1
			}))
			L.SetField(mt, "__newindex", L.NewFunction(func(L *lua.LState) int {
				if ctx.Readonly {
					L.RaiseError("mapping: state modification not allowed in staticcall")
					return 0
				}
				key := L.CheckString(2)
				bi, err := parseUint256Value(L.CheckAny(3))
				if err != nil {
					L.RaiseError("mapping.__newindex: %s", err.Error())
					return 0
				}
				chargePrimGas(gasSStore)
				var slot common.Hash
				bi.FillBytes(slot[:])
				stateDB.SetState(contractAddr, MapSlot(mapName, []string{key}), slot)
				return 0
			}))
		} else {
			L.SetField(mt, "__index", L.NewFunction(func(L *lua.LState) int {
				key1 := L.CheckString(2)
				L.Push(makeLevel2(key1))
				return 1
			}))
			L.SetField(mt, "__newindex", L.NewFunction(func(L *lua.LState) int {
				L.RaiseError("mapping: depth=2 requires second key (use m[k1][k2])")
				return 0
			}))
		}
		L.SetMetatable(proxy, mt)
		L.Push(proxy)
		return 1
	}))

	// tos.mappingStr(name [, depth]) → read/write proxy table for string values
	//   depth=1: proxy[key]         ↔ mapGetStr/mapSetStr(name, key)
	//   depth=2: proxy[k1][k2]      ↔ mapGetStr/mapSetStr(name, k1, k2)
	L.SetField(tosTable, "mappingStr", L.NewFunction(func(L *lua.LState) int {
		mapName := L.CheckString(1)
		depth := L.OptInt(2, 1)
		if depth != 1 && depth != 2 {
			L.RaiseError("tos.mappingStr: depth must be 1 or 2")
			return 0
		}

		mapGetStrByKeys := func(keys []string) int {
			chargePrimGas(gasSLoad) // length slot
			base := MapStrLenSlot(mapName, keys)
			lenSlot := stateDB.GetState(contractAddr, base)
			if lenSlot == (common.Hash{}) {
				L.Push(lua.LNil)
				return 1
			}
			length := binary.BigEndian.Uint64(lenSlot[24:]) - 1
			if numChunks := uint64((int(length) + 31) / 32); numChunks > 0 {
				chargePrimGas(numChunks * gasSLoad)
			}
			data := make([]byte, length)
			for i := 0; i < int(length); i += 32 {
				chunk := stateDB.GetState(contractAddr, StrChunkSlot(base, i/32))
				copy(data[i:], chunk[:])
			}
			L.Push(lua.LString(string(data)))
			return 1
		}
		mapSetStrByKeys := func(keys []string, val string) int {
			if ctx.Readonly {
				L.RaiseError("mappingStr: state modification not allowed in staticcall")
				return 0
			}
			data := []byte(val)
			numChunks := uint64((len(data) + 31) / 32)
			chargePrimGas(gasSStore + numChunks*gasSStore)
			base := MapStrLenSlot(mapName, keys)
			var lenSlot common.Hash
			binary.BigEndian.PutUint64(lenSlot[24:], uint64(len(data))+1)
			stateDB.SetState(contractAddr, base, lenSlot)
			for i := 0; i < len(data); i += 32 {
				chunk := data[i:]
				if len(chunk) > 32 {
					chunk = chunk[:32]
				}
				var s common.Hash
				copy(s[:], chunk)
				stateDB.SetState(contractAddr, StrChunkSlot(base, i/32), s)
			}
			return 0
		}

		makeLevel2 := func(key1 string) *lua.LTable {
			sub := L.NewTable()
			subMt := L.NewTable()
			L.SetField(subMt, "__index", L.NewFunction(func(L *lua.LState) int {
				key2 := L.CheckString(2)
				return mapGetStrByKeys([]string{key1, key2})
			}))
			L.SetField(subMt, "__newindex", L.NewFunction(func(L *lua.LState) int {
				key2 := L.CheckString(2)
				val := L.CheckString(3)
				return mapSetStrByKeys([]string{key1, key2}, val)
			}))
			L.SetMetatable(sub, subMt)
			return sub
		}

		proxy := L.NewTable()
		mt := L.NewTable()
		if depth == 1 {
			L.SetField(mt, "__index", L.NewFunction(func(L *lua.LState) int {
				key := L.CheckString(2)
				return mapGetStrByKeys([]string{key})
			}))
			L.SetField(mt, "__newindex", L.NewFunction(func(L *lua.LState) int {
				key := L.CheckString(2)
				val := L.CheckString(3)
				return mapSetStrByKeys([]string{key}, val)
			}))
		} else {
			L.SetField(mt, "__index", L.NewFunction(func(L *lua.LState) int {
				key1 := L.CheckString(2)
				L.Push(makeLevel2(key1))
				return 1
			}))
			L.SetField(mt, "__newindex", L.NewFunction(func(L *lua.LState) int {
				L.RaiseError("mappingStr: depth=2 requires second key (use m[k1][k2])")
				return 0
			}))
		}
		L.SetMetatable(proxy, mt)
		L.Push(proxy)
		return 1
	}))

	// ── Return data ───────────────────────────────────────────────────────────

	// tos.result("type1", val1, ...)
	//   Sets the ABI-encoded return data for this call and immediately stops
	//   execution.  The caller receives the data as the second return value of
	//   tos.call().
	//
	//   Behaviour is analogous to Solidity's `return` statement:
	//   state changes are committed (not reverted), gas used is accounted, and
	//   the encoded data is delivered to the caller.
	//
	//   Note: `return` is a Lua keyword; use `tos.result(...)` instead.
	//
	//   Example (callee):
	//     tos.dispatch({
	//       ["balanceOf(address)"] = function(addr)
	//         tos.result("uint256", tos.balance(addr))
	//       end,
	//     })
	//
	//   Example (caller):
	//     local sel  = tos.selector("balanceOf(address)")
	//     local ok, data = tos.call(tokenAddr, 0, sel)
	//     tos.require(ok, "balanceOf failed")
	//     local bal = tos.abi.decode(data, "uint256")
	L.SetField(tosTable, "result", L.NewFunction(func(L *lua.LState) int {
		data, err := abiEncodeBytes(L, 1)
		if err != nil {
			L.RaiseError("tos.result: %v", err)
			return 0
		}
		capturedResult = data
		hasResult = true
		// Raise the typed sentinel to stop execution cleanly.
		// Execute catches this via isResultSignal and converts it to a (data, nil) return.
		// Using a typed LUserData (unexported Go pointer) instead of a plain string
		// prevents contract code from forging the signal with error("known-string").
		ud := L.NewUserData()
		ud.Value = lvmResultSentinel
		L.Error(ud, 0)
		return 0
	}))

	// ── Package calls ─────────────────────────────────────────────────────────

	// tos.package_call(addr, contractName, calldata) → bool, retdata
	//
	// Low-level dispatch to a named contract within a .tor package at addr.
	// Automatically prepends the 4-byte dispatch tag (keccak256("pkg:"+contractName)[:4])
	// to the provided calldata before calling tos.call.
	//
	// calldata should be selector + abi.encode(args...) — no dispatch tag.
	// This is the primitive emitted by the TOL compiler for cross-package calls
	// (__tol_host_package_call in the TOL lowering prelude).
	//
	// Example (from TOL-compiled code):
	//   local ok, ret = tos.package_call("0xabc...", "AgentRegistry", calldata)
	L.SetField(tosTable, "package_call", L.NewFunction(func(L *lua.LState) int {
		if ctx.Depth >= maxCallDepth {
			L.RaiseError("tos.package_call: max call depth (%d) exceeded", maxCallDepth)
			return 0
		}
		addrHex := L.CheckString(1)
		contractName := L.CheckString(2)
		calleeAddr := common.HexToAddress(addrHex)
		currentBlock := uint64(0)
		if blockCtx.BlockNumber != nil {
			currentBlock = blockCtx.BlockNumber.Uint64()
		}
		if err := lease.CheckCallable(stateDB, calleeAddr, currentBlock, chainConfig); err != nil {
			L.Push(lua.LFalse)
			L.Push(lua.LNil)
			return 2
		}

		var callData []byte
		if L.GetTop() >= 3 && L.Get(3) != lua.LNil {
			callData = common.FromHex(L.CheckString(3))
		}

		// Prepend dispatch tag: keccak256("pkg:"+contractName)[:4]
		tag := crypto.Keccak256([]byte("pkg:" + contractName))[:4]
		fullData := append(tag, callData...)

		parentUsedNow := L.GasUsed()
		totalUsed := parentUsedNow + totalChildGas + primGasCharged
		if totalUsed >= gasLimit {
			L.RaiseError("tos.package_call: out of gas")
			return 0
		}
		available := gasLimit - totalUsed
		childGasLimit := available - available/64 // keep 1/64 gas in parent frame

		calleeCode := stateDB.GetCode(calleeAddr)
		if len(calleeCode) == 0 {
			// No code at address — not a package.
			L.Push(lua.LFalse)
			L.Push(lua.LNil)
			return 2
		}

		calleeSnap := stateDB.Snapshot()
		childCtx := CallCtx{
			From:     contractAddr,
			To:       calleeAddr,
			Value:    new(big.Int),
			Data:     fullData,
			Depth:    ctx.Depth + 1,
			TxOrigin: ctx.TxOrigin,
			TxPrice:  ctx.TxPrice,
			Readonly: ctx.Readonly,
			GoCtx:    ctx.GoCtx, // propagate RPC timeout
		}
		childGasUsed, childReturnData, childRevertData, childErr := Execute(stateDB, blockCtx, chainConfig, childCtx, calleeCode, childGasLimit)
		totalChildGas += childGasUsed

		newTotalUsed := parentUsedNow + totalChildGas + primGasCharged
		if newTotalUsed < gasLimit {
			L.SetGasLimit(parentUsedNow + (gasLimit - newTotalUsed))
		} else {
			L.SetGasLimit(parentUsedNow)
		}

		if childErr != nil {
			stateDB.RevertToSnapshot(calleeSnap)
			L.Push(lua.LFalse)
			if len(childRevertData) > 0 {
				L.Push(lua.LString("0x" + common.Bytes2Hex(childRevertData)))
			} else {
				L.Push(lua.LNil)
			}
			return 2
		}
		L.Push(lua.LTrue)
		if len(childReturnData) > 0 {
			L.Push(lua.LString("0x" + common.Bytes2Hex(childReturnData)))
		} else {
			L.Push(lua.LNil)
		}
		return 2
	}))

	// tos.package(addr) → proxy table
	//
	// Returns a dynamic proxy for calling contracts within a .tor package at addr.
	// Usage:
	//   local ok, ret = tos.package("0xabc").AgentRegistry.call("0xSELECTOR...calldata")
	//
	// proxy.ContractName         → contract proxy table (dispatch tag auto-derived)
	// contractProxy.call(data)   → tos.package_call(addr, contractName, data)
	L.SetField(tosTable, "package", L.NewFunction(func(L *lua.LState) int {
		addrHex := L.CheckString(1)

		// Build a package proxy: __index returns a per-contract proxy.
		pkgProxy := L.NewTable()
		pkgMeta := L.NewTable()
		L.SetField(pkgMeta, "__index", L.NewFunction(func(L *lua.LState) int {
			contractName := L.CheckString(2)

			// Build a contract proxy: .call(data) dispatches to contractName.
			contractProxy := L.NewTable()
			L.SetField(contractProxy, "call", L.NewFunction(func(L *lua.LState) int {
				var calldataHex string
				if L.GetTop() >= 1 && L.Get(1) != lua.LNil {
					calldataHex = L.CheckString(1)
				}
				// Delegate to tos.package_call.
				pkgCallFn := L.GetField(tosTable, "package_call")
				L.Push(pkgCallFn)
				L.Push(lua.LString(addrHex))
				L.Push(lua.LString(contractName))
				L.Push(lua.LString(calldataHex))
				if err := L.PCall(3, 2, nil); err != nil {
					L.RaiseError("tos.package: %v", err)
					return 0
				}
				return 2
			}))
			L.Push(contractProxy)
			return 1
		}))
		L.SetMetatable(pkgProxy, pkgMeta)
		L.Push(pkgProxy)
		return 1
	}))

	// ── Encrypted ciphertext operations (tos.ciphertext.*) ───────────────────
	registerCiphertextTable(L, tosTable, chargePrimGas, ctx.Readonly, proofBundle, stateDB, contractAddr)

	// ── Inject globals ────────────────────────────────────────────────────────

	L.SetGlobal("tos", tosTable)

	// Make every tos.* field also available as a bare global.
	// tos.caller / caller, tos.sstore() / sstore(), tos.block.number / block.number …
	tosTable.ForEach(func(k, v lua.LValue) {
		if name, ok := k.(lua.LString); ok {
			L.SetGlobal(string(name), v)
		}
	})

	// ── Execute ───────────────────────────────────────────────────────────────

	// Accept both pre-compiled bytecode and raw Lua source.
	var fn *lua.LFunction
	var loadErr error
	if lua.IsBytecode(src) {
		fn, loadErr = L.LoadBytecode(src)
	} else {
		fn, loadErr = L.Load(bytes.NewReader(src), "contract")
	}
	if loadErr != nil {
		total := L.GasUsed() + totalChildGas + primGasCharged
		return total, nil, nil, loadErr
	}
	L.Push(fn)
	if err := L.PCall(0, lua.MultRet, nil); err != nil {
		total := L.GasUsed() + totalChildGas + primGasCharged
		// Check for clean return via tos.result().
		if hasResult && isResultSignal(err) {
			return total, capturedResult, nil, nil
		}
		// Check for structured revert error via tos.revert("ErrorName", ...).
		if hasRevertData && isRevertSignal(err) {
			return total, nil, capturedRevertData, fmt.Errorf("revert with data")
		}
		return total, nil, nil, err
	}

	// ── Post-module dispatch ──────────────────────────────────────────────────
	// For TOL-compiled contracts the module sets tos.oncreate / tos.oninvoke as
	// Lua closures.  Call the appropriate one now.
	// Raw Lua contracts dispatch inline (tos.dispatch / tos.oncreate(fn)) and
	// expose a Go function at tos.oncreate (IsG=true), so the check below is a
	// no-op for them.
	if tosVal := L.GetGlobal("tos"); tosVal != lua.LNil {
		if tosT, ok := tosVal.(*lua.LTable); ok {
			if dispatchErr := tolDispatch(L, tosT, ctx, &capturedResult, &hasResult, &capturedRevertData, &hasRevertData); dispatchErr != nil {
				total := L.GasUsed() + totalChildGas + primGasCharged
				if hasResult && isResultSignal(dispatchErr) {
					return total, capturedResult, nil, nil
				}
				if hasRevertData && isRevertSignal(dispatchErr) {
					return total, nil, capturedRevertData, fmt.Errorf("revert with data")
				}
				return total, nil, nil, dispatchErr
			}
		}
	}

	return L.GasUsed() + totalChildGas + primGasCharged, nil, nil, nil
}

// tolDispatch calls tos.oncreate() or tos.oninvoke(selector) if a Lua function
// is registered — i.e. for TOL-compiled contracts.
// Returns nil if no dispatch is needed (raw Lua contract or no handler set).
func tolDispatch(L *lua.LState, tosTable *lua.LTable, ctx CallCtx, capturedResult *[]byte, hasResult *bool, capturedRevertData *[]byte, hasRevertData *bool) error {
	if ctx.IsCreate {
		fn := L.GetField(tosTable, "oncreate")
		luaFn, ok := fn.(*lua.LFunction)
		if !ok || luaFn.IsG {
			return nil // Go function or nil → raw Lua contract, already ran inline
		}
		L.Push(luaFn)
		return L.PCall(0, lua.MultRet, nil)
	}
	fn := L.GetField(tosTable, "oninvoke")
	luaFn, ok := fn.(*lua.LFunction)
	if !ok || luaFn.IsG {
		return nil // nil or Go function → raw Lua contract, already dispatched inline
	}
	var selector lua.LValue
	if len(ctx.Data) >= 4 {
		selector = lua.LString("0x" + hex.EncodeToString(ctx.Data[:4]))
	} else {
		selector = lua.LNil
	}
	L.Push(luaFn)
	L.Push(selector)
	return L.PCall(1, lua.MultRet, nil)
}

// applyLua executes the Lua contract code (source or bytecode) stored at the
// destination address.
//
// Gas model:
//   - Execute is capped to st.gas total opcodes (including nested calls).
//   - On success, st.gas is decremented by total opcodes consumed.
//
// State model:
//   - A StateDB snapshot is taken before execution.
//   - Any Lua error (including OOG) reverts all state changes.
//   - msg.Value is transferred to contractAddr before the script runs.
