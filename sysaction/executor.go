package sysaction

import (
	"fmt"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/params"
)

// Context carries information available to a system-action handler.
type Context struct {
	From        common.Address
	Value       *big.Int
	BlockNumber *big.Int
	StateDB     vm.StateDB
	ChainConfig *params.ChainConfig
}

// Handler is implemented by agent and staking sub-systems.
type Handler interface {
	CanHandle(kind ActionKind) bool
	Handle(ctx *Context, sa *SysAction) error
}

// Registry holds registered handlers.
type Registry struct{ handlers []Handler }

// DefaultRegistry is the process-wide handler registry.
var DefaultRegistry = &Registry{}

// Register adds a handler to the registry.
func (r *Registry) Register(h Handler) { r.handlers = append(r.handlers, h) }

// Msg is the minimal message interface for Execute, satisfied by core.Message.
type Msg interface {
	From()  common.Address
	To()    *common.Address
	Value() *big.Int
	Data()  []byte
}

// Execute processes a system action from msg and dispatches to a registered handler.
// Returns (gasUsed, error) — called from core/state_transition.go.
func Execute(msg Msg, db vm.StateDB) (uint64, error) {
	sa, err := Decode(msg.Data())
	if err != nil {
		return params.SysActionGas, err
	}
	ctx := &Context{
		From:    msg.From(),
		Value:   msg.Value(),
		StateDB: db,
	}
	for _, h := range DefaultRegistry.handlers {
		if h.CanHandle(sa.Action) {
			return params.SysActionGas, h.Handle(ctx, sa)
		}
	}
	return params.SysActionGas, fmt.Errorf("unknown system action: %q", sa.Action)
}

// ExecuteWithContext dispatches using a pre-built Context (used in tests).
func ExecuteWithContext(ctx *Context, data []byte) error {
	sa, err := Decode(data)
	if err != nil {
		return err
	}
	for _, h := range DefaultRegistry.handlers {
		if h.CanHandle(sa.Action) {
			return h.Handle(ctx, sa)
		}
	}
	return fmt.Errorf("unknown system action: %q", sa.Action)
}
