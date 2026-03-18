package tns

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&tnsHandler{})
}

type tnsHandler struct{}

func (h *tnsHandler) Actions() []sysaction.ActionKind {
	return []sysaction.ActionKind{sysaction.ActionTNSRegister}
}

func (h *tnsHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	return h.handleRegister(ctx, sa)
}

type registerPayload struct {
	Name string `json:"name"`
}

// reservedNames is the set of names that cannot be registered.
var reservedNames = map[string]struct{}{
	"admin": {}, "system": {}, "tos": {}, "root": {},
	"null": {}, "test": {}, "node": {}, "validator": {},
}

// validateName checks the TNS name format rules:
//   - length 3–64
//   - starts with lowercase letter
//   - only a-z, 0-9, '.', '-', '_'
//   - does not end with separator
//   - no consecutive separators
//   - not a reserved word
func validateName(name string) error {
	if len(name) < params.TNSMinNameLen || len(name) > params.TNSMaxNameLen {
		return ErrTNSInvalidName
	}
	if _, reserved := reservedNames[name]; reserved {
		return ErrTNSInvalidName
	}
	runes := []rune(name)
	// Must start with lowercase letter.
	if !unicode.IsLower(runes[0]) || !unicode.IsLetter(runes[0]) {
		return ErrTNSInvalidName
	}
	// Must not end with separator.
	last := runes[len(runes)-1]
	if last == '.' || last == '-' || last == '_' {
		return ErrTNSInvalidName
	}
	// Validate each character and check consecutive separators.
	for i, r := range runes {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
			// No consecutive separators.
			if i > 0 {
				prev := runes[i-1]
				if prev == '.' || prev == '-' || prev == '_' {
					return ErrTNSInvalidName
				}
			}
		default:
			return ErrTNSInvalidName
		}
	}
	return nil
}

func (h *tnsHandler) handleRegister(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	// 1. Registration fee check.
	if ctx.Value.Cmp(params.TNSRegistrationFee) < 0 {
		return ErrTNSInsufficientFee
	}
	// 2. Balance check.
	if ctx.StateDB.GetBalance(ctx.From).Cmp(ctx.Value) < 0 {
		return ErrTNSInsufficientFee
	}

	// 3. Decode and validate name.
	var p registerPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	name := strings.ToLower(p.Name)
	if err := validateName(name); err != nil {
		return err
	}

	// 4. One name per account.
	if HasName(ctx.StateDB, ctx.From) {
		return ErrTNSAccountHasName
	}

	// 5. Name must not be taken.
	nameHash := HashName(name)
	if Resolve(ctx.StateDB, nameHash) != (common.Address{}) {
		return ErrTNSAlreadyRegistered
	}

	// 6. Deduct fee: sender → TNS registry (treasury).
	ctx.StateDB.SubBalance(ctx.From, ctx.Value)
	ctx.StateDB.AddBalance(params.TNSRegistryAddress, ctx.Value)

	// 7. Write both directions of the mapping.
	writeMapping(ctx.StateDB, nameHash, ctx.From)
	return nil
}
