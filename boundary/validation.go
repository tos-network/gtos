package boundary

import (
	"errors"
	"fmt"

	"github.com/tos-network/gtos/common"
)

var (
	errEmptyID        = errors.New("id must not be empty")
	errEmptyAction    = errors.New("action must not be empty")
	errZeroAddress    = errors.New("address must not be zero")
	errInvalidStatus  = errors.New("invalid status")
	errZeroTimestamp   = errors.New("timestamp must not be zero")
	errExpiresBeforeCreated = errors.New("expires_at must be after created_at")
)

var zeroAddress common.Address

func validateTimestamps(created, expires uint64) error {
	if created == 0 {
		return fmt.Errorf("created_at: %w", errZeroTimestamp)
	}
	if expires == 0 {
		return fmt.Errorf("expires_at: %w", errZeroTimestamp)
	}
	if expires <= created {
		return errExpiresBeforeCreated
	}
	return nil
}

var validIntentStatuses = map[IntentStatus]bool{
	IntentPending:   true,
	IntentPlanning:  true,
	IntentApproved:  true,
	IntentExecuting: true,
	IntentSettled:   true,
	IntentFailed:    true,
	IntentExpired:   true,
	IntentCancelled: true,
}

var validPlanStatuses = map[PlanStatus]bool{
	PlanDraft:     true,
	PlanReady:     true,
	PlanApproved:  true,
	PlanExecuting: true,
	PlanCompleted: true,
	PlanFailed:    true,
	PlanExpired:   true,
}

var validApprovalStatuses = map[ApprovalStatus]bool{
	ApprovalPending: true,
	ApprovalGranted: true,
	ApprovalDenied:  true,
	ApprovalRevoked: true,
	ApprovalExpired: true,
}

var validReceiptStatuses = map[ReceiptStatus]bool{
	ReceiptSuccess:  true,
	ReceiptFailed:   true,
	ReceiptReverted: true,
}

// Validate checks that required fields are set and values are consistent.
func (e *IntentEnvelope) Validate() error {
	if e.IntentID == "" {
		return fmt.Errorf("intent_id: %w", errEmptyID)
	}
	if e.Action == "" {
		return errEmptyAction
	}
	if e.Requester == zeroAddress {
		return fmt.Errorf("requester: %w", errZeroAddress)
	}
	if !validIntentStatuses[e.Status] {
		return fmt.Errorf("status %q: %w", e.Status, errInvalidStatus)
	}
	return validateTimestamps(e.CreatedAt, e.ExpiresAt)
}

// Validate checks that required fields are set and values are consistent.
func (p *PlanRecord) Validate() error {
	if p.PlanID == "" {
		return fmt.Errorf("plan_id: %w", errEmptyID)
	}
	if p.IntentID == "" {
		return fmt.Errorf("intent_id: %w", errEmptyID)
	}
	if p.Provider == zeroAddress {
		return fmt.Errorf("provider: %w", errZeroAddress)
	}
	if !validPlanStatuses[p.Status] {
		return fmt.Errorf("status %q: %w", p.Status, errInvalidStatus)
	}
	return validateTimestamps(p.CreatedAt, p.ExpiresAt)
}

// Validate checks that required fields are set and values are consistent.
func (a *ApprovalRecord) Validate() error {
	if a.ApprovalID == "" {
		return fmt.Errorf("approval_id: %w", errEmptyID)
	}
	if a.IntentID == "" {
		return fmt.Errorf("intent_id: %w", errEmptyID)
	}
	if a.PlanID == "" {
		return fmt.Errorf("plan_id: %w", errEmptyID)
	}
	if a.Approver == zeroAddress {
		return fmt.Errorf("approver: %w", errZeroAddress)
	}
	if !validApprovalStatuses[a.Status] {
		return fmt.Errorf("status %q: %w", a.Status, errInvalidStatus)
	}
	return validateTimestamps(a.CreatedAt, a.ExpiresAt)
}

// Validate checks that required fields are set and values are consistent.
func (r *ExecutionReceipt) Validate() error {
	if r.ReceiptID == "" {
		return fmt.Errorf("receipt_id: %w", errEmptyID)
	}
	if r.IntentID == "" {
		return fmt.Errorf("intent_id: %w", errEmptyID)
	}
	if r.PlanID == "" {
		return fmt.Errorf("plan_id: %w", errEmptyID)
	}
	if r.From == zeroAddress {
		return fmt.Errorf("from: %w", errZeroAddress)
	}
	if r.To == zeroAddress {
		return fmt.Errorf("to: %w", errZeroAddress)
	}
	if !validReceiptStatuses[r.Status] {
		return fmt.Errorf("status %q: %w", r.Status, errInvalidStatus)
	}
	if r.SettledAt == 0 {
		return fmt.Errorf("settled_at: %w", errZeroTimestamp)
	}
	return nil
}
