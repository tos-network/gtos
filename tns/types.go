package tns

import "errors"

var (
	ErrTNSAlreadyRegistered = errors.New("tns: name already registered")
	ErrTNSAccountHasName    = errors.New("tns: account already has a registered name")
	ErrTNSInvalidName       = errors.New("tns: invalid name format")
	ErrTNSInsufficientFee   = errors.New("tns: registration fee not met")
)
