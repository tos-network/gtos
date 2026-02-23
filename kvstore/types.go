// Package kvstore implements TTL-native namespace/key value storage over StateDB.
package kvstore

import "errors"

var (
	ErrInvalidNamespace  = errors.New("kvstore: namespace must not be empty")
	ErrInvalidTTL        = errors.New("kvstore: ttl must be greater than zero")
	ErrTTLOverflow       = errors.New("kvstore: ttl overflows expire block")
	ErrInvalidPutPayload = errors.New("kvstore: invalid kv put payload")
)

// PutPayload is the KV put payload carried inside transaction data.
type PutPayload struct {
	Namespace string
	Key       []byte
	Value     []byte
	TTL       uint64
}

// RecordMeta is the persisted metadata for a KV record.
type RecordMeta struct {
	CreatedAt uint64
	ExpireAt  uint64
	Exists    bool
}
