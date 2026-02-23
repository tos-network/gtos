package kvstore

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tos-network/gtos/rlp"
)

const (
	putPayloadPrefix  = "GTOSKV1"
	putPayloadVersion = uint8(1)
)

type putEnvelope struct {
	Version   uint8
	Namespace string
	Key       []byte
	Value     []byte
	TTL       uint64
}

// EncodePutPayload serializes KV put payload bytes for tx.Data.
func EncodePutPayload(namespace string, key, value []byte, ttl uint64) ([]byte, error) {
	if strings.TrimSpace(namespace) == "" {
		return nil, ErrInvalidNamespace
	}
	if ttl == 0 {
		return nil, ErrInvalidTTL
	}
	env := putEnvelope{
		Version:   putPayloadVersion,
		Namespace: namespace,
		Key:       key,
		Value:     value,
		TTL:       ttl,
	}
	body, err := rlp.EncodeToBytes(&env)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPutPayload, err)
	}
	out := make([]byte, len(putPayloadPrefix)+len(body))
	copy(out, []byte(putPayloadPrefix))
	copy(out[len(putPayloadPrefix):], body)
	return out, nil
}

// DecodePutPayload parses tx.Data bytes into a KV put payload.
func DecodePutPayload(data []byte) (*PutPayload, error) {
	if len(data) <= len(putPayloadPrefix) || !bytes.Equal(data[:len(putPayloadPrefix)], []byte(putPayloadPrefix)) {
		return nil, ErrInvalidPutPayload
	}
	var env putEnvelope
	if err := rlp.DecodeBytes(data[len(putPayloadPrefix):], &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPutPayload, err)
	}
	if env.Version != putPayloadVersion {
		return nil, ErrInvalidPutPayload
	}
	if strings.TrimSpace(env.Namespace) == "" {
		return nil, ErrInvalidNamespace
	}
	if env.TTL == 0 {
		return nil, ErrInvalidTTL
	}
	return &PutPayload{
		Namespace: env.Namespace,
		Key:       env.Key,
		Value:     env.Value,
		TTL:       env.TTL,
	}, nil
}
