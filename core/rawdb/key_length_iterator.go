package rawdb

import "github.com/tos-network/gtos/tosdb"

// KeyLengthIterator is a wrapper for a database iterator that ensures only key-value pairs
// with a specific key length will be returned.
type KeyLengthIterator struct {
	requiredKeyLength int
	tosdb.Iterator
}

// NewKeyLengthIterator returns a wrapped version of the iterator that will only return key-value
// pairs where keys with a specific key length will be returned.
func NewKeyLengthIterator(it tosdb.Iterator, keyLen int) tosdb.Iterator {
	return &KeyLengthIterator{
		Iterator:          it,
		requiredKeyLength: keyLen,
	}
}

func (it *KeyLengthIterator) Next() bool {
	// Return true as soon as a key with the required key length is discovered
	for it.Iterator.Next() {
		if len(it.Iterator.Key()) == it.requiredKeyLength {
			return true
		}
	}

	// Return false when we exhaust the keys in the underlying iterator.
	return false
}
