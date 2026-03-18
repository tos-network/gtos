// Package indexmap provides a generic ordered map that preserves insertion
// order. Iteration via Range always visits entries in the order they were
// first inserted, which is critical for consensus-deterministic code paths
// where Go's built-in map randomised iteration would cause state-root
// divergence across nodes.
//
// Design: hash map for O(1) lookup + intrusive doubly-linked list for O(1)
// append / remove while preserving insertion order.
package indexmap

// entry is an intrusive doubly-linked list node that also carries the
// key-value pair stored in the map.
type entry[K comparable, V any] struct {
	key        K
	value      V
	prev, next *entry[K, V]
}

// IndexMap is an insertion-ordered map.  All mutating operations are O(1)
// amortised; Range is O(n).  The zero value is ready to use.
type IndexMap[K comparable, V any] struct {
	m          map[K]*entry[K, V]
	head, tail *entry[K, V]
	length     int
}

// New creates an IndexMap with the given initial capacity hint.
func New[K comparable, V any](cap int) *IndexMap[K, V] {
	return &IndexMap[K, V]{m: make(map[K]*entry[K, V], cap)}
}

// init lazily allocates the internal map on first write.
func (om *IndexMap[K, V]) init() {
	if om.m == nil {
		om.m = make(map[K]*entry[K, V])
	}
}

// Len returns the number of entries.
func (om *IndexMap[K, V]) Len() int { return om.length }

// Has reports whether key exists.
func (om *IndexMap[K, V]) Has(key K) bool {
	if om.m == nil {
		return false
	}
	_, ok := om.m[key]
	return ok
}

// Get returns the value for key and whether it was found.
func (om *IndexMap[K, V]) Get(key K) (V, bool) {
	if om.m == nil {
		var zero V
		return zero, false
	}
	if e, ok := om.m[key]; ok {
		return e.value, true
	}
	var zero V
	return zero, false
}

// Set inserts or updates key.  If the key is new it is appended to the end
// of the iteration order; if it already exists its value is updated in place
// and its position is unchanged.
func (om *IndexMap[K, V]) Set(key K, value V) {
	om.init()
	if e, ok := om.m[key]; ok {
		e.value = value
		return
	}
	e := &entry[K, V]{key: key, value: value, prev: om.tail}
	if om.tail != nil {
		om.tail.next = e
	} else {
		om.head = e
	}
	om.tail = e
	om.m[key] = e
	om.length++
}

// Delete removes key and returns whether it existed.
func (om *IndexMap[K, V]) Delete(key K) bool {
	if om.m == nil {
		return false
	}
	e, ok := om.m[key]
	if !ok {
		return false
	}
	om.unlink(e)
	delete(om.m, key)
	om.length--
	return true
}

// Range calls fn for every entry in insertion order.  If fn returns false
// iteration stops early.
func (om *IndexMap[K, V]) Range(fn func(key K, value V) bool) {
	for e := om.head; e != nil; e = e.next {
		if !fn(e.key, e.value) {
			return
		}
	}
}

// Keys returns all keys in insertion order.
func (om *IndexMap[K, V]) Keys() []K {
	out := make([]K, 0, om.length)
	for e := om.head; e != nil; e = e.next {
		out = append(out, e.key)
	}
	return out
}

// Values returns all values in insertion order.
func (om *IndexMap[K, V]) Values() []V {
	out := make([]V, 0, om.length)
	for e := om.head; e != nil; e = e.next {
		out = append(out, e.value)
	}
	return out
}

// unlink removes e from the doubly-linked list.
func (om *IndexMap[K, V]) unlink(e *entry[K, V]) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		om.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		om.tail = e.prev
	}
	e.prev = nil
	e.next = nil
}
