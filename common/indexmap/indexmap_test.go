package indexmap

import (
	"fmt"
	"testing"
)

func TestSetGetHas(t *testing.T) {
	m := New[string, int](4)
	m.Set("a", 1)
	m.Set("b", 2)
	m.Set("c", 3)

	if m.Len() != 3 {
		t.Fatalf("Len = %d, want 3", m.Len())
	}
	if v, ok := m.Get("b"); !ok || v != 2 {
		t.Fatalf("Get(b) = (%d, %v), want (2, true)", v, ok)
	}
	if !m.Has("c") {
		t.Fatal("Has(c) = false, want true")
	}
	if m.Has("z") {
		t.Fatal("Has(z) = true, want false")
	}
}

func TestSetUpdate(t *testing.T) {
	m := New[string, int](4)
	m.Set("a", 1)
	m.Set("b", 2)
	m.Set("a", 10) // update

	if m.Len() != 2 {
		t.Fatalf("Len = %d, want 2", m.Len())
	}
	if v, _ := m.Get("a"); v != 10 {
		t.Fatalf("Get(a) = %d, want 10", v)
	}
	// insertion order preserved: a before b
	keys := m.Keys()
	if keys[0] != "a" || keys[1] != "b" {
		t.Fatalf("Keys = %v, want [a b]", keys)
	}
}

func TestDelete(t *testing.T) {
	m := New[string, int](4)
	m.Set("a", 1)
	m.Set("b", 2)
	m.Set("c", 3)

	if !m.Delete("b") {
		t.Fatal("Delete(b) = false, want true")
	}
	if m.Delete("b") {
		t.Fatal("Delete(b) again = true, want false")
	}
	if m.Len() != 2 {
		t.Fatalf("Len = %d, want 2", m.Len())
	}

	keys := m.Keys()
	if len(keys) != 2 || keys[0] != "a" || keys[1] != "c" {
		t.Fatalf("Keys = %v, want [a c]", keys)
	}
}

func TestDeleteHead(t *testing.T) {
	m := New[string, int](4)
	m.Set("a", 1)
	m.Set("b", 2)
	m.Delete("a")

	keys := m.Keys()
	if len(keys) != 1 || keys[0] != "b" {
		t.Fatalf("Keys = %v, want [b]", keys)
	}
}

func TestDeleteTail(t *testing.T) {
	m := New[string, int](4)
	m.Set("a", 1)
	m.Set("b", 2)
	m.Delete("b")

	keys := m.Keys()
	if len(keys) != 1 || keys[0] != "a" {
		t.Fatalf("Keys = %v, want [a]", keys)
	}
}

func TestDeleteOnly(t *testing.T) {
	m := New[string, int](4)
	m.Set("a", 1)
	m.Delete("a")

	if m.Len() != 0 {
		t.Fatalf("Len = %d, want 0", m.Len())
	}
	keys := m.Keys()
	if len(keys) != 0 {
		t.Fatalf("Keys = %v, want []", keys)
	}
}

func TestRangeOrder(t *testing.T) {
	m := New[int, string](8)
	for i := 0; i < 100; i++ {
		m.Set(i, fmt.Sprintf("v%d", i))
	}

	var got []int
	m.Range(func(k int, _ string) bool {
		got = append(got, k)
		return true
	})

	for i, k := range got {
		if k != i {
			t.Fatalf("Range[%d] = %d, want %d", i, k, i)
		}
	}
}

func TestRangeEarlyStop(t *testing.T) {
	m := New[int, int](4)
	m.Set(1, 10)
	m.Set(2, 20)
	m.Set(3, 30)

	var visited int
	m.Range(func(k, v int) bool {
		visited++
		return k < 2
	})
	if visited != 2 {
		t.Fatalf("visited = %d, want 2", visited)
	}
}

func TestValues(t *testing.T) {
	m := New[string, int](4)
	m.Set("x", 10)
	m.Set("y", 20)
	m.Set("z", 30)

	vals := m.Values()
	if len(vals) != 3 || vals[0] != 10 || vals[1] != 20 || vals[2] != 30 {
		t.Fatalf("Values = %v, want [10 20 30]", vals)
	}
}

func TestZeroValue(t *testing.T) {
	var m IndexMap[string, int]
	if m.Len() != 0 {
		t.Fatalf("Len = %d, want 0", m.Len())
	}
	if m.Has("x") {
		t.Fatal("Has on zero-value should be false")
	}
	if _, ok := m.Get("x"); ok {
		t.Fatal("Get on zero-value should return false")
	}
	if m.Delete("x") {
		t.Fatal("Delete on zero-value should return false")
	}

	// Set on zero value should work (lazy init)
	m.Set("a", 1)
	if v, ok := m.Get("a"); !ok || v != 1 {
		t.Fatalf("Get(a) = (%d, %v), want (1, true)", v, ok)
	}
}

// TestDeterministicIteration verifies that iteration order is always
// insertion-order, not random like a built-in Go map.
func TestDeterministicIteration(t *testing.T) {
	for run := 0; run < 50; run++ {
		m := New[int, bool](16)
		for i := 0; i < 16; i++ {
			m.Set(i, true)
		}
		keys := m.Keys()
		for i, k := range keys {
			if k != i {
				t.Fatalf("run %d: Keys[%d] = %d, want %d", run, i, k, i)
			}
		}
	}
}

func BenchmarkSet(b *testing.B) {
	m := New[int, int](b.N)
	for i := 0; i < b.N; i++ {
		m.Set(i, i)
	}
}

func BenchmarkGet(b *testing.B) {
	m := New[int, int](b.N)
	for i := 0; i < b.N; i++ {
		m.Set(i, i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Get(i)
	}
}

func BenchmarkRange(b *testing.B) {
	m := New[int, int](1000)
	for i := 0; i < 1000; i++ {
		m.Set(i, i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Range(func(k, v int) bool { return true })
	}
}
