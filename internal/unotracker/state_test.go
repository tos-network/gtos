package unotracker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	prev := &State{
		Address:     "0x1234",
		Version:     10,
		BlockNumber: 100,
	}

	if err := Validate(prev, State{
		Address:     "0x1234",
		Version:     10,
		BlockNumber: 101,
	}, false); err != nil {
		t.Fatalf("expected monotonic transition to pass, got %v", err)
	}

	if err := Validate(prev, State{
		Address:     "0x9999",
		Version:     10,
		BlockNumber: 101,
	}, false); err == nil {
		t.Fatal("expected address mismatch error")
	}

	if err := Validate(prev, State{
		Address:     "0x1234",
		Version:     9,
		BlockNumber: 101,
	}, false); err == nil {
		t.Fatal("expected version rollback error")
	}

	if err := Validate(prev, State{
		Address:     "0x1234",
		Version:     9,
		BlockNumber: 101,
	}, true); err != nil {
		t.Fatalf("expected version rollback allowed with reorg flag, got %v", err)
	}

	if err := Validate(prev, State{
		Address:     "0x1234",
		Version:     10,
		BlockNumber: 99,
	}, false); err == nil {
		t.Fatal("expected block rollback error")
	}
}

func TestLoadSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uno", "tracker.json")

	if got, err := Load(path); err != nil || got != nil {
		t.Fatalf("load empty expected (nil,nil), got (%v,%v)", got, err)
	}

	curr := State{
		Address:     "0xabc",
		Balance:     42,
		Version:     7,
		BlockNumber: 88,
	}
	if err := Save(path, curr); err != nil {
		t.Fatalf("save tracker state: %v", err)
	}

	st, err := Load(path)
	if err != nil {
		t.Fatalf("load tracker state: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
	if st.Address != curr.Address || st.Balance != curr.Balance || st.Version != curr.Version || st.BlockNumber != curr.BlockNumber {
		t.Fatalf("state mismatch got=%+v want=%+v", *st, curr)
	}
	if st.UpdatedAt == "" {
		t.Fatal("expected updatedAt to be populated")
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("tracker file missing: %v", err)
	}
}
