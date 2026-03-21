package tosapi

import (
	"context"
	"testing"
)

func TestTolGetCapabilityReturnsNilForEmptyState(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	got, err := api.TolGetCapability(context.Background(), "transfer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for empty state, got %+v", got)
	}
}

func TestTolGetDelegationReturnsNilForEmptyState(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	got, err := api.TolGetDelegation(context.Background(), "0xabc", "0xdef", "0x123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for empty state, got %+v", got)
	}
}

func TestTolGetPackageReturnsNilForEmptyState(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	got, err := api.TolGetPackage(context.Background(), "demo.checkout", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for empty state, got %+v", got)
	}
}

func TestTolGetPublisherReturnsNilForEmptyState(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	got, err := api.TolGetPublisher(context.Background(), "pub-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for empty state, got %+v", got)
	}
}
