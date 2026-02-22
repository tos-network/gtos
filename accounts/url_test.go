package accounts

import (
	"testing"
)

func TestURLParsing(t *testing.T) {
	url, err := parseURL("https://tos.org")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if url.Scheme != "https" {
		t.Errorf("expected: %v, got: %v", "https", url.Scheme)
	}
	if url.Path != "tos.org" {
		t.Errorf("expected: %v, got: %v", "tos.org", url.Path)
	}

	for _, u := range []string{"tos.org", ""} {
		if _, err = parseURL(u); err == nil {
			t.Errorf("input %v, expected err, got: nil", u)
		}
	}
}

func TestURLString(t *testing.T) {
	url := URL{Scheme: "https", Path: "tos.org"}
	if url.String() != "https://tos.org" {
		t.Errorf("expected: %v, got: %v", "https://tos.org", url.String())
	}

	url = URL{Scheme: "", Path: "tos.org"}
	if url.String() != "tos.org" {
		t.Errorf("expected: %v, got: %v", "tos.org", url.String())
	}
}

func TestURLMarshalJSON(t *testing.T) {
	url := URL{Scheme: "https", Path: "tos.org"}
	json, err := url.MarshalJSON()
	if err != nil {
		t.Errorf("unexpcted error: %v", err)
	}
	if string(json) != "\"https://tos.org\"" {
		t.Errorf("expected: %v, got: %v", "\"https://tos.org\"", string(json))
	}
}

func TestURLUnmarshalJSON(t *testing.T) {
	url := &URL{}
	err := url.UnmarshalJSON([]byte("\"https://tos.org\""))
	if err != nil {
		t.Errorf("unexpcted error: %v", err)
	}
	if url.Scheme != "https" {
		t.Errorf("expected: %v, got: %v", "https", url.Scheme)
	}
	if url.Path != "tos.org" {
		t.Errorf("expected: %v, got: %v", "https", url.Path)
	}
}

func TestURLComparison(t *testing.T) {
	tests := []struct {
		urlA   URL
		urlB   URL
		expect int
	}{
		{URL{"https", "tos.org"}, URL{"https", "tos.org"}, 0},
		{URL{"http", "tos.org"}, URL{"https", "tos.org"}, -1},
		{URL{"https", "tos.org/a"}, URL{"https", "tos.org"}, 1},
		{URL{"https", "abc.org"}, URL{"https", "tos.org"}, -1},
	}

	for i, tt := range tests {
		result := tt.urlA.Cmp(tt.urlB)
		if result != tt.expect {
			t.Errorf("test %d: cmp mismatch: expected: %d, got: %d", i, tt.expect, result)
		}
	}
}
