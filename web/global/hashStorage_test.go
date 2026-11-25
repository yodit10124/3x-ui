package global

import (
	"testing"
	"time"
)

// TestSaveHashRandomKeys (L-14): the same query must not map to the
// same key twice — the old unsalted MD5 was deterministic.
func TestSaveHashRandomKeys(t *testing.T) {
	storage := NewHashStorage(20 * time.Minute)
	query := "reset client with a very long query string that exceeds sixty-four characters easily"
	key1 := storage.SaveHash(query)
	key2 := storage.SaveHash(query)
	if key1 == key2 {
		t.Fatalf("SaveHash(%q) returned the same key twice: %s", query, key1)
	}
	if !storage.IsHashKey(key1) || !storage.IsHashKey(key2) {
		t.Fatalf("keys are not 32 hex chars: %q, %q", key1, key2)
	}
	if v, ok := storage.GetValue(key1); !ok || v != query {
		t.Fatalf("GetValue(key1) = (%q, %v), want (%q, true)", v, ok, query)
	}
	if v, ok := storage.GetValue(key2); !ok || v != query {
		t.Fatalf("GetValue(key2) = (%q, %v), want (%q, true)", v, ok, query)
	}
}

// TestGetValueEnforcesExpiry (L-14): the audit's PoC — an expired
// entry must no longer decode.
func TestGetValueEnforcesExpiry(t *testing.T) {
	storage := NewHashStorage(50 * time.Millisecond)
	key := storage.SaveHash("some long query that needs to be stored for a while")
	if _, ok := storage.GetValue(key); !ok {
		t.Fatal("GetValue(fresh) should succeed")
	}
	time.Sleep(60 * time.Millisecond)
	if v, ok := storage.GetValue(key); ok {
		t.Fatalf("GetValue(expired) = (%q, true), want (\"\", false)", v)
	}
	storage.RemoveExpiredHashes()
	if _, exists := storage.Data[key]; exists {
		t.Fatal("RemoveExpiredHashes should delete the expired entry")
	}
	if _, ok := storage.GetValue("00000000000000000000000000000000"); ok {
		t.Fatal("GetValue(unknown key) should fail")
	}
}

func TestIsHashKey(t *testing.T) {
	storage := NewHashStorage(time.Minute)
	if valid := storage.SaveHash("x"); !storage.IsHashKey(valid) {
		t.Fatalf("IsHashKey(%q) = false", valid)
	}
	for _, bad := range []string{"", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "ABCDEF0123456789ABCDEF0123456789", "abc", "aabbccddeeff00112233445566778899ff"} {
		if storage.IsHashKey(bad) {
			t.Fatalf("IsHashKey(%q) = true, want false", bad)
		}
	}
}
