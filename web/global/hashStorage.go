package global

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"sync"
	"time"
)

// HashEntry represents a stored hash entry with its value and timestamp.
type HashEntry struct {
	Hash      string    // Random key string (32 hex characters)
	Value     string    // Original value
	Timestamp time.Time // Time when the hash was created
}

// HashStorage provides thread-safe storage for hash-value pairs with expiration.
type HashStorage struct {
	sync.RWMutex
	Data       map[string]HashEntry // Map of hash to entry
	Expiration time.Duration        // Expiration duration for entries
}

// NewHashStorage creates a new HashStorage instance with the specified expiration duration.
func NewHashStorage(expiration time.Duration) *HashStorage {
	return &HashStorage{
		Data:       make(map[string]HashEntry),
		Expiration: expiration,
	}
}

// SaveHash generates a random key for the given query string and stores
// it with a timestamp (L-14). The old implementation derived the key as
// an unsalted MD5 of the query, so the same query always produced the
// same key and an attacker who could control the query could craft an
// MD5 collision that decoded to a different query. A random key has
// neither property. The key format stays 32 hex characters, so the
// callback data length is unchanged.
func (h *HashStorage) SaveHash(query string) string {
	h.Lock()
	defer h.Unlock()

	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		// crypto/rand only fails if the OS RNG is unavailable; fall
		// back to a time-seeded key so SaveHash still returns a
		// usable unique key instead of an empty one.
		seed := time.Now().UnixNano()
		for i := range key {
			seed = seed*6364136223846793005 + 1442695040888963407
			key[i] = byte(seed >> 56)
		}
	}
	keyString := hex.EncodeToString(key)

	entry := HashEntry{
		Hash:      keyString,
		Value:     query,
		Timestamp: time.Now(),
	}

	h.Data[keyString] = entry

	return keyString
}

// GetValue retrieves the original value for the given hash, returning true if found.
// Expired entries are treated as absent (L-14): the old implementation
// ignored Timestamp entirely, so a query stayed decodable after its
// 20-minute expiry until the 2-minute sweeper happened to delete it.
func (h *HashStorage) GetValue(hash string) (string, bool) {
	h.RLock()
	defer h.RUnlock()

	entry, exists := h.Data[hash]
	if !exists {
		return "", false
	}
	if time.Since(entry.Timestamp) > h.Expiration {
		return "", false
	}

	return entry.Value, true
}

// IsHashKey checks if the given string is a valid 32-character hex key
// as produced by SaveHash. (Formerly IsMD5, renamed when the keys
// stopped being MD5 digests.)
func (h *HashStorage) IsHashKey(hash string) bool {
	match, _ := regexp.MatchString("^[a-f0-9]{32}$", hash)
	return match
}

// RemoveExpiredHashes removes all hash entries that have exceeded the expiration duration.
func (h *HashStorage) RemoveExpiredHashes() {
	h.Lock()
	defer h.Unlock()

	now := time.Now()

	for hash, entry := range h.Data {
		if now.Sub(entry.Timestamp) > h.Expiration {
			delete(h.Data, hash)
		}
	}
}

// Reset clears all stored hash entries.
func (h *HashStorage) Reset() {
	h.Lock()
	defer h.Unlock()

	h.Data = make(map[string]HashEntry)
}
