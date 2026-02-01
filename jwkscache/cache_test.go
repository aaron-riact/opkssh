// Copyright 2025 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package jwkscache

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mockJWKS creates a minimal valid JWKS JSON
func mockJWKS(keyID string) []byte {
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": keyID,
				"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e":   "AQAB",
				"alg": "RS256",
				"use": "sig",
			},
		},
	}
	b, _ := json.Marshal(jwks)
	return b
}

func TestCachedPublicKeyFinder_DirectCaching(t *testing.T) {
	// Create a temporary directory for cache
	tempDir := t.TempDir()

	keyID := "test-key-1"
	issuer := "https://test-issuer.example.com"

	// Simulate a pre-populated cache
	config := CacheConfig{
		CacheDir:          tempDir,
		MaxCacheAge:       5 * time.Minute,
		MaxCacheRetention: 1 * time.Hour,
		RefreshJitter:     0, // Disable jitter for testing
		EternalJWKSDir:    filepath.Join(tempDir, "eternal"),
		Enabled:           true,
	}

	cachedFinder := NewCachedPublicKeyFinder(config)

	// Pre-populate the cache directly
	entry := CacheEntry{
		JWKS:      mockJWKS(keyID),
		Timestamp: time.Now(),
		Issuer:    issuer,
	}
	err := cachedFinder.writeCacheEntry(issuer, entry)
	require.NoError(t, err)

	// Now the cache should be able to load this entry
	loadedEntry, err := cachedFinder.loadMostRecentCache(issuer)
	require.NoError(t, err)
	require.NotNil(t, loadedEntry)
	require.Equal(t, issuer, loadedEntry.Issuer)

	// Verify the JWKS content
	var parsed map[string]interface{}
	err = json.Unmarshal(loadedEntry.JWKS, &parsed)
	require.NoError(t, err)
	keys := parsed["keys"].([]interface{})
	firstKey := keys[0].(map[string]interface{})
	require.Equal(t, keyID, firstKey["kid"])
}

func TestCachedPublicKeyFinder_CacheExpiry(t *testing.T) {
	tempDir := t.TempDir()

	keyID := "test-key-1"
	issuer := "https://test-issuer.example.com"

	config := CacheConfig{
		CacheDir:          tempDir,
		MaxCacheAge:       100 * time.Millisecond,
		MaxCacheRetention: 1 * time.Hour,
		RefreshJitter:     0,
		Enabled:           true,
	}

	cachedFinder := NewCachedPublicKeyFinder(config)

	// Pre-populate the cache with an old timestamp
	oldTime := time.Now().Add(-200 * time.Millisecond)
	entry := CacheEntry{
		JWKS:      mockJWKS(keyID),
		Timestamp: oldTime,
		Issuer:    issuer,
	}
	err := cachedFinder.writeCacheEntry(issuer, entry)
	require.NoError(t, err)

	// The cache should still be loadable
	loadedEntry, err := cachedFinder.loadMostRecentCache(issuer)
	require.NoError(t, err)
	require.NotNil(t, loadedEntry)

	// But the cache age check should indicate it's expired
	cacheAge := time.Since(loadedEntry.Timestamp)
	require.Greater(t, cacheAge, config.MaxCacheAge)
}

func TestCachedPublicKeyFinder_EternalJWKS(t *testing.T) {
	tempDir := t.TempDir()
	eternalDir := filepath.Join(tempDir, "eternal")
	require.NoError(t, os.MkdirAll(eternalDir, 0755))

	issuer := "https://example.com"
	keyID := "eternal-key-1"

	// Write an eternal JWKS file
	sanitizedIssuer := sanitizeIssuerForPath(issuer)
	eternalPath := filepath.Join(eternalDir, sanitizedIssuer+".json")
	require.NoError(t, os.WriteFile(eternalPath, mockJWKS(keyID), 0644))

	config := CacheConfig{
		CacheDir:          tempDir,
		MaxCacheAge:       5 * time.Minute,
		MaxCacheRetention: 1 * time.Hour,
		RefreshJitter:     0,
		EternalJWKSDir:    eternalDir,
		Enabled:           true,
	}

	cachedFinder := NewCachedPublicKeyFinder(config)

	// Load eternal JWKS directly
	jwks, err := cachedFinder.loadEternalJWKS(issuer)
	require.NoError(t, err)
	require.NotNil(t, jwks)

	// Verify it's the eternal JWKS
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(jwks, &parsed))
	keys := parsed["keys"].([]interface{})
	firstKey := keys[0].(map[string]interface{})
	require.Equal(t, keyID, firstKey["kid"])
}

func TestCachedPublicKeyFinder_EternalJWKSByHash(t *testing.T) {
	tempDir := t.TempDir()
	eternalDir := filepath.Join(tempDir, "eternal")
	require.NoError(t, os.MkdirAll(eternalDir, 0755))

	issuer := "https://accounts.google.com"
	keyID := "eternal-hash-key"

	// Write an eternal JWKS file using hash naming
	issuerHash := hashIssuer(issuer)
	eternalPath := filepath.Join(eternalDir, issuerHash+".json")
	require.NoError(t, os.WriteFile(eternalPath, mockJWKS(keyID), 0644))

	config := CacheConfig{
		CacheDir:       tempDir,
		EternalJWKSDir: eternalDir,
		Enabled:        true,
	}

	cachedFinder := NewCachedPublicKeyFinder(config)

	// Load eternal JWKS by hash
	jwks, err := cachedFinder.loadEternalJWKS(issuer)
	require.NoError(t, err)
	require.NotNil(t, jwks)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(jwks, &parsed))
	keys := parsed["keys"].([]interface{})
	firstKey := keys[0].(map[string]interface{})
	require.Equal(t, keyID, firstKey["kid"])
}

func TestCachedPublicKeyFinder_Disabled(t *testing.T) {
	tempDir := t.TempDir()

	config := CacheConfig{
		CacheDir: tempDir,
		Enabled:  false, // Disabled
	}

	cachedFinder := NewCachedPublicKeyFinder(config)
	require.NotNil(t, cachedFinder)
	require.False(t, cachedFinder.config.Enabled)
}

func TestCachedPublicKeyFinder_CleanupOldEntries(t *testing.T) {
	tempDir := t.TempDir()

	keyID := "test-key-1"
	issuer := "https://test-issuer.example.com"

	config := CacheConfig{
		CacheDir:          tempDir,
		MaxCacheAge:       1 * time.Millisecond,
		MaxCacheRetention: 50 * time.Millisecond,
		RefreshJitter:     0,
		Enabled:           true,
	}

	cachedFinder := NewCachedPublicKeyFinder(config)
	ctx := context.Background()

	// Create some cache entries with old timestamps
	for i := 0; i < 3; i++ {
		oldTime := time.Now().Add(-100 * time.Millisecond)
		entry := CacheEntry{
			JWKS:      mockJWKS(keyID),
			Timestamp: oldTime,
			Issuer:    issuer,
		}
		err := cachedFinder.writeCacheEntry(issuer, entry)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for entries to become old enough to clean
	time.Sleep(100 * time.Millisecond)

	// Manually manipulate the mod times of the directories to be old
	issuerDir := cachedFinder.issuerCacheDir(issuer)
	doneDir := filepath.Join(issuerDir, "done")
	entries, err := os.ReadDir(doneDir)
	require.NoError(t, err)

	oldTime := time.Now().Add(-100 * time.Millisecond)
	for _, entry := range entries {
		entryPath := filepath.Join(doneDir, entry.Name())
		_ = os.Chtimes(entryPath, oldTime, oldTime)
	}

	// Trigger cleanup
	err = cachedFinder.CleanupAllOldEntries()
	require.NoError(t, err)

	// Verify old entries were cleaned up
	entries, err = os.ReadDir(doneDir)
	if err == nil {
		// All entries should be cleaned up (or the dir itself removed)
		require.Empty(t, entries, "Expected all old entries to be cleaned up")
	}

	_ = ctx // silence unused warning
}

func TestCachedPublicKeyFinder_InvalidateCache(t *testing.T) {
	tempDir := t.TempDir()

	keyID := "test-key-1"
	issuer := "https://test-issuer.example.com"

	config := CacheConfig{
		CacheDir:          tempDir,
		MaxCacheAge:       5 * time.Minute,
		MaxCacheRetention: 1 * time.Hour,
		RefreshJitter:     0,
		Enabled:           true,
	}

	cachedFinder := NewCachedPublicKeyFinder(config)

	// Pre-populate the cache
	entry := CacheEntry{
		JWKS:      mockJWKS(keyID),
		Timestamp: time.Now(),
		Issuer:    issuer,
	}
	err := cachedFinder.writeCacheEntry(issuer, entry)
	require.NoError(t, err)

	// Verify cache exists
	issuerDir := cachedFinder.issuerCacheDir(issuer)
	_, err = os.Stat(issuerDir)
	require.NoError(t, err)

	// Invalidate cache
	err = cachedFinder.InvalidateCache(issuer)
	require.NoError(t, err)

	// Verify cache is gone
	_, err = os.Stat(issuerDir)
	require.True(t, os.IsNotExist(err))
}

func TestSanitizeIssuerForPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://accounts.google.com", "accounts.google.com"},
		{"https://login.microsoftonline.com/tenant", "login.microsoftonline.com_tenant"},
		{"http://localhost:8080/path", "localhost_8080_path"},
		{"https://example.com?query=value", "example.com_query_value"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeIssuerForPath(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestHashIssuer(t *testing.T) {
	issuer := "https://accounts.google.com"
	hash := hashIssuer(issuer)

	// Verify it's a valid hex string of expected length (SHA256 = 64 hex chars)
	require.Len(t, hash, 64)

	// Verify same input produces same output
	require.Equal(t, hash, hashIssuer(issuer))

	// Verify different input produces different output
	require.NotEqual(t, hash, hashIssuer("https://other.example.com"))
}

func TestCacheEntryMarshaling(t *testing.T) {
	keyID := "test-key"
	entry := CacheEntry{
		JWKS:      mockJWKS(keyID),
		WellKnown: []byte(`{"issuer": "https://test.example.com"}`),
		Timestamp: time.Now().UTC().Truncate(time.Second), // Truncate for comparison
		Issuer:    "https://test.example.com",
	}

	// Marshal
	data, err := json.Marshal(entry)
	require.NoError(t, err)

	// Unmarshal
	var restored CacheEntry
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	require.Equal(t, entry.Issuer, restored.Issuer)
	require.Equal(t, entry.JWKS, restored.JWKS)
	require.Equal(t, entry.WellKnown, restored.WellKnown)
	require.WithinDuration(t, entry.Timestamp, restored.Timestamp, time.Second)
}

func TestDefaultCacheConfig(t *testing.T) {
	config := DefaultCacheConfig()

	require.Equal(t, "/var/cache/opkssh/jwks-cache", config.CacheDir)
	require.Equal(t, 5*time.Minute, config.MaxCacheAge)
	require.Equal(t, 24*time.Hour, config.MaxCacheRetention)
	require.Equal(t, 30*time.Second, config.RefreshJitter)
	require.Equal(t, "/etc/opk/eternal-jwks", config.EternalJWKSDir)
	require.True(t, config.Enabled)
}
