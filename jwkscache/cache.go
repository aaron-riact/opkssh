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

// Package jwkscache provides a caching layer for JWKS (JSON Web Key Sets) that
// handles disk-based caching with failover logic, eternal JWKS support, and
// automatic cache expiration.
package jwkscache

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openpubkey/openpubkey/discover"
)

// CacheConfig holds the configuration for the JWKS cache
type CacheConfig struct {
	// CacheDir is the base directory for the JWKS cache
	// Default: /var/cache/opkssh/jwks-cache
	CacheDir string `yaml:"cache_dir"`

	// MaxCacheAge is how long before a cache entry is considered stale and needs refresh
	// Default: 5 minutes
	MaxCacheAge time.Duration `yaml:"max_cache_age"`

	// MaxCacheRetention is how long to keep old cache entries on disk before deletion
	// Default: 24 hours
	MaxCacheRetention time.Duration `yaml:"max_cache_retention"`

	// RefreshJitter is the random time variance added to cache refresh to avoid thundering herd
	// Default: 30 seconds
	RefreshJitter time.Duration `yaml:"refresh_jitter"`

	// EternalJWKSDir is the directory containing eternal JWKS files that serve as final backup
	// Files should be named by issuer hash: <sha256-of-issuer>.json
	// Default: /etc/opk/eternal-jwks
	EternalJWKSDir string `yaml:"eternal_jwks_dir"`

	// Enabled controls whether caching is enabled
	// Default: true
	Enabled bool `yaml:"enabled"`

	// HTTPClient is the HTTP client to use for fetching JWKS (optional, mainly for testing)
	HTTPClient *http.Client `yaml:"-"`
}

// DefaultCacheConfig returns a CacheConfig with sensible defaults
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		CacheDir:          "/var/cache/opkssh/jwks-cache",
		MaxCacheAge:       5 * time.Minute,
		MaxCacheRetention: 24 * time.Hour,
		RefreshJitter:     30 * time.Second,
		EternalJWKSDir:    "/etc/opk/eternal-jwks",
		Enabled:           true,
	}
}

// CachedPublicKeyFinder wraps discover.PublicKeyFinder with disk-based caching
type CachedPublicKeyFinder struct {
	config      CacheConfig
	innerFinder *discover.PublicKeyFinder
	mu          sync.RWMutex

	// For testing - allows overriding time.Now()
	nowFunc func() time.Time
}

// NewCachedPublicKeyFinder creates a new CachedPublicKeyFinder with the given configuration
func NewCachedPublicKeyFinder(config CacheConfig) *CachedPublicKeyFinder {
	c := &CachedPublicKeyFinder{
		config:  config,
		nowFunc: time.Now,
	}

	// Create the inner finder with our caching JWKS function
	c.innerFinder = &discover.PublicKeyFinder{
		JwksFunc: c.getJwksWithCache,
	}

	return c
}

// GetPublicKeyFinder returns the underlying PublicKeyFinder that can be used
// with ProviderVerifierOpts.DiscoverPublicKey
func (c *CachedPublicKeyFinder) GetPublicKeyFinder() *discover.PublicKeyFinder {
	return c.innerFinder
}

// CacheEntry represents a cached JWKS entry
type CacheEntry struct {
	// JWKS is the raw JWKS JSON bytes
	JWKS []byte `json:"jwks"`

	// WellKnown is the cached .well-known/openid-configuration response
	WellKnown []byte `json:"well_known,omitempty"`

	// Timestamp is when this entry was created
	Timestamp time.Time `json:"timestamp"`

	// Issuer is the issuer this cache entry is for
	Issuer string `json:"issuer"`
}

// getJwksWithCache implements the caching logic for JWKS fetching
func (c *CachedPublicKeyFinder) getJwksWithCache(ctx context.Context, issuer string) ([]byte, error) {
	if !c.config.Enabled {
		// Caching disabled, go straight to network
		return discover.GetJwksByIssuer(ctx, issuer, c.config.HTTPClient)
	}

	// Step 1: Look for the most recent cache entry
	entry, err := c.loadMostRecentCache(issuer)
	if err != nil {
		log.Printf("Warning: failed to load cache for issuer %s: %v", issuer, err)
	}

	now := c.nowFunc()

	// Step 2: Check if cache is fresh enough
	if entry != nil {
		cacheAge := now.Sub(entry.Timestamp)
		jitter := c.getRandomJitter()
		maxAge := c.config.MaxCacheAge + jitter

		if cacheAge < maxAge {
			// Cache is fresh, use it
			return entry.JWKS, nil
		}
	}

	// Step 3: Cache is stale or doesn't exist, try to download fresh JWKS
	freshJWKS, downloadErr := c.downloadAndCacheJWKS(ctx, issuer)
	if downloadErr == nil {
		// Successfully downloaded new JWKS
		return freshJWKS, nil
	}

	log.Printf("Warning: failed to download JWKS for issuer %s: %v", issuer, downloadErr)

	// Step 4: Download failed, try to use stale cache
	if entry != nil {
		log.Printf("Warning: using stale cache for issuer %s (age: %v)", issuer, now.Sub(entry.Timestamp))
		return entry.JWKS, nil
	}

	// Step 5: No cache available, try eternal JWKS
	eternalJWKS, eternalErr := c.loadEternalJWKS(issuer)
	if eternalErr == nil {
		log.Printf("Warning: using eternal JWKS for issuer %s", issuer)
		return eternalJWKS, nil
	}

	// Step 6: All options exhausted
	return nil, fmt.Errorf("failed to get JWKS for issuer %s: download failed (%w), no cache available, no eternal JWKS", issuer, downloadErr)
}

// GetJwksWithRetryOnVerificationFailure should be called when signature verification fails.
// It forces a refresh of the JWKS in case the OP rotated keys.
func (c *CachedPublicKeyFinder) GetJwksWithRetryOnVerificationFailure(ctx context.Context, issuer string) ([]byte, error) {
	if !c.config.Enabled {
		return discover.GetJwksByIssuer(ctx, issuer, c.config.HTTPClient)
	}

	// Try to download fresh JWKS since the cached one may have stale keys
	freshJWKS, err := c.downloadAndCacheJWKS(ctx, issuer)
	if err == nil {
		return freshJWKS, nil
	}

	log.Printf("Warning: forced JWKS refresh failed for issuer %s: %v", issuer, err)

	// Fall back to cache
	entry, cacheErr := c.loadMostRecentCache(issuer)
	if cacheErr == nil && entry != nil {
		return entry.JWKS, nil
	}

	// Try eternal JWKS
	eternalJWKS, eternalErr := c.loadEternalJWKS(issuer)
	if eternalErr == nil {
		return eternalJWKS, nil
	}

	return nil, fmt.Errorf("failed to refresh JWKS for issuer %s: %w", issuer, err)
}

// downloadAndCacheJWKS downloads the JWKS and caches it to disk using the atomic
// downloading -> done directory pattern
func (c *CachedPublicKeyFinder) downloadAndCacheJWKS(ctx context.Context, issuer string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Download the JWKS
	jwks, err := discover.GetJwksByIssuer(ctx, issuer, c.config.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("failed to download JWKS: %w", err)
	}

	// Create the cache entry
	entry := CacheEntry{
		JWKS:      jwks,
		Timestamp: c.nowFunc(),
		Issuer:    issuer,
	}

	// Also cache the well-known config (best effort)
	wellKnown, _ := c.fetchWellKnown(ctx, issuer)
	if wellKnown != nil {
		entry.WellKnown = wellKnown
	}

	// Write to disk using atomic pattern
	if err := c.writeCacheEntry(issuer, entry); err != nil {
		log.Printf("Warning: failed to write cache for issuer %s: %v", issuer, err)
		// Don't fail the operation if caching fails - we still have the JWKS
	}

	// Clean up old cache entries (best effort, don't block on this)
	go c.cleanupOldEntries(issuer)

	return jwks, nil
}

// writeCacheEntry writes a cache entry using the atomic downloading -> done pattern
func (c *CachedPublicKeyFinder) writeCacheEntry(issuer string, entry CacheEntry) error {
	issuerDir := c.issuerCacheDir(issuer)
	downloadingDir := filepath.Join(issuerDir, "downloading")
	doneDir := filepath.Join(issuerDir, "done")

	// Create directories if they don't exist
	if err := os.MkdirAll(downloadingDir, 0750); err != nil {
		return fmt.Errorf("failed to create downloading dir: %w", err)
	}
	if err := os.MkdirAll(doneDir, 0750); err != nil {
		return fmt.Errorf("failed to create done dir: %w", err)
	}

	// Generate timestamped directory name with random suffix
	randNum, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return fmt.Errorf("failed to generate random number: %w", err)
	}
	timestamp := entry.Timestamp.Format("20060102-150405")
	entryDirName := fmt.Sprintf("%s_%d", timestamp, randNum)

	// Write to downloading directory first
	tempDir := filepath.Join(downloadingDir, entryDirName)
	if err := os.MkdirAll(tempDir, 0750); err != nil {
		return fmt.Errorf("failed to create temp cache dir: %w", err)
	}

	// Write the cache entry
	entryPath := filepath.Join(tempDir, "jwks.json")
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		os.RemoveAll(tempDir)
		return fmt.Errorf("failed to marshal cache entry: %w", err)
	}

	if err := os.WriteFile(entryPath, entryBytes, 0640); err != nil {
		os.RemoveAll(tempDir)
		return fmt.Errorf("failed to write cache entry: %w", err)
	}

	// Atomically move from downloading to done
	finalDir := filepath.Join(doneDir, entryDirName)
	if err := os.Rename(tempDir, finalDir); err != nil {
		os.RemoveAll(tempDir)
		return fmt.Errorf("failed to move cache entry to done: %w", err)
	}

	return nil
}

// loadMostRecentCache loads the most recent cache entry for an issuer
func (c *CachedPublicKeyFinder) loadMostRecentCache(issuer string) (*CacheEntry, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	doneDir := filepath.Join(c.issuerCacheDir(issuer), "done")

	entries, err := os.ReadDir(doneDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No cache exists yet
		}
		return nil, fmt.Errorf("failed to read cache dir: %w", err)
	}

	if len(entries) == 0 {
		return nil, nil
	}

	// Sort entries by name (which includes timestamp) in descending order
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() > entries[j].Name()
	})

	// Try to load the most recent entry
	for _, dirEntry := range entries {
		if !dirEntry.IsDir() {
			continue
		}

		entryPath := filepath.Join(doneDir, dirEntry.Name(), "jwks.json")
		entryBytes, err := os.ReadFile(entryPath)
		if err != nil {
			log.Printf("Warning: failed to read cache entry %s: %v", entryPath, err)
			continue
		}

		var entry CacheEntry
		if err := json.Unmarshal(entryBytes, &entry); err != nil {
			log.Printf("Warning: failed to parse cache entry %s: %v", entryPath, err)
			continue
		}

		return &entry, nil
	}

	return nil, nil
}

// loadEternalJWKS loads an eternal JWKS file for an issuer
func (c *CachedPublicKeyFinder) loadEternalJWKS(issuer string) ([]byte, error) {
	if c.config.EternalJWKSDir == "" {
		return nil, fmt.Errorf("eternal JWKS directory not configured")
	}

	// Try loading by issuer hash
	issuerHash := hashIssuer(issuer)
	hashPath := filepath.Join(c.config.EternalJWKSDir, issuerHash+".json")
	if jwks, err := os.ReadFile(hashPath); err == nil {
		return jwks, nil
	}

	// Try loading by sanitized issuer name
	sanitizedIssuer := sanitizeIssuerForPath(issuer)
	namePath := filepath.Join(c.config.EternalJWKSDir, sanitizedIssuer+".json")
	if jwks, err := os.ReadFile(namePath); err == nil {
		return jwks, nil
	}

	return nil, fmt.Errorf("no eternal JWKS found for issuer %s", issuer)
}

// cleanupOldEntries removes cache entries older than MaxCacheRetention
func (c *CachedPublicKeyFinder) cleanupOldEntries(issuer string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	doneDir := filepath.Join(c.issuerCacheDir(issuer), "done")
	downloadingDir := filepath.Join(c.issuerCacheDir(issuer), "downloading")

	now := c.nowFunc()
	cutoff := now.Add(-c.config.MaxCacheRetention)

	// Clean up done directory
	c.cleanupDirectory(doneDir, cutoff)

	// Also clean up any stale downloading entries (shouldn't happen normally)
	c.cleanupDirectory(downloadingDir, cutoff)
}

// cleanupDirectory removes entries older than the cutoff time
func (c *CachedPublicKeyFinder) cleanupDirectory(dir string, cutoff time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		entryPath := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			if err := os.RemoveAll(entryPath); err != nil {
				log.Printf("Warning: failed to cleanup old cache entry %s: %v", entryPath, err)
			}
		}
	}
}

// getRandomJitter returns a random duration between 0 and RefreshJitter
func (c *CachedPublicKeyFinder) getRandomJitter() time.Duration {
	if c.config.RefreshJitter <= 0 {
		return 0
	}

	max := big.NewInt(int64(c.config.RefreshJitter))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0
	}

	// Add some randomness in both directions (-jitter/2 to +jitter/2)
	jitter := time.Duration(n.Int64()) - c.config.RefreshJitter/2
	return jitter
}

// issuerCacheDir returns the cache directory for a specific issuer
func (c *CachedPublicKeyFinder) issuerCacheDir(issuer string) string {
	sanitized := sanitizeIssuerForPath(issuer)
	return filepath.Join(c.config.CacheDir, sanitized)
}

// fetchWellKnown fetches the .well-known/openid-configuration
func (c *CachedPublicKeyFinder) fetchWellKnown(ctx context.Context, issuer string) ([]byte, error) {
	wellKnownURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	client := c.config.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, "GET", wellKnownURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// CleanupAllOldEntries cleans up old entries for all issuers
func (c *CachedPublicKeyFinder) CleanupAllOldEntries() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries, err := os.ReadDir(c.config.CacheDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	now := c.nowFunc()
	cutoff := now.Add(-c.config.MaxCacheRetention)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		doneDir := filepath.Join(c.config.CacheDir, entry.Name(), "done")
		downloadingDir := filepath.Join(c.config.CacheDir, entry.Name(), "downloading")

		c.cleanupDirectory(doneDir, cutoff)
		c.cleanupDirectory(downloadingDir, cutoff)
	}

	return nil
}

// InvalidateCache removes all cache entries for an issuer
func (c *CachedPublicKeyFinder) InvalidateCache(issuer string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	issuerDir := c.issuerCacheDir(issuer)
	return os.RemoveAll(issuerDir)
}
