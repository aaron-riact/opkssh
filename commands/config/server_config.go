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

package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// JWKSCacheConfig holds the configuration for the JWKS cache
type JWKSCacheConfig struct {
	// Enabled controls whether JWKS caching is enabled
	// Default: true
	Enabled *bool `yaml:"enabled,omitempty"`

	// CacheDir is the base directory for the JWKS cache
	// Default: /var/cache/opkssh/jwks-cache
	CacheDir string `yaml:"cache_dir,omitempty"`

	// MaxCacheAge is how long (in seconds) before a cache entry is considered stale and needs refresh
	// Default: 300 (5 minutes)
	MaxCacheAgeSeconds int `yaml:"max_cache_age_seconds,omitempty"`

	// MaxCacheRetention is how long (in seconds) to keep old cache entries on disk before deletion
	// Default: 86400 (24 hours)
	MaxCacheRetentionSeconds int `yaml:"max_cache_retention_seconds,omitempty"`

	// RefreshJitter is the random time variance (in seconds) added to cache refresh to avoid thundering herd
	// Default: 30
	RefreshJitterSeconds int `yaml:"refresh_jitter_seconds,omitempty"`

	// EternalJWKSDir is the directory containing eternal JWKS files that serve as final backup
	// Files should be named by sanitized issuer: <issuer-domain>.json
	// Default: /etc/opk/eternal-jwks
	EternalJWKSDir string `yaml:"eternal_jwks_dir,omitempty"`
}

// GetMaxCacheAge returns the max cache age as a time.Duration
func (c *JWKSCacheConfig) GetMaxCacheAge() time.Duration {
	if c.MaxCacheAgeSeconds <= 0 {
		return 5 * time.Minute // default
	}
	return time.Duration(c.MaxCacheAgeSeconds) * time.Second
}

// GetMaxCacheRetention returns the max cache retention as a time.Duration
func (c *JWKSCacheConfig) GetMaxCacheRetention() time.Duration {
	if c.MaxCacheRetentionSeconds <= 0 {
		return 24 * time.Hour // default
	}
	return time.Duration(c.MaxCacheRetentionSeconds) * time.Second
}

// GetRefreshJitter returns the refresh jitter as a time.Duration
func (c *JWKSCacheConfig) GetRefreshJitter() time.Duration {
	if c.RefreshJitterSeconds <= 0 {
		return 30 * time.Second // default
	}
	return time.Duration(c.RefreshJitterSeconds) * time.Second
}

// IsEnabled returns whether caching is enabled (defaults to true)
func (c *JWKSCacheConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true // enabled by default
	}
	return *c.Enabled
}

// GetCacheDir returns the cache directory or the default
func (c *JWKSCacheConfig) GetCacheDir() string {
	if c.CacheDir == "" {
		return "/var/cache/opkssh/jwks-cache"
	}
	return c.CacheDir
}

// GetEternalJWKSDir returns the eternal JWKS directory or the default
func (c *JWKSCacheConfig) GetEternalJWKSDir() string {
	if c.EternalJWKSDir == "" {
		return "/etc/opk/eternal-jwks"
	}
	return c.EternalJWKSDir
}

// ServerConfig struct to represent the /etc/opk/config.yml file that runs on the server that the user is SSHing into
type ServerConfig struct {
	EnvVars    map[string]string `yaml:"env_vars"`
	DenyUsers  []string          `yaml:"deny_users"`
	DenyEmails []string          `yaml:"deny_emails"`
	JWKSCache  JWKSCacheConfig   `yaml:"jwks_cache,omitempty"`
}

func NewServerConfig(c []byte) (*ServerConfig, error) {
	var serverConfig ServerConfig
	if err := yaml.Unmarshal(c, &serverConfig); err != nil {
		return nil, err
	}

	return &serverConfig, nil
}

func (c *ServerConfig) SetEnvVars() error {
	for k, v := range c.EnvVars {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
	}
	return nil
}
