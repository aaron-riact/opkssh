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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestServerConfigWithJWKSCache(t *testing.T) {
	configYAML := `
env_vars:
  MY_VAR: my_value
deny_users:
  - baduser
deny_emails:
  - bad@example.com
jwks_cache:
  enabled: true
  cache_dir: /custom/cache/dir
  max_cache_age_seconds: 600
  max_cache_retention_seconds: 172800
  refresh_jitter_seconds: 60
  eternal_jwks_dir: /custom/eternal/dir
`

	serverConfig, err := NewServerConfig([]byte(configYAML))
	require.NoError(t, err)
	require.NotNil(t, serverConfig)

	// Check basic config
	require.Equal(t, "my_value", serverConfig.EnvVars["MY_VAR"])
	require.Contains(t, serverConfig.DenyUsers, "baduser")
	require.Contains(t, serverConfig.DenyEmails, "bad@example.com")

	// Check JWKS cache config
	require.True(t, serverConfig.JWKSCache.IsEnabled())
	require.Equal(t, "/custom/cache/dir", serverConfig.JWKSCache.GetCacheDir())
	require.Equal(t, 10*time.Minute, serverConfig.JWKSCache.GetMaxCacheAge())
	require.Equal(t, 48*time.Hour, serverConfig.JWKSCache.GetMaxCacheRetention())
	require.Equal(t, 60*time.Second, serverConfig.JWKSCache.GetRefreshJitter())
	require.Equal(t, "/custom/eternal/dir", serverConfig.JWKSCache.GetEternalJWKSDir())
}

func TestServerConfigJWKSCacheDefaults(t *testing.T) {
	// Empty config should use defaults
	configYAML := `
env_vars: {}
`

	serverConfig, err := NewServerConfig([]byte(configYAML))
	require.NoError(t, err)
	require.NotNil(t, serverConfig)

	// Check defaults
	require.True(t, serverConfig.JWKSCache.IsEnabled()) // enabled by default
	require.Equal(t, "/var/cache/opkssh/jwks-cache", serverConfig.JWKSCache.GetCacheDir())
	require.Equal(t, 5*time.Minute, serverConfig.JWKSCache.GetMaxCacheAge())
	require.Equal(t, 24*time.Hour, serverConfig.JWKSCache.GetMaxCacheRetention())
	require.Equal(t, 30*time.Second, serverConfig.JWKSCache.GetRefreshJitter())
	require.Equal(t, "/etc/opk/eternal-jwks", serverConfig.JWKSCache.GetEternalJWKSDir())
}

func TestServerConfigJWKSCacheDisabled(t *testing.T) {
	configYAML := `
jwks_cache:
  enabled: false
`

	serverConfig, err := NewServerConfig([]byte(configYAML))
	require.NoError(t, err)
	require.NotNil(t, serverConfig)

	require.False(t, serverConfig.JWKSCache.IsEnabled())
}

func TestJWKSCacheConfigGetters(t *testing.T) {
	tests := []struct {
		name     string
		config   JWKSCacheConfig
		expected struct {
			cacheDir          string
			maxCacheAge       time.Duration
			maxCacheRetention time.Duration
			refreshJitter     time.Duration
			eternalDir        string
			enabled           bool
		}
	}{
		{
			name:   "empty config uses defaults",
			config: JWKSCacheConfig{},
			expected: struct {
				cacheDir          string
				maxCacheAge       time.Duration
				maxCacheRetention time.Duration
				refreshJitter     time.Duration
				eternalDir        string
				enabled           bool
			}{
				cacheDir:          "/var/cache/opkssh/jwks-cache",
				maxCacheAge:       5 * time.Minute,
				maxCacheRetention: 24 * time.Hour,
				refreshJitter:     30 * time.Second,
				eternalDir:        "/etc/opk/eternal-jwks",
				enabled:           true,
			},
		},
		{
			name: "custom values",
			config: JWKSCacheConfig{
				CacheDir:                 "/my/cache",
				MaxCacheAgeSeconds:       120,
				MaxCacheRetentionSeconds: 3600,
				RefreshJitterSeconds:     10,
				EternalJWKSDir:           "/my/eternal",
			},
			expected: struct {
				cacheDir          string
				maxCacheAge       time.Duration
				maxCacheRetention time.Duration
				refreshJitter     time.Duration
				eternalDir        string
				enabled           bool
			}{
				cacheDir:          "/my/cache",
				maxCacheAge:       2 * time.Minute,
				maxCacheRetention: 1 * time.Hour,
				refreshJitter:     10 * time.Second,
				eternalDir:        "/my/eternal",
				enabled:           true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected.cacheDir, tt.config.GetCacheDir())
			require.Equal(t, tt.expected.maxCacheAge, tt.config.GetMaxCacheAge())
			require.Equal(t, tt.expected.maxCacheRetention, tt.config.GetMaxCacheRetention())
			require.Equal(t, tt.expected.refreshJitter, tt.config.GetRefreshJitter())
			require.Equal(t, tt.expected.eternalDir, tt.config.GetEternalJWKSDir())
			require.Equal(t, tt.expected.enabled, tt.config.IsEnabled())
		})
	}
}
