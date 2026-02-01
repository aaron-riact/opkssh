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
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// hashIssuer creates a SHA256 hash of the issuer URL for use in file paths
func hashIssuer(issuer string) string {
	h := sha256.New()
	h.Write([]byte(issuer))
	return hex.EncodeToString(h.Sum(nil))
}

// sanitizeIssuerForPath converts an issuer URL to a safe directory name
func sanitizeIssuerForPath(issuer string) string {
	// Remove protocol
	s := issuer
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")

	// Replace unsafe characters
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "?", "_")
	s = strings.ReplaceAll(s, "&", "_")
	s = strings.ReplaceAll(s, "=", "_")
	s = strings.ReplaceAll(s, " ", "_")

	// Limit length
	if len(s) > 100 {
		s = s[:100]
	}

	return s
}
