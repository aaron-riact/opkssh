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

package policy

import (
	"fmt"
	"strings"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
)

type ProvidersRow struct {
	Issuer           string
	ClientID         string
	ExpirationPolicy string
}

func (p ProvidersRow) GetExpirationPolicy() (verifier.ExpirationPolicy, error) {
	switch p.ExpirationPolicy {
	case "12h":
		return verifier.ExpirationPolicies.MAX_AGE_12HOURS, nil
	case "24h":
		return verifier.ExpirationPolicies.MAX_AGE_24HOURS, nil
	case "48h":
		return verifier.ExpirationPolicies.MAX_AGE_48HOURS, nil
	case "1week":
		return verifier.ExpirationPolicies.MAX_AGE_1WEEK, nil
	case "oidc":
		return verifier.ExpirationPolicies.OIDC, nil
	case "oidc_refreshed":
		return verifier.ExpirationPolicies.OIDC_REFRESHED, nil
	case "never":
		return verifier.ExpirationPolicies.NEVER_EXPIRE, nil
	default:
		return verifier.ExpirationPolicy{}, fmt.Errorf("invalid expiration policy: %s", p.ExpirationPolicy)
	}
}

func (p ProvidersRow) ToString() string {
	return p.Issuer + " " + p.ClientID + " " + p.ExpirationPolicy
}

type ProviderPolicy struct {
	rows []ProvidersRow
}

func (p *ProviderPolicy) AddRow(row ProvidersRow) {
	p.rows = append(p.rows, row)
}

func (p *ProviderPolicy) GetRows() []ProvidersRow {
	return p.rows
}

// VerifierOptions contains options for creating a verifier
type VerifierOptions struct {
	// PublicKeyFinder is a custom public key finder (e.g., with caching)
	// If nil, the default finder is used
	PublicKeyFinder *discover.PublicKeyFinder
}

// CreateVerifier creates a verifier with default options (no caching)
func (p *ProviderPolicy) CreateVerifier() (*verifier.Verifier, error) {
	return p.CreateVerifierWithOptions(VerifierOptions{})
}

// CreateVerifierWithOptions creates a verifier with the provided options
func (p *ProviderPolicy) CreateVerifierWithOptions(opts VerifierOptions) (*verifier.Verifier, error) {
	pvs := []verifier.ProviderVerifier{}
	var expirationPolicy verifier.ExpirationPolicy
	var err error
	for _, row := range p.rows {
		// Create a ProviderVerifier with custom public key finder if provided
		commitType := providers.CommitTypesEnum.NONCE_CLAIM

		pvOpts := providers.ProviderVerifierOpts{
			CommitType: commitType,
			ClientID:   row.ClientID,
		}

		// If a custom public key finder is provided, use it
		if opts.PublicKeyFinder != nil {
			pvOpts.DiscoverPublicKey = opts.PublicKeyFinder
		}

		provider := providers.NewProviderVerifier(row.Issuer, pvOpts)

		expirationPolicy, err = row.GetExpirationPolicy()
		if err != nil {
			return nil, err
		}
		pv := verifier.ProviderVerifierExpires{
			ProviderVerifier: provider,
			Expiration:       expirationPolicy,
		}
		pvs = append(pvs, pv)
	}

	if len(pvs) == 0 {
		return nil, fmt.Errorf("no providers configured")
	}
	pktVerifier, err := verifier.NewFromMany(
		pvs,
		verifier.WithExpirationPolicy(expirationPolicy),
	)
	if err != nil {
		return nil, err
	}
	return pktVerifier, nil
}

func (p ProviderPolicy) ToString() string {
	var sb strings.Builder
	for _, row := range p.rows {
		sb.WriteString(row.ToString() + "\n")
	}
	return sb.String()
}

// ProviderLoader defines the interface for loading provider policies
type ProviderLoader interface {
	LoadProviderPolicy(path string) (*ProviderPolicy, error)
}

type ProvidersFileLoader struct {
	files.FileLoader
	Path string
}

func NewProviderFileLoader() *ProvidersFileLoader {
	return &ProvidersFileLoader{
		FileLoader: files.FileLoader{
			Fs:           afero.NewOsFs(),
			RequiredPerm: files.ModeSystemPerms,
		},
	}
}

func (o *ProvidersFileLoader) LoadProviderPolicy(path string) (*ProviderPolicy, error) {
	content, err := o.LoadFileAtPath(path)
	if err != nil {
		return nil, err
	}
	policy := o.FromTable(content, path)
	return policy, nil
}

// FromTable decodes whitespace delimited input into policy.Policy
func (o ProvidersFileLoader) ToTable(opPolicies ProviderPolicy) files.Table {
	table := files.Table{}
	for _, opPolicy := range opPolicies.rows {
		table.AddRow(opPolicy.Issuer, opPolicy.ClientID, opPolicy.ExpirationPolicy)
	}
	return table
}

// FromTable decodes whitespace delimited input into policy.Policy
// Path is passed only for logging purposes
func (o *ProvidersFileLoader) FromTable(input []byte, path string) *ProviderPolicy {
	table := files.NewTable(input)
	policy := &ProviderPolicy{
		rows: []ProvidersRow{},
	}
	for _, row := range table.GetRows() {
		// Error should not break everyone's ability to login, skip those rows
		if len(row) != 3 {
			configProblem := files.ConfigProblem{
				Filepath:      path,
				OffendingLine: strings.Join(row, " "),
				ErrorMessage:  fmt.Sprintf("wrong number of arguments (expected=3, got=%d)", len(row)),
				Source:        "providers policy file",
			}
			files.ConfigProblems().RecordProblem(configProblem)
			continue
		}
		policyRow := ProvidersRow{
			Issuer:           row[0],
			ClientID:         row[1],
			ExpirationPolicy: row[2], // TODO: Validate this so that we can determine the line number that has the error
		}
		policy.AddRow(policyRow)
	}
	return policy
}
