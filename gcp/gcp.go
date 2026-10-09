// Package gcpauth mints Google Cloud OAuth2 access tokens from a service
// account key.
//
// A service account authenticates by signing a short-lived JWT assertion with
// its RSA private key and exchanging that assertion for an access token, rather
// than by presenting a static secret. The token lasts about an hour, so a
// TokenCache keeps it per (account, key id, key, token endpoint, scope) and
// refreshes it shortly before it expires. Each TokenCache owns its state; the
// package keeps none.
//
// This uses only the standard library: crypto/rsa and crypto/x509 sign the
// assertion, so the gateway keeps its three-module dependency tree.
//
// Key material never appears in an error, a log line, or a String method. Only
// Metadata is safe to surface.
package gcp

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// CloudPlatformScope is the scope Vertex AI model calls require.
const CloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// CredentialKind is the stored connection kind for a service-account key. It
// lives here so the storage layer and the provider layer agree on one spelling
// without either importing the other.
const CredentialKind = "gcp_service_account"

const (
	defaultTokenURI = "https://oauth2.googleapis.com/token"
	jwtGrantType    = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	assertionTTL    = time.Hour
	// refreshBeforeExpiry mirrors copilotauth: renew slightly early so a token
	// cannot expire in flight between the check and the upstream call.
	refreshBeforeExpiry = 60 * time.Second
)

// Credential is a parsed service-account key. The private key is kept in its
// parsed form only; callers never need the PEM text again.
type Credential struct {
	projectID    string
	privateKeyID string
	clientEmail  string
	tokenURI     string
	key          *rsa.PrivateKey
	// keyFingerprint tells apart credentials that share an account and key id
	// but sign with different keys. It hashes the public key, which identifies
	// the key pair because parsing validates the private key against it, so no
	// value derived from the private bytes is kept.
	keyFingerprint [sha256.Size]byte
}

// Metadata is the non-secret description of a credential, safe to return from
// an API or render in the console.
type Metadata struct {
	ProjectID    string `json:"project_id"`
	ClientEmail  string `json:"client_email"`
	PrivateKeyID string `json:"private_key_id"`
}

// Metadata describes the credential without exposing key material.
func (c *Credential) Metadata() Metadata {
	return Metadata{
		ProjectID:    c.projectID,
		ClientEmail:  c.clientEmail,
		PrivateKeyID: c.privateKeyID,
	}
}

// ProjectID is the project the key was issued for. A Vertex provider with no
// configured project defaults to it.
func (c *Credential) ProjectID() string { return c.projectID }

// serviceAccountJSON is the on-disk shape Google issues.
type serviceAccountJSON struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	TokenURI     string `json:"token_uri"`
}

// LooksLikeServiceAccount reports whether raw is a service-account key document.
// It is deliberately cheap and total: callers use it to pick a credential kind
// before validating, so anything that is not such a document answers false
// rather than failing.
func LooksLikeServiceAccount(raw string) bool {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		return false
	}
	return probe.Type == "service_account"
}

// Parse reads a service-account key. It rejects the other credential shapes
// Google hands out (authorized_user, external_account) by name, because those
// fail much later and far less clearly when treated as a service account.
func Parse(raw []byte) (*Credential, error) {
	var doc serviceAccountJSON
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, errors.New("service account key: not valid JSON")
	}
	if doc.Type != "service_account" {
		kind := doc.Type
		if kind == "" {
			kind = "unspecified"
		}
		return nil, fmt.Errorf(
			"service account key: expected type \"service_account\", got %q", kind,
		)
	}
	missing := []string{}
	for name, value := range map[string]string{
		"client_email": doc.ClientEmail,
		"private_key":  doc.PrivateKey,
		"project_id":   doc.ProjectID,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		// Sorted so the message is stable across map iteration order.
		for i := 0; i < len(missing); i++ {
			for j := i + 1; j < len(missing); j++ {
				if missing[j] < missing[i] {
					missing[i], missing[j] = missing[j], missing[i]
				}
			}
		}
		return nil, fmt.Errorf(
			"service account key: missing required field(s): %s", strings.Join(missing, ", "),
		)
	}
	key, err := parsePrivateKey(doc.PrivateKey)
	if err != nil {
		return nil, err
	}
	tokenURI := strings.TrimSpace(doc.TokenURI)
	if tokenURI == "" {
		tokenURI = defaultTokenURI
	}
	if err := checkTokenURI(tokenURI); err != nil {
		return nil, err
	}
	return &Credential{
		projectID:      strings.TrimSpace(doc.ProjectID),
		privateKeyID:   strings.TrimSpace(doc.PrivateKeyID),
		clientEmail:    strings.TrimSpace(doc.ClientEmail),
		tokenURI:       tokenURI,
		key:            key,
		keyFingerprint: sha256.Sum256(x509.MarshalPKCS1PublicKey(&key.PublicKey)),
	}, nil
}

// checkTokenURI admits an https endpoint, or plain http on a loopback host
// where a local test server listens. The exchange posts a signed assertion that
// the endpoint accepts until it expires, so it must not cross a network in
// cleartext. Errors omit the value, because a URL can carry credentials in its
// userinfo or query.
func checkTokenURI(raw string) error {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Host == "" {
		return errors.New("service account key: token_uri is not an absolute URL")
	}
	switch endpoint.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(endpoint.Hostname()) {
			return nil
		}
	}
	return errors.New("service account key: token_uri must use https; http is accepted only for a loopback host")
}

// isLoopbackHost reports whether host is localhost or a loopback IP literal.
// Any other name could resolve to a remote address.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// parsePrivateKey decodes the PEM block. Errors deliberately describe only the
// shape of the failure, never the contents.
func parsePrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("service account key: private_key is not a PEM block")
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("service account key: private_key is not an RSA key")
		}
		return key, nil
	}
	// Older keys are emitted as PKCS#1.
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("service account key: private_key could not be parsed")
	}
	return key, nil
}
