package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveServiceAccountMintsToken exercises the real Google token endpoint
// with a real key. It is skipped unless LLMGW_LIVE_GCP_KEY names a key file, so
// the default suite stays hermetic and needs no credential.
//
//	LLMGW_LIVE_GCP_KEY=/path/to/key.json go test ./gcp -run Live -v
//
// The key is read from disk by this test and never printed: only the
// non-secret metadata and the token's reported scope and lifetime are logged.
func TestLiveServiceAccountMintsToken(t *testing.T) {
	path := strings.TrimSpace(os.Getenv("LLMGW_LIVE_GCP_KEY"))
	if path == "" {
		t.Skip("set LLMGW_LIVE_GCP_KEY to a service account key file to run the live check")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}

	credential, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	meta := credential.Metadata()
	t.Logf("key: project=%s client_email=%s key_id=%s",
		meta.ProjectID, meta.ClientEmail, meta.PrivateKeyID)

	cache := &TokenCache{}
	token, err := cache.AccessToken(credential, CloudPlatformScope)
	if err != nil {
		t.Fatalf("AccessToken against the live endpoint: %v", err)
	}
	if strings.TrimSpace(token) == "" {
		t.Fatal("live endpoint returned an empty token")
	}
	t.Logf("minted an access token (%d chars, value withheld)", len(token))

	// Ask Google what it thinks the token is. This proves the assertion was
	// accepted and the token carries the scope we requested.
	response, err := http.PostForm(
		"https://oauth2.googleapis.com/tokeninfo", url.Values{"access_token": {token}},
	)
	if err != nil {
		t.Fatalf("tokeninfo: %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("tokeninfo returned HTTP %d: %s", response.StatusCode, string(body))
	}
	var info struct {
		Scope     string `json:"scope"`
		ExpiresIn any    `json:"expires_in"`
		Email     string `json:"email"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatalf("tokeninfo body: %v", err)
	}
	if !strings.Contains(info.Scope, "cloud-platform") {
		t.Fatalf("token scope = %q, want the cloud-platform scope", info.Scope)
	}
	t.Logf("google accepted the assertion: scope=%s expires_in=%v", info.Scope, info.ExpiresIn)

	// A second call must be served from cache rather than re-minting.
	before := time.Now()
	again, err := cache.AccessToken(credential, CloudPlatformScope)
	if err != nil {
		t.Fatalf("second AccessToken: %v", err)
	}
	if again != token {
		t.Fatal("second call re-minted instead of using the cache")
	}
	t.Logf("second call served from cache in %s", time.Since(before))
}
