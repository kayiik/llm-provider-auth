# llm-provider-auth

Modular Go credential resolvers, OAuth flows, and session token brokers for LLM providers.

## Modules & Drivers

Each driver is an independent subpackage with zero unnecessary dependencies:

- **`gcp`**: Google Cloud Service Account JWT RS256 token minter. **Zero Google Cloud SDK dependencies** (pure standard library `crypto/rsa` and `crypto/x509`).
- **`browseroauth`**: Storage-neutral browser OAuth primitives with caller-supplied endpoints and client configuration, PKCE S256, state generation, code exchange, and refresh.
- **`tokenstore`**: A storage contract and refresh coordinator that spend a rotating refresh token exactly once, even when several processes share one credential store. It includes an in-memory reference store and the `tokenstore/storetest` conformance suite.

No package reads environment variables, runs an `init` function, or keeps
mutable package-level state; callers supply all configuration explicitly. An
architecture test enforces this.

## Installation

```bash
# Core interfaces
go get github.com/kayiik/llm-provider-auth

# Or install specific drivers directly
go get github.com/kayiik/llm-provider-auth/gcp
go get github.com/kayiik/llm-provider-auth/browseroauth
go get github.com/kayiik/llm-provider-auth/tokenstore
```

`browseroauth` deliberately does not open a browser, run a callback listener, or
persist tokens. The caller owns those concerns and supplies the redirect URI,
OAuth endpoints, client credentials, scopes, and any provider-specific
authorization or token parameters.

`browseroauth.Config.ClientAuthMode` is required. Use `public_pkce` for public
clients, which require PKCE and never send a client secret, or
`client_secret_post` for confidential clients, which require the secret and
send it in token request bodies. Unknown and zero-valued modes are rejected.

## Quick Start

### Google Cloud Service Account (Vertex AI / Gemini)

```go
import "github.com/kayiik/llm-provider-auth/gcp"

// Parse a service account key read from a file or a secret manager.
cred, err := gcp.Parse(keyJSON)
if err != nil {
    log.Fatal(err)
}

// Keep one TokenCache for the process. It owns its cached tokens, HTTP client
// and clock, and mints a new token shortly before the cached one expires.
var tokens gcp.TokenCache
token, err := tokens.AccessToken(cred, gcp.CloudPlatformScope)
request.Header.Set("Authorization", "Bearer "+token)
```

`Parse` requires the key's `token_uri` to use `https`; plain `http` is accepted
only for a loopback host, such as a local test server. A `TokenCache` keys each
token on the account, key id, private key, token endpoint and scope, so
credentials that differ in any of these never share a token. Its default HTTP
client does not follow redirects, because the exchange request carries a
signed assertion; a redirect fails the exchange with a `TokenError`. A client
supplied through `TokenCache.HTTPClient` should refuse redirects too, for
example with a `CheckRedirect` function that returns `http.ErrUseLastResponse`.

## Refresh-safe credential storage

Providers rotate refresh tokens and detect reuse: presenting an
old refresh token can revoke the whole grant. `tokenstore` prevents two
goroutines or processes from spending the same refresh token.

A store implements `tokenstore.Store`:

- `Load`, `Save`, `ReplaceIfCurrent`, and `RevokeIfCurrent`, with an opaque
  revision assigned on every write. Conditional writes return `ErrConflict`
  when the revision moved.
- A required `Lease(ctx, key)`. The lease must be exclusive across every
  process sharing the store. File-backed stores should hold an OS advisory
  lock on a separate lock file, because a data file rewritten by
  temp-file-and-rename loses any lock held on it.

`tokenstore.Coordinator` combines the two guarantees:

```go
coordinator, err := tokenstore.NewCoordinator(store, refreshFunc)

record, err := coordinator.Token(ctx, "provider")        // refreshes near expiry
record, err = coordinator.Rejected(ctx, "provider", record) // after an upstream 401
```

The coordinator provides these guarantees:

- It refreshes under the lease, then re-reads, so a waiter uses a refresh that
  another holder already completed.
- It never lets a refresh change the bound `AccountID`.
- It revokes the credential when the provider rejects the grant permanently.
  `IsTerminal` classifies the refresh error.
- It never overwrites a login that lands during a refresh.
- It keeps token material out of errors and out of `Record`'s `String`,
  `GoString`, and `slog` output.

Every store implementation should run the conformance suite:

```go
func TestConformance(t *testing.T) {
    storetest.Run(t, func(t *testing.T) storetest.Opener {
        path := filepath.Join(t.TempDir(), "auth.json")
        return func(t *testing.T) tokenstore.Store { return mystore.Open(path) }
    })
}
```

## License

MIT
