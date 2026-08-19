# delinea-common

Dependency-free Go packages for Delinea Secret Server, Secret Server Cloud,
and the Delinea Platform.

| Package | Purpose |
|---|---|
| [`api`](api/) | OAuth2 grants, interactive Platform login, backend probing, vault discovery and trust validation, token caching, retries, and authenticated raw REST requests. |
| [`secrets`](secrets/) | Resolves secret fields by ID or path, including file attachments, into ordered name/value pairs. |
| [`secrets/ciout`](secrets/ciout/) | Validated and escaped shell, GitHub Actions, and Azure Pipelines delivery formats. |
| [`secrets/retrievejson`](secrets/retrievejson/) | Strict parser for the shared CI retrieve-secrets JSON schema. |
| [`secrets/secretstest`](secrets/secretstest/) | Map-backed `secrets.Fetcher` for tests in consuming modules. |

The module imports only the Go standard library. Its dependency-free invariant
is enforced by the ordinary test suite and CI.

## API client

Normalize operator-supplied URLs with `api.NormalizeURL`, construct one client
per credential, and reuse it. Clients are safe for concurrent use and share an
in-memory token cache by default.

```go
baseURL, err := api.NormalizeURL(rawURL)
if err != nil {
	log.Fatal(err)
}
client, err := api.New(api.Config{
	URL:      baseURL,
	Username: username,
	Password: password,
})
if err != nil {
	log.Fatal(err)
}
defer client.CloseIdleConnections()

resp, err := client.Do(ctx, api.Request{
	Method: "GET",
	Path:   "/api/v1/users/current",
})
if err != nil {
	log.Fatal(err)
}
defer resp.Body.Close()
```

For the Delinea Platform, use `ClientID` and `ClientSecret` and set `Target` to
`api.TargetPlatform`. `api.Request.UseVault` routes a request through Platform
vault discovery. A pre-obtained bearer token can be supplied in `Config.Token`.

## Secret resolution

```go
client, err := secrets.New(secrets.Config{
	URL:      baseURL,
	Username: username,
	Password: password,
})
if err != nil {
	log.Fatal(err)
}
defer client.CloseIdleConnections()

vars, err := client.Resolve(ctx, []secrets.Mapping{{
	EnvName:  "DB_PASSWORD",
	SecretID: 126,
	Field:    "password",
}})
if err != nil {
	log.Fatal(err)
}
```

Use `secrets.NewWithClient` to share an `api.Client`, or
`secrets.NewWithFetcher` to supply another concurrency-safe backend. The
`secretstest` package provides a deterministic fetcher for consumer tests.

## Security model

Credentials and configured sensitive headers are redacted from configuration,
errors, and operational logging. Token grants and mutating API requests do not
follow redirects. TLS configuration is client-local. Platform vault URLs are
validated before use, and alternate ports require an explicit `host:port`
allowlist entry. Nothing is persisted by these packages.

Callers still own secret delivery: avoid argv and logs, close response bodies,
and use the formatters in `secrets/ciout` when a CI wire format is required.

The precise retry, timeout, authentication-recovery, and upstream API contracts
are recorded in [docs/api-contracts.md](docs/api-contracts.md). Live test
fixtures and strict-mode operation are documented in [docs/E2E.txt](docs/E2E.txt).

The `delinea-util` command that consumes these packages is maintained in
[`DelineaXPM/delinea-tools`](https://github.com/DelineaXPM/delinea-tools).

MIT licensed. See [LICENSE](LICENSE).
