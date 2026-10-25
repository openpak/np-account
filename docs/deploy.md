# Deploy: np-account

Copy `example.env` to `.env`, supply operator credentials, and export it before
`GOWORK=off go run -mod=vendor ./cmd/np-account`. OAuth client ID/secret, token key
(at least 32 bytes), core key and both service URLs are required. `NP_CORE_ADDR`
defaults to `localhost:7000`; `NP_HTTP_ADDR` defaults to `:8002`.

Optional OAuth settings: `NP_ENV_ISS_ID=1`, `NP_COMM_DOMAIN=00`,
`NP_AUTO_ONLINE_ID=false`, `NP_REQUIRE_CONSOLE_TOKEN=false`,
`NP_REDIRECT_PREFIXES=orbis://`, `NP_ACCESS_TTL=1h` (at least one minute).
`NP_TLS_ADDR`, `NP_TLS_CA_CERT` and `NP_TLS_CA_KEY` enable the firmware RSA-kex TLS
front. Otherwise serve plain HTTP behind a compatible TLS terminator.

## Build and verify

```sh
GOWORK=off go test -mod=vendor ./...
GOWORK=off go vet -mod=vendor ./...
podman build -t np-account .
```

The checked-in vendor tree makes the repository independently buildable, including
integration tests that call the extracted services over HTTP. Refresh shared code
with sibling repositories present: `GOWORK=off go mod vendor`. Release tags publish
`ghcr.io/openpak/np-account`; samples in `deploy/` are not applied automatically.
`cmd/np-account-lab` now serves account routes only with a fake core; it does not
start community/XMPP. AGPL-3.0-only.
