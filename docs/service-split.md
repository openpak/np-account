# Independent PS3 services

Implemented locally on 2026-10-25. Existing np-account and np-trophy repository
histories remain intact. np-community and np-common are independent sibling Git
repositories; their origin URLs name openpak/np-community and openpak/np-common.
No remote repositories, release tags or live deployments are created by this change.

## Ownership and contracts

np-account owns credential checks, native binding, `/nav/auth`, OAuth and console
tokens. np-community owns profiles, avatars, roster reconciliation and XMPP.
np-trophy owns both native trophy protocol and the existing private storage API.
np-common contains shared protocol/client code, not service implementations.
The core remains the sole owner of identity, links, friendships and presence leases.

Account and community use the same shared NP provisioning policy, preserving
existing links and immutable handles. The ticket envelope, numeric account IDs,
credential derivation and avatar capabilities are unchanged. Mount the existing
Ed25519 key read-only in all three services. All consumers recheck current core
account/link state; each process independently consumes account invalidations.
Only community owns XMPP sockets and expires their core presence leases.

Trophy protocol handlers now use the existing Store directly, preserving its
schema and merge rules. The private bearer API stays on a separate listener.
`NP_TROPHY_BACKEND` and `NP_TROPHY_BACKEND_KEY` are no longer used by np-account.
No internal sign-in API is introduced and passwords never pass to community or trophies.

## Routing

Keep existing DNS and PS3 trust-store configuration. Existing firmware HTTP/S
hosts can continue to reach np-account, which forwards by path:

- `/basic_view/`, `/basic_update/`, `/a/`, `/np/resource/title/` → `NP_COMMUNITY_URL`.
- `/trophy/`, `/np/resource/trophy/` → `NP_TROPHY_URL` (native port 8531).
- Account, network-test and update-list routes remain local.

Both upstream origins are mandatory and checked at account startup. Forwarding
preserves method, host, path, query, body and firmware reply headers. A failed
upstream returns 503; there is no in-process fallback. Unknown native routes
remain the owner's 404. The private trophy API is never forwarded.

Route TCP 5223 directly to np-community:8523, using `NP_XMPP_TLS=1` with the
existing PS3 CA or retaining a separate compatible TLS terminator. Do not route
XMPP through np-account. This is what allows account/trophy deployments without
ending community connections. Account's gateway can temporarily interrupt new
HTTP requests while it restarts; existing XMPP streams remain with community.
Path routing at a TLS-terminating proxy may instead target the services directly.
SNI-only passthrough cannot split paths on a shared hostname.

Defaults: account HTTP 8002; community HTTP 8003 / XMPP 8523; trophies native HTTP
8531 / private HTTP 8530. Each service optionally supports its own PS3 HTTP TLS
listener via `NP_TLS_ADDR` and the existing CA files.

## Build and deployment samples

Every executable has its own Dockerfile and tag-triggered multiarch release
workflow. Shared code is included in each service's tracked vendor tree using
sibling `replace` directives. Release builds and tests need only that repository:
`GOWORK=off go test -mod=vendor ./...`. Account's integration tests vendor the
community/native trophy handlers as test dependencies; its executable imports
neither service. np-common is a library and has a test workflow, not an image.

After shared changes, run `GOWORK=off go mod vendor` in community, trophies and
account, then test each. After community/trophy handler changes, refresh account's
vendor tree as well. This matches the workspace's Switch dependency convention.

Each service has a sample Quadlet in `deploy/`, with separate environment files.
The account repo also includes `deploy/compose.yml` to build/start all three from
sibling checkouts on an existing `openpak` network. Copy each `example.env` to its
repo's `.env`, supply real values and the existing database/core addresses, then
set `NP_PS3_KEYS_DIR` to the host directory containing the existing key files.
Examples do not provision identity, migrate live deployments, or manage TLS/DNS.
The sample TCP router preserves the existing HTTPS gateway and moves XMPP to
community. Adapt entrypoint names/host rules to the operator's configuration.

## Cut-over and rollback

1. Build and publish the three service images and make the two new repos available
   for future shared-code updates. Save the exact old image IDs and routing config.
2. Start np-trophy against the existing trophy database and keys. Check native
   discovery and private bearer API on their distinct ports.
3. Start np-community using the same core, signing key and resource key. Verify
   profiles and core event consumption. Reconciliation is idempotent; existing
   link IDs, numeric identities and avatars do not change.
4. Set account's `NP_COMMUNITY_URL` and `NP_TROPHY_URL`, move TCP 5223 to community,
   then replace the old account process. One reconnect is expected during the
   initial transfer because its sockets belonged to the old process.
5. Verify native binding → `/nav/auth` → profile → authenticated XMPP; inspect the
   friend roster, public avatars, trophy discovery/read/sync and ban revocation.
   Restart account and trophy separately and confirm XMPP remains connected.

Rollback restores the old account image and original XMPP route. Stop the new
community service to avoid duplicate sessions. The trophy database schema has not
changed; the old trophy image and native adapter can use the same database/key.
Keep signing material unchanged in either direction. Console/Pier visual checks
and an operator cut-over remain separate from the local automated checks.

Matching2 continues to advertise maintenance. Network tests and update discovery
remain in account for this extraction; moving those to core connectivity can be
handled independently.

## Local validation

All four modules pass `go test ./...` and `go vet ./...` with workspace mode off.
Account/community/trophy integration paths also pass the race detector. Native
and private trophy tests ran against a disposable Postgres 17 database, covering
schema reuse, persisted sync, first-unlock semantics, account revocation and
separate public/private listeners. An authenticated XMPP stream survives shutdown
of the account HTTP server in the integration test.

All three service repositories pass offline tests and vet from isolated source
copies without sibling repositories. Linux ARM64 executables build from those
copies using vendor mode (VCS stamping disabled for the copied source contexts).
Docker builds using Go 1.26 produce all three amd64 images as user `app`:
`openpak/np-account:split-check`, `openpak/np-community:split-check`, and
`openpak/np-trophy:split-check`. Workflow YAML and the Compose sample validate.
Podman build verification hit an overlay-mount limitation on the scratch filesystem;
Docker completed the same Dockerfiles. No live deployment or console UI test was run.
