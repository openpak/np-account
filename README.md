# np-account

OpenPak's PlayStation 3 account and sign-in adapter. It answers what the PS3 4.93 firmware calls when
you sign in on the XMB (the OAuth sign-in, the console token and the network connection test) and
translates it into calls on the central [`account`](../account) core. It **owns no identity**: no
passwords, no accounts, no links. The core stays console-agnostic; everything Sony-shaped lives here,
the same split as [`nn-account`](../nn-account) for Wii U/3DS.

Architecture: Pier firmware and real PS3s use the same native protocol endpoints.
The central account core owns identity and relationships. No emulator-only game
login/export/verifier is provided. RPCN is used only as private trophy storage
behind native trophy endpoints. Matching2 discovery reports maintenance until
a native agent exists; this adapter does not yet provide native multiplayer.

Status, 2026-10-15: native binding, authenticated `/nav/auth`, self profile,
core-backed friends and leased XMPP presence are implemented. Every active OpenPak
account receives a PlayStation identity, including accounts that never sign in on
PS3. Existing identities are preserved. Enable the captured community path with
`NP_TICKET_KEY`; see [setup and migration](docs/ps3-community.md) and
[wire provenance](docs/provenance.md). The earlier unsigned lab flow reached a
signed-in XMB; the authenticated stream also connects in Pier. Populated-roster
visual verification remains a separate check. OAuth endpoints remain unconfirmed
for this firmware path. `cmd/np-account-lab` uses a fake core for isolated testing.

Design: [`docs/ps3/np-account-design.md`](../docs/ps3/np-account-design.md). Wire facts (from firmware
strings, not from a capture): [`docs/ps3/psn-signin-findings.md`](../docs/ps3/psn-signin-findings.md).
Protocol knowledge comes only from those documents and the OpenPak repos; see the
[clean-room policy](../docs/clean-room-policy.md).

## Run

```sh
cp example.env .env      # fill in the required values
set -a; source .env; set +a
go run ./cmd/np-account
```

Needs a reachable account core (`NP_CORE_ADDR`, `NP_CORE_KEY`). It serves plain HTTP on `NP_HTTP_ADDR`
(default `:8002`); TLS and host routing belong to the reverse proxy. The firmware reaches the routes
through several Sony hostnames (`auth.api.<env>.ac.playstation.net`, `csla.<env>.community.playstation.net`,
`get.net.` / `post.net.playstation.net`, `fj00.ps3.update.playstation.org`); point them all at this one
listener, the paths tell them apart. DNS and the console trust store are Pier-side work (see the findings).

```sh
go test ./...        # needs no database, no core, no network
go vet ./... && gofmt -l .
docker build -t np-account .
```

## Configuration

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `NP_CORE_KEY` | yes | | bearer key for the core's internal gRPC |
| `NP_CLIENT_ID` | yes | | Sony's OAuth client id, embedded in the firmware; operator-supplied, never committed |
| `NP_CLIENT_SECRET` | yes | | Sony's OAuth client secret, same rule |
| `NP_TOKEN_KEY` | yes | | signs every token issued here, at least 32 bytes; rotating it signs everyone out |
| `NP_CORE_ADDR` | no | `localhost:7000` | core gRPC address |
| `NP_HTTP_ADDR` | no | `:8002` | listen address |
| `NP_ENV_ISS_ID` | no | `1` | `env_iss_id` claim (guess) |
| `NP_COMM_DOMAIN` | no | `00` | `comm_domain` claim (guess) |
| `NP_AUTO_ONLINE_ID` | no | `false` | on a first sign-in, derive the online ID from the account's display name |
| `NP_REQUIRE_CONSOLE_TOKEN` | no | `false` | refuse token/authorize requests without a valid `X-NP-CONSOLE-TOKEN` |
| `NP_REDIRECT_PREFIXES` | no | `orbis://` | comma list of `redirect_uri` prefixes a grant code may be sent to |
| `NP_ACCESS_TTL` | no | `1h` | access token / id_token lifetime, at least 1m |

There are no defaults for secrets; startup fails naming the missing ones. Tests use fake values only.

## Endpoints

| Route | What it does |
|---|---|
| `POST /2.0/oauth/token`, `grant_type=password` | `username` = account email, `password`. Checks `client_id`/`client_secret`, then core `Identity.VerifyPassword` (namespace `np`, purpose `console_login`, second factor supported). Replies with JSON `access_token`, `token_type` (`bearer`), `expires_in`, `scope`, `id_token`; header `X-NP-GRANT-CODE`; cookie `npsso_token` (the sign-in session, 1 h, Secure, HttpOnly) |
| `POST /2.0/oauth/token`, `grant_type=authorization_code` | exchanges a grant code (5 min, single use, per process) for a fresh access token and id_token. Account and link are re-read from the core, so a ban after issue is honoured |
| `GET /2.0/oauth/authorize` | with a valid `npsso_token` cookie, issues a new grant code: `302` to `redirect_uri?code=...&state=...` (and `X-NP-GRANT-CODE`), or JSON `{"code": ...}` when no `redirect_uri` is given. Without a session: `302` to `redirect_uri?error=login_required&state=...`. A `redirect_uri` outside `NP_REDIRECT_PREFIXES` is a 400, never followed |
| `GET /csla/{x}/console/lwConsoleToken` | `{"consoleToken": "<signed, 24 h>"}`. `{x}` is accepted and ignored |
| `GET /networktest/get_2m` | 2 MiB of a fixed repeating byte pattern |
| `POST /networktest/post`, `/networktest/post_128` | read and discard the body (first 16 MiB), `200` empty |
| `GET /networktest/trial.txt` | `OK\n` |
| `POST /native/reg/getCountries.action` | binary TLV country list (see `docs/ps3/psn-signin-findings.md`) |
| `POST /native/reg/bindAccount.action` | `username` (email) + `password` -> core `VerifyPassword`; success = TLV element `0x5e` (account id, online ID, country, language, NP credential blob); bad password = result byte `0x14`, suspended = `0x1b`. 2FA accounts are refused (no field for it) |
| `GET /healthz` | `ok` |

`X-NP-CONSOLE-TOKEN`, when present on token/authorize requests, must be a console token this server
issued (else 401 `invalid_console_token`); absence is allowed unless `NP_REQUIRE_CONSOLE_TOKEN` is set.

### Errors

OAuth failures are JSON with `Cache-Control: no-store` (native, nav/auth and community routes use their firmware-specific reply formats):

```json
{"error": "invalid_grant", "error_code": 1003, "error_description": "invalid username or password"}
```

| `error` | HTTP | `error_code` | When |
|---|---|---|---|
| `invalid_request` | 400 | 1001 | missing/malformed fields, disallowed `redirect_uri` |
| `invalid_client` | 401 | 1002 | wrong `client_id` / `client_secret` |
| `invalid_grant` | 401 / 400 | 1003 | wrong email or password (401); bad, expired or reused grant code (400) |
| `unsupported_grant_type` | 400 | 1004 | |
| `second_factor_required` | 401 | 1005 | two-factor account, no code sent |
| `invalid_second_factor` | 401 | 1006 | wrong TOTP or recovery code |
| `account_disabled` | 403 | 1007 | banned, deleted or deletion pending |
| `online_id_required` | 403 | 1008 | no `np` link yet and no online ID could be chosen |
| `invalid_online_id` | 400 | 1009 | fails the online ID rules |
| `online_id_taken` | 409 | 1010 | |
| `too_many_attempts` | 429 | 1011 | core rate limit on second-factor codes |
| `invalid_console_token` | 401 | 1012 | |
| `login_required` | 401 | 1013 | authorize without a valid session |
| `server_error` | 503 / 500 | 1099 | the core is unreachable (fails closed) or something unexpected |

The `error_code` numbers are assigned by OpenPak, not Sony's.

## How it maps to the core

- **Credentials**: the core's `Identity.VerifyPassword` / `VerifySecondFactor`. A password alone never
  signs in a two-factor account. The stock XMB form has no second-factor field, so a console can
  only complete a two-factor sign-in if a client sends the OpenPak form field `second_factor` (TOTP) or
  `recovery_code`; otherwise the account is refused with `second_factor_required`. That fails closed.
- **Links**: namespace `np`, link subject = the **online ID**. `Links.ReserveLink` + `ActivateLink`, then
  the ID is published as the link's public code (`SetLinkPublicCode`). The core compares public codes on
  lower-cased letters and digits, which is what makes online IDs unique ignoring case and punctuation;
  if that step is refused the link is unlinked again and the sign-in gets `online_id_taken`.
- **First sign-in** (no `np` link): the online ID comes from the OpenPak form field `online_id`, or, when
  `NP_AUTO_ONLINE_ID=true`, from the display name (invalid characters become `_`, a leading non-letter gets
  a `P`, cut to 16, padded to 3). Neither exists on the real firmware form, so until the Silk register pages
  exist this is how a first link is made. Otherwise: `online_id_required`.
- **Online ID rules** (enforced here, UNCONFIRMED against the real service): 3 to 16 ASCII characters,
  letters, digits, `-` and `_`, starting with a letter.
- **id_token claims**: `auth_time` (sign-in time, unix seconds), `env_iss_id` (`NP_ENV_ISS_ID`), `user_id`,
  `acct_id` (core account id), `ctry_code` (the account's country, lower-case, `us` if empty), `comm_domain`
  (`NP_COMM_DOMAIN`), `online_id` (the link subject), plus `iss`, `aud`, `iat`, `exp`. It is a compact HS256 JWT
  signed with a key derived from `NP_TOKEN_KEY`.
- **`user_id`**: the first 8 bytes of SHA-256 of `"openpak-np-user-id-v1" 0x00 <core link id>`, big endian,
  top bit cleared (a positive int64), as a decimal string. Stable for the life of the link, different per link,
  no storage needed. Not derived from the online ID, so it does not change if the ID is renamed on the same link; a new link gets a new `user_id`.
- **Tokens** are HMAC-SHA256 signed with per-purpose keys derived from `NP_TOKEN_KEY` and verified statelessly,
  except that grant codes are marked used in process memory: a restart forgets them (they live 5 minutes).

## Not yet

Deliberately out of this cut:

- Sony-compatible ticket signatures and title-specific ticket semantics for games. The captured XMB path uses an owner-local Ed25519-authenticated extension.
- The Silk account pages (register, password reset) on `account.<env>.ac.playstation.net`, commerce and store hosts.
- Invitations and private/offline messages. Friends use core `Social`; presence uses leased core `Sessions`.
- Following core `Events` (revocation is only checked at sign-in and at grant/authorize time).
- Rate limiting of password attempts on this side (the core limits second-factor attempts; password limits are
  the core's business).
- Multi-instance grant-code single use (one process only), persistence, metrics.
- DNS, TLS and trust-store work on the console or Pier side.

## UNCONFIRMED

The OAuth surface below remains unconfirmed. The native, nav/auth, profile and XMPP flows were captured; see docs/provenance.md. In particular:

- That the password grant returns `X-NP-GRANT-CODE`, the `npsso_token` cookie and `id_token` together, and which
  reply the firmware reads each from; that `authorize` is called afterwards with the cookie.
- The value types of the claims (`user_id`, `env_iss_id` and `comm_domain` are strings here) and whether `id_token`
  is a JWT, whether the firmware verifies its signature, and what `env_iss_id` / `comm_domain` values it expects.
- `error_code` value type and numbers, HTTP statuses, and the `error` slug field.
- The `lwConsoleToken` path segment `{x}`, the console token's content and lifetime, and whether the firmware
  always sends `X-NP-CONSOLE-TOKEN`.
- The exact network-test replies (sizes, content types, the content of `trial.txt`).
- Online ID rules and that `client_id` is the only thing sent to `authorize`.
- Whether `np_oauth` accepts our TLS chain ("SCEI DNAS Root 05" pinning is an open question in the findings).

## Layout

`cmd/np-account` main; `internal/config`, `coreclient` (the only code that talks to the core), `oauth`
(token/authorize/console token), `nettest`, `token` (signing), `onlineid` (rules, `user_id`), `server`
(routes); `internal/accountpb` is the vendored core proto (refresh from `../account/proto/openpak/account/v1`);
`internal/fakecore` is the in-process core the tests run against. License: AGPL-3.0-only, like the rest of the
OpenPak servers.
