# Historical combined-adapter notes

The services are now split. Use [service-split.md](service-split.md) for current
processes, ports and migration. Operator commands below now run in np-community;
account owns native binding and /nav/auth, community owns profiles and XMPP, and
np-trophy owns trophy discovery and protocol. The remaining text records the
pre-split protocol behavior.

# Authenticated PS3 community adapter

The captured XMB path is native bindAccount → POST /nav/auth → self profile →
TLS/XMPP on 5223. All three identity-bearing steps now use the account core.

Enable it with `NP_TICKET_KEY=/owner/local/np-ticket-key.pem` (Ed25519 PKCS8 PEM).
Generate the file with `umask 077; openssl genpkey -algorithm ED25519 -out ...`.
Never commit the key. The HTTP listener remains plain behind the lab RSA-kex TLS
terminator; XMPP listens on `NP_XMPP_ADDR` (default 127.0.0.1:8523) behind TLS 5223.
Changing the signing key invalidates issued tickets. Ticket authentication is an
OpenPak extension; Sony ticket signatures for arbitrary games remain unresolved.

`/nav/auth` verifies loginid/password through the core and refuses accounts that
require an uncompleted second factor. Identity numbers share the native binding
function, and tickets expire. Profile and XMPP authentication verify the signature
and re-read current account/link status; XMPP rechecks bans/revocation periodically.
Firmware-appended device data is not trusted as authentication state.

Every active OpenPak user gets a real `np` link even without a PS3 login. The
background reconciler scans the core's home-only `Identity.ListAccounts` directory
at startup and every minute. Existing IDs remain unchanged. A display-name
collision receives a stable account-derived suffix. Friend-roster reads provision
missing links immediately as well. The core holds every identity and relationship;
there is no second friend database in this adapter.

One-shot migration / inspection (load the normal operator environment first):

```sh
go run ./cmd/np-identities -migrate
go run ./cmd/np-identities -online-id AndroidTest
go run ./cmd/np-identities -list
```

The migration is idempotent. It does not create OpenPak accounts, change passwords,
add friendships, rename existing PS3 IDs, or re-enable inactive users. A directory
export can be passed with `-account-ids` for an explicit account subset.

Roster comes from core Social.ListFriends, filtered through CheckInteraction and
active-account checks. Pending requests use the core's request/accept lifecycle;
XMPP subscription/removal operations call the same core graph. Presence registers
a core session only after available presence, renews its lease, and expires on
unavailable/disconnect. Core presence for friends includes other OpenPak adapters.
Graph and presence changes are projected every ten seconds. Removal/blocks produce
roster removal and unavailable presence. Stanza input, nesting, deadlines, writes,
and connection count are bounded. Unsupported messages/IQ operations fail explicitly.

Tests include ticket byte tampering, truncation, wrong-key/expiry, native/ticket ID
consistency, failed passwords/2FA, core ban checks, migration/collision idempotence,
friends without a console login, live core presence and disconnect cleanup,
subscription policy, and removal after a block. Wire facts and provisional fields
are in [provenance.md](provenance.md). Real populated-roster UI validation is a
separate final check; no game multiplayer or invitations are claimed here.

The stream sends whitespace keepalives every twenty seconds (TCP ACKs alone do
not keep VSH's receive-idle timer alive). Avatar URLs come from the account core's
validated 256px PNG; short signed capabilities fit VSH's URL buffer. Serve HTTP
`/basic_view/func/get_profile` and `/a/` through this adapter as well as HTTPS
self-profile. Public friend-profile requests contain no ticket and return only
public profile data; account status is checked on profile and image reads.

Firmware can serialize friend JIDs with the viewer's region, so validate the
PlayStation domain shape independently of the target account country. Trophy
discovery returns HTTP 200 with `nptrophy status="maintenance"` until that service
is implemented. Incoming whitespace refreshes the socket idle deadline even when
the XML decoder has not produced a complete stanza.

The website also renders deterministic default pictures absent from Media storage.
`go run ./cmd/np-avatar-backfill` copies the canonical public website PNGs at both
sizes into the core only for missing avatars. Existing avatars are skipped. This
was run for all active users on 2026-10-15: 11 backfilled, 2 already stored.
New accounts still need the website to publish defaults or another backfill until
default avatar publication is unified across account creation paths.

Online friend status uses the core session namespace for the console name and
its reported client for known emulator names, such as `Online on Switch (Harbor)`
or `Online on PS3 (Pier)`. Hardware and unknown clients omit the parentheses.
Reported title IDs follow the platform label when present.
