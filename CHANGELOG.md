# Changelog: np-account

## v0.2.0 — 2026-10-16

- Serves on OpenPak's primary server: Traefik passes the PS3 SNIs through to the new firmware TLS
  listener (`NP_TLS_ADDR`, RSA key exchange TLS 1.0-1.2, an exact leaf per SNI minted from the
  OpenPak PS3 CA in `NP_TLS_CA_CERT`/`NP_TLS_CA_KEY`, HTTP/1.1 only); XMPP can share it
  (`NP_XMPP_TLS=1`).
- PS3 system update list (`/update/ps3/list/<region>/ps3-updatelist.txt`), always "already latest".
- Community surface from the lab runs: Ed25519 tickets, `/nav/auth`, self and friend profiles,
  avatars, trophies, XMPP presence, account provisioning over the core's social/media/directory APIs.
- Release workflow: tag `v*.*.*` publishes `ghcr.io/openpak/np-account` for amd64 and arm64.

## Unreleased

- 2026-10-14: first cut. OAuth `POST /2.0/oauth/token` (password grant and grant-code exchange), `GET
  /2.0/oauth/authorize`, console token, network-test endpoints, all backed by the account core (namespace
  `np`, link subject = online ID). Tested against an in-process fake core. Nothing confirmed against a real
  firmware capture. No tickets, no Silk pages, no presence/friends.
