# Changelog: np-account

## Unreleased

- Native (Account Information, `/native/{service}/`): getAddr and getResAddr answer with the address
  elements the firmware requires (empty, country from the last authenticate of the same client address);
  getTranHist, getCnslAct and getSrvs answer with empty lists; setName, setLid, setOptIn, setWalOpt,
  remPay and updPass answer 503 (firmware "unavailable"): nothing is persisted, the request names no
  account and the core has no password-change call. The firmware sends no cookie
  after authenticate, so these replies are not per account.

## v0.3.4 — 2026-11-02

- Forwards `/tpl/` title patch lists to np-update (`NP_UPDATE_URL`) and `/uploader/` message
  attachments to np-uploader (`NP_UPLOADER_URL`).
- Native: getCountries and delSess answer on every service prefix (cam/, reg/, store/, upgrade/, pwd/).
  Account Information sends cam/getCountries after cam/authenticate; the empty catch-all reply
  failed the firmware's 0x5b list lookup and the screen closed with no message.
- Native: getName, getOptIn and getWalOpt (Account Information's personal-info load) answer with
  the elements the firmware requires: empty names, mail opt-ins off, wallet options off.
- Split PS3 account, community/XMPP and native trophies into independent services; share protocol primitives through vendored np-common.


## Unreleased

- Follows the account core's event stream: a ban or a started deletion denies the account at once and
  closes its XMPP streams; unban and restore lift it; final erasure cuts and drops the account.

## v0.2.1 — 2026-10-16

- PS3 TLS leaves keep the SNI exactly as the firmware sent it (mixed-case service IDs).

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
