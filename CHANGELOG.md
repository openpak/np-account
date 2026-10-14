# Changelog: np-account

## Unreleased

- 2026-10-14: first cut. OAuth `POST /2.0/oauth/token` (password grant and grant-code exchange), `GET
  /2.0/oauth/authorize`, console token, network-test endpoints, all backed by the account core (namespace
  `np`, link subject = online ID). Tested against an in-process fake core. Nothing confirmed against a real
  firmware capture. No tickets, no Silk pages, no presence/friends.
