# Protocol: np-account

Account routes: `/native/reg/getCountries.action`, `/native/reg/bindAccount.action`,
`/nav/auth`, `/2.0/oauth/token`, `/2.0/oauth/authorize`,
`/csla/{x}/console/lwConsoleToken`, `/networktest/*`,
`/update/ps3/list/{region}/ps3-updatelist.txt`, `/healthz`.
Forwarded prefixes: `/basic_view/`, `/basic_update/`, `/a/`, `/np/resource/title/`
to community; `/trophy/`, `/np/resource/trophy/` to trophies.

## Ticket

`/nav/auth` issues tickets in the captured firmware envelope with an OpenPak authentication extension, signed Ed25519 (`NP_TICKET_KEY`). Arbitrary game ticket compatibility and native multiplayer are not provided.

## Routing

The HTTP/TLS entry point forwards community and trophy paths to their owners ([np-community](https://github.com/openpak/np-community), [np-trophy](https://github.com/openpak/np-trophy)); there are no in-process implementations. XMPP connects directly to np-community, so releasing np-account does not end those streams. This service stores no identity or relationships; the account core owns them. Native binding, OAuth, console tokens and `/nav/auth` ticket issuance stay here, with network tests and update-list discovery.
