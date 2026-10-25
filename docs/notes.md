# Notes: np-account

OpenPak's PlayStation 3 sign-in adapter over the console-agnostic account core.
Owns native account binding, OAuth, console tokens and `/nav/auth` ticket issuance.
Network tests and update-list discovery remain here. Identity and relationships
belong to the account core; this service stores neither.

PS3 services now have independent repositories, binaries and images:
[np-community](https://github.com/openpak/np-community) owns profiles, avatars,
friends and XMPP; [np-trophy](https://github.com/openpak/np-trophy) owns native trophy
routes and storage; [np-common](https://github.com/openpak/np-common) supplies shared
protocol primitives. See [the split and migration guide](service-split.md).

The existing HTTP/TLS entry point forwards community and trophy paths to their
owners. XMPP connects directly to np-community, so releasing this service does
not end those streams. There are no in-process community/trophy implementations.
