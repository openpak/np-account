# Evidence: np-account

`NP_TICKET_KEY` enables native `/nav/auth` with the existing owner-local Ed25519
PKCS8 key. Keep that key unchanged during migration. Tickets use the captured
firmware envelope with an OpenPak authentication extension; arbitrary game ticket
compatibility and native multiplayer are not claimed. OAuth remains unconfirmed
against the captured firmware path; see [wire provenance](provenance.md).
