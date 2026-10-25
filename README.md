# PS3 Account Server

OpenPak's PS3 Account Server.

| | |
| --- | --- |
| Network | PS3 |
| Role | PlayStation 3 sign-in adapter over the account core: native account binding, OAuth, console tokens and `/nav/auth` ticket issuance |
| Depends on | [`account`](https://github.com/openpak/account) (core, `NP_CORE_ADDR`), [`np-community`](https://github.com/openpak/np-community), [`np-trophy`](https://github.com/openpak/np-trophy) |
| Image | `ghcr.io/openpak/np-account` |
| Licence | AGPL-3.0-only |

## What it serves

| Endpoint | What |
| --- | --- |
| `/native/reg/getCountries.action`, `/native/reg/bindAccount.action`, `/nav/auth` | Native account binding and `/nav/auth` tickets |
| `/2.0/oauth/token`, `/2.0/oauth/authorize`, `/csla/{x}/console/lwConsoleToken` | OAuth and console tokens |
| `/networktest/*` | Network tests |
| `/update/ps3/list/{region}/ps3-updatelist.txt` | PS3 update list |
| `/healthz` | Health check |
| `/basic_view/`, `/basic_update/`, `/a/`, `/np/resource/title/` | Forwarded to np-community |
| `/trophy/`, `/np/resource/trophy/` | Forwarded to np-trophy |

## Run

```sh
cp example.env .env   # fill in required values
set -a; . ./.env; set +a
GOWORK=off go run -mod=vendor ./cmd/np-account
```

## Docs

- [Protocol](docs/protocol.md)
- [Evidence](docs/evidence.md)
- [Deploy](docs/deploy.md)
- [Notes](docs/notes.md)
- [Handles](docs/handles.md)
- [Provenance](docs/provenance.md)
- [PS3 community](docs/ps3-community.md)
- [Service split](docs/service-split.md)

## Licence

AGPL-3.0-only. See [LICENSE](LICENSE).
