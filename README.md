# PS3 Account Server

OpenPak's PS3 Account Server.

| | |
| --- | --- |
| Network | PS3 |
| Role | PlayStation 3 sign-in adapter over the account core: native account binding, OAuth, console tokens and `/nav/auth` ticket issuance |
| Depends on | [`account`](https://github.com/openpak/account) (core, `NP_CORE_ADDR`), [`np-community`](https://github.com/openpak/np-community), [`np-trophy`](https://github.com/openpak/np-trophy), [`np-tus`](https://github.com/openpak/np-tus) |
| Image | `ghcr.io/openpak/np-account` |
| Licence | AGPL-3.0-only |

## What it serves

| Endpoint | What |
| --- | --- |
| `/native/reg/getCountries.action`, `/native/reg/bindAccount.action`, `/nav/auth` | Native account binding and `/nav/auth` tickets |
| `/native/{reg,cam,store,upgrade,pwd}/*.action` (Account Information) | Name, opt-ins, wallet options, address, history and service lists (empty); save actions and password change answer 503 (nothing is persisted) |
| `/2.0/oauth/token`, `/2.0/oauth/authorize`, `/csla/{x}/console/lwConsoleToken` | OAuth and console tokens |
| `/networktest/*` | Network tests |
| `/update/ps3/list/{region}/ps3-updatelist.txt` | PS3 update list |
| `/healthz` | Health check |
| `/basic_view/`, `/basic_update/`, `/a/`, `/np/resource/title/`, `/nsx/` | Forwarded to np-community |
| `/trophy/`, `/np/resource/trophy/` | Forwarded to np-trophy |
| `/user_storage/`, `/tss/`, `/np/resource/title/{commid}/storage/` | Forwarded to np-tus (`NP_TUS_URL`, optional) |
| `/ranking_update/`, `/ranking_view/`, `/ranking_clan_view/`, `/np/resource/title/{commid}/ranking/` | Forwarded to np-score (`NP_SCORE_URL`, optional) |
| `/tpl/` | Forwarded to np-update (`NP_UPDATE_URL`, optional): title patch lists |
| `/uploader/` | Forwarded to np-uploader (`NP_UPLOADER_URL`, optional): message attachments |

## Run

```sh
cp example.env .env   # fill in required values
set -a; . ./.env; set +a
GOWORK=off go run -mod=vendor ./cmd/np-account
```

## Docs

- [Protocol](docs/protocol.md)
- [Deploy](docs/deploy.md)
- [Handles](docs/handles.md)
- [Provenance](docs/provenance.md)
- [Service split](docs/service-split.md)

## Licence

AGPL-3.0-only. See [LICENSE](LICENSE).
