# Cloudflare DNS record reconciliation

<!-- 561-group-standards:badges:start -->
[![Red Cup Engineering](https://img.shields.io/badge/561%20Group-Red%20Cup%20Engineering-c0392b)](https://github.com/red-cup-engineering)
[![License: MIT](https://img.shields.io/badge/license-MIT-c0392b)](LICENSE)
[![Indigenous data: CARE](https://img.shields.io/badge/Indigenous%20data-CARE-4b6f44)](https://github.com/red-cup-engineering/.github/blob/main/GOVERNANCE.md)
[![Tips welcome](https://img.shields.io/badge/tips-welcome-d4a017)](https://github.com/561-group/.github/blob/main/TIPS.md)
<!-- 561-group-standards:badges:end -->

One action: reconcile one explicitly declared DNS record through an already
verified named Cloudflare profile. The engineering service contains no customer
zone, hostname, or target. Operational packages own those declarations.

The pure import and CLI are package-qualified. The CLI reads one JSON request
from stdin and emits a non-secret JSON receipt.

```sh
reconcile-cloudflare-dns-record < request.json
```

`mapping.state` is `"present"` (default) or `"absent"`. Absent skips
`content`/`proxied`/`ttl` and deletes the sole matching record instead of
creating or updating one:

```json
{
  "authentication": {"profile": "named-profile", "scopes": ["dns:write"]},
  "mapping": {"zone": "example.test", "type": "CNAME", "name": "app.example.test", "state": "absent"}
}
```

## Authentication

Two authentication shapes; an `authentication` object carrying both
`profile` and `token` is refused.

- `authentication.profile` — a named Wrangler keyring profile, inspected
  through `@red-cup-engineering/linux-cloudflare-authentication-service`.
- `authentication.token.environmentVariable` — the name of an environment
  variable holding a Cloudflare API token with the DNS edit scope. The
  keyring inspection is skipped; the receipt's `inspection` carries
  `{"mode": "environment-token", "environmentVariable": "<NAME>"}` and
  `credentialReturned: false`. An unset or empty variable refuses with
  `error.code === "TOKEN_ENVIRONMENT_VARIABLE_UNSET"`; the value itself is
  never logged or included in any receipt or error.

Absent request using the token shape, with the token supplied by
`CLOUDFLARE_API_TOKEN`:

```json
{
  "authentication": {"token": {"environmentVariable": "CLOUDFLARE_API_TOKEN"}, "scopes": ["dns:write"]},
  "mapping": {"zone": "example.test", "type": "CNAME", "name": "app.example.test", "state": "absent"}
}
```

The CLI never reads `.env` itself; supply the token through Node's own
`--env-file`:

```sh
node --env-file=/home/emsenn/info/.env scripts/reconcile-cloudflare-dns-record.mjs < request.json
```
