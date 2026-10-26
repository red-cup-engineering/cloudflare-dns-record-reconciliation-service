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

Set `dryRun: true` on that same request to read the exact zone and matching
record without making any mutating request. Its receipt has `disposition:
"planned"`, an `action` of `create`, `update`, `remove`, `none` or `blocked`, and the
observed `before` record (or `null` when absent). Token dry runs accept the
explicit `dns:read` scope; actual reconciliation still requires `dns:write`.
Named profile inspection retains its original authentication requirements.

The read includes every record type at the exact name. A CNAME conflicting
with an A or AAAA record, or an A/AAAA mapping conflicting with a CNAME, has
`action: "blocked"` and compact observed records in `conflicts`. Applying
that mapping refuses; the service never removes a conflicting record
implicitly. A paginated record collection also refuses instead of accepting
an incomplete observation. Other record types retain their existing behavior.

After accepting a plan, pass its `before` as `expectedRecord` with the original
mapping to apply. A different record ID, value, type, name, proxy setting or TTL
refuses before mutation. `expectedRecord: null` requires the record still to be
absent. Omitting `dryRun` and `expectedRecord` preserves the existing apply
behavior. An environment-token call loads no Linux keyring or Wrangler runtime;
the named-profile path loads its original authentication provider when used.

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

For an environment token, optional `authentication.expectedAccountId` must be
a 32-character Cloudflare account ID. The exact resolved zone must belong to
that account before the service reads or changes its records; a missing or
different account refuses. Existing calls that omit this field retain their
original behavior.

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

