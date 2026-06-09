# SingleStore Cloud IAM HTTP API

This directory documents the authentication service HTTP API for customers who prefer
to integrate without the `s2iam` client libraries.

## Published documentation

- [API reference (Markdown)](api.md)
- [API reference (HTML)](api.html)
- [OpenAPI spec](openapi.yaml) — source of truth

## Regenerate documentation

After editing `openapi.yaml`, regenerate and commit the outputs:

```bash
make docs-api          # HTML + Markdown
make docs-api-html     # HTML only (Redoc)
make docs-api-md       # Markdown only (Widdershins)
make docs-api-lint     # Validate the OpenAPI spec
```

Requires Node.js/npm for `npx`.

## Quick reference

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/auth/iam/database` | Cloud identity → engine/database JWT |
| POST | `/auth/iam/api` | Cloud identity → management API JWT |
| GET | `/auth/oidc/op/Customer/.well-known/jwks.json` | Public keys to verify returned JWTs |

**Host:** `https://authsvc.singlestore.com`

Database (engine) and management API JWTs are both available. APIs may change
before general availability.

Authentication uses cloud provider credentials in request headers (AWS key triple,
GCP identity token, or Azure managed-identity bearer token). See the [API reference](api.md)
for details.
