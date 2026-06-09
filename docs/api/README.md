# SingleStore Cloud IAM HTTP API

This directory documents the authentication service HTTP API for customers who prefer
to integrate without the `s2iam` client libraries.

## Source of truth

- [`openapi.yaml`](openapi.yaml) — OpenAPI 3.0 specification

## Generate documentation

From the repository root (requires Node.js/npm for `npx`):

```bash
make docs-api          # HTML + Markdown
make docs-api-html     # HTML only (Redoc)
make docs-api-md       # Markdown only (Widdershins)
make docs-api-lint     # Validate the OpenAPI spec
```

Generated files are written to `docs/generated/` (gitignored).

## Quick reference

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/auth/iam/database` | Cloud identity → engine/database JWT |
| POST | `/auth/iam/api` | Cloud identity → management API JWT |
| GET | `/auth/oidc/op/Customer/.well-known/jwks.json` | Public keys to verify returned JWTs |

**Host:** `https://authsvc.singlestore.com`

Authentication uses cloud provider credentials in request headers (AWS key triple,
GCP identity token, or Azure managed-identity bearer token). See the OpenAPI spec
for details and examples.
