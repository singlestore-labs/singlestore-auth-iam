# SingleStore Cloud IAM HTTP API

This directory documents the authentication service HTTP API for customers who prefer
to integrate without the `s2iam` client libraries.

## Published documentation

- [Authentication guide](AUTHENTICATION.md) — how to obtain cloud credentials, curl examples, common mistakes
- [OpenAPI spec](openapi.yaml) — source of truth for endpoints, schemas, and security schemes
- [API reference (HTML)](https://redocly.github.io/redoc/?url=https://raw.githubusercontent.com/singlestore-labs/singlestore-auth-iam/main/docs/api/openapi.yaml) — rendered via Redoc (reads `openapi.yaml` from this repo)

### GitHub Pages (self-hosted Redoc)

GitHub's repo browser shows HTML as source; it does not render it. Generated HTML
(`api.html`, `index.html`) is **not** checked into git — it is built in CI when
GitHub Pages deploys.

If GitHub Pages is enabled for this repository, the workflow in
`.github/workflows/api-docs-pages.yml` generates Redoc HTML and deploys `docs/api/` to
`https://singlestore-labs.github.io/singlestore-auth-iam/` — but that URL only works
**after** an admin enables Pages (Settings → Pages → Source: GitHub Actions) and a
successful deploy. Until then, use the Redoc link above.

## Regenerate documentation locally

After editing `openapi.yaml`:

```bash
make docs-api-lint     # Validate the OpenAPI spec
make docs-api-html     # Generate api.html + index.html (gitignored)
```

Requires Node.js/npm for `npx`.

We do not commit generated Markdown. Swagger-to-Markdown tools (Widdershins, Redocly,
openapi-generator) produce poor output for this spec — especially multi-header AWS
auth — so human-readable auth guidance lives in [AUTHENTICATION.md](AUTHENTICATION.md)
and machine-readable schemas in [openapi.yaml](openapi.yaml). Redoc HTML is the
interactive reference.

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
GCP identity token, or Azure managed-identity bearer token). See the
[Authentication guide](AUTHENTICATION.md) for credential acquisition and curl examples,
or the [OpenAPI spec](openapi.yaml) for endpoint schemas.
