# SingleStore Cloud IAM HTTP API

This directory documents the authentication service HTTP API for customers who prefer
to integrate without the `s2iam` client libraries.

## Published documentation

- [API reference (HTML)](https://singlestore-labs.github.io/singlestore-auth-iam/) — rendered Redoc site (GitHub Pages)
- [API reference (Markdown)](api.md) — readable in the GitHub repo browser
- [OpenAPI spec](openapi.yaml) — source of truth

The committed [`api.html`](api.html) file is the GitHub Pages payload; GitHub's repo
browser shows HTML as source code rather than rendering it. Use the Pages link above
for the interactive reference.

GitHub Pages is deployed from `docs/api/` on pushes to `main` (see
`.github/workflows/api-docs-pages.yml`). The first deploy may require enabling Pages
under repository **Settings → Pages → Build and deployment → Source: GitHub Actions**.

## Regenerate documentation

After editing `openapi.yaml`, regenerate and commit the outputs:

```bash
make docs-api          # HTML + Markdown (+ index.html for Pages)
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
