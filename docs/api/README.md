# SingleStore Cloud IAM HTTP API

This directory documents the authentication service HTTP API for customers who prefer
to integrate without the `s2iam` client libraries.

## Published documentation

- [API reference (HTML)](https://redocly.github.io/redoc/?url=https://raw.githubusercontent.com/singlestore-labs/singlestore-auth-iam/main/docs/api/openapi.yaml) — rendered via Redoc (reads `openapi.yaml` from this repo)
- [API reference (Markdown)](api.md) — readable in the GitHub repo browser
- [OpenAPI spec](openapi.yaml) — source of truth

### Why not link to `api.html` in the repo?

GitHub's repo browser shows HTML files as source code; it does not render them.
The committed [`api.html`](api.html) / [`index.html`](index.html) bundle is for optional
[GitHub Pages](https://docs.github.com/en/pages) self-hosting.

If GitHub Pages is enabled for this repository, the workflow in
`.github/workflows/api-docs-pages.yml` deploys `docs/api/` to
`https://singlestore-labs.github.io/singlestore-auth-iam/` — but that URL only works
**after** an admin enables Pages (Settings → Pages → Source: GitHub Actions) and a
successful deploy. Until then, use the Redoc link above.

## Regenerate documentation

After editing `openapi.yaml`, regenerate and commit the outputs:

```bash
make docs-api          # HTML + Markdown (+ index.html for optional Pages)
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
