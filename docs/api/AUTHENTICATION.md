# Authentication guide

This guide explains how to authenticate directly against the SingleStore Cloud IAM
HTTP API without the `s2iam` client libraries. For endpoint schemas and response
codes, see the [OpenAPI spec](openapi.yaml) and the [Redoc HTML reference](https://redocly.github.io/redoc/?url=https://raw.githubusercontent.com/singlestore-labs/singlestore-auth-iam/main/docs/api/openapi.yaml).

**Production host:** `https://authsvc.singlestore.com`

## Two-phase model: cloud credentials in, SingleStore JWT out

Every IAM exchange endpoint follows the same pattern:

1. **You send cloud provider credentials in request headers.** These prove that the
   caller is a specific AWS role, GCP service account, or Azure managed identity.
   This is *inbound* authentication — credentials flow **into** the auth service.

2. **The service returns a SingleStore JWT in the JSON response body.** On `200 OK`,
   the response always includes a `jwt` field. Production responses may also include
   `expires_at` and `audience`; reference clients only depend on `jwt`. This is
   *outbound* authentication — the token flows **out** to your application.

The SingleStore JWT is **not** what you put on the `Authorization` header when calling
these exchange endpoints. For AWS you send three custom headers; for GCP and Azure you
send a **cloud provider** bearer token on `Authorization`. The `jwt` field in the
response is a separate token issued by SingleStore for engine or management API access.

Validate returned JWTs with the public keys at
`GET /auth/oidc/op/Customer/.well-known/jwks.json`.

Pick **exactly one** cloud provider per request. Sending AWS headers and a GCP bearer
token on the same request is invalid.

## AWS

### How to obtain credentials

Obtain **temporary** credentials for the IAM role or instance profile attached to your
workload:

- **EC2 / ECS / Lambda:** Use the instance or task role credentials from the AWS SDK or
  metadata service.
- **EKS (IRSA):** Use credentials from the web identity token file mounted into the pod.
- **Cross-account:** Call STS `AssumeRole` and use the returned access key, secret key,
  and session token.

See the [AWS Security Credentials guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
and [STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).

### Required headers (all three)

| Header | Value |
|--------|-------|
| `X-AWS-Access-Key-ID` | Temporary access key ID (e.g. `ASIA...`) |
| `X-AWS-Secret-Access-Key` | Secret access key |
| `X-AWS-Session-Token` | Session token from temporary credentials |

Long-lived IAM user access keys without a session token are not sufficient.

### Resulting identity

The service verifies the credentials with STS `GetCallerIdentity`. **By default the
verified identity (JWT `sub`) is the raw caller ARN** returned by STS, e.g.
`arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/SESSION_NAME` for an assumed-role session
(instance profile, IRSA, or explicit `AssumeRole`) or `arn:aws:iam::ACCOUNT:user/NAME`
for an IAM user.

The issued `sub` can be negotiated to an alternate representation (for AWS, the
session-stripped base IAM role ARN) via the `X-S2IAM-Identity-Format-Preference`
request header; the chosen form is reported in the response `identityFormat` field. The
SingleStore client libraries and CLI send `aws-iam-role-arn,aws-arn` by default as of
v0.6.0, so they authenticate an assumed-role session as the base IAM role ARN; a
protocol-only client that omits the header still gets the raw caller ARN described
above. See
[Identity format preferences](../../README.md#identity-format-preferences-content-negotiation)
in the main README for the vocabulary and semantics, and [openapi.yaml](openapi.yaml)
for the schema.

### Database JWT: required `workspaceGroupID` query parameter

Database JWT requests (`POST /auth/iam/database`) require a `workspaceGroupID`
query parameter that identifies the target workspace group. The value must be a
UUID: the 36-character canonical form (`8-4-4-4-12`) or 32 hexadecimal digits.
The auth server rejects other shapes, including prefixed ids such as `wg-...`.
Go and Java reference clients reject empty values; include a UUID on every
database JWT request.

Management API JWT requests (`POST /auth/iam/api`) do not use this parameter.

### Example: database JWT

```shell
curl -X POST 'https://authsvc.singlestore.com/auth/iam/database?workspaceGroupID=11111111-1111-4111-8111-111111111111' \
  -H 'X-AWS-Access-Key-ID: ASIAIOSFODNN7EXAMPLE' \
  -H 'X-AWS-Secret-Access-Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' \
  -H 'X-AWS-Session-Token: IQoJb3JpZ2luX2VjE...'
```

### Example: management API JWT

```shell
curl -X POST 'https://authsvc.singlestore.com/auth/iam/api' \
  -H 'X-AWS-Access-Key-ID: ASIAIOSFODNN7EXAMPLE' \
  -H 'X-AWS-Secret-Access-Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' \
  -H 'X-AWS-Session-Token: IQoJb3JpZ2luX2VjE...'
```

## GCP

### How to obtain credentials

Request a **workload identity JWT** (OIDC ID token) for the service account running
your workload:

- **GCE / GKE:** Use the metadata server
  (`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=...`).
- **Service account impersonation:** Use the
  [IAM Credentials `generateIdToken`](https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateIdToken)
  API.

See [Authenticating workloads to Google Cloud](https://cloud.google.com/docs/authentication).

### Audience requirement

The identity token **must** be minted with audience:

```text
https://authsvc.singlestore.com
```

Using the default metadata audience or a different URL will cause verification to fail.

### Required header

| Header | Value |
|--------|-------|
| `Authorization` | `Bearer <gcp-identity-token>` |

This bearer token is the GCP OIDC identity token — **not** the SingleStore JWT from
the response body.

### Example: database JWT

```shell
curl -X POST 'https://authsvc.singlestore.com/auth/iam/database?workspaceGroupID=11111111-1111-4111-8111-111111111111' \
  -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImV4YW1wbGUifQ...'
```

### Example: management API JWT

```shell
curl -X POST 'https://authsvc.singlestore.com/auth/iam/api' \
  -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImV4YW1wbGUifQ...'
```

## Azure

### How to obtain credentials

Acquire an **access token** for the managed identity attached to your Azure resource:

- **VM / App Service / AKS:** Query the
  [Azure Instance Metadata Service (IMDS)](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token)
  endpoint.
- **Local development:** Use the
  [Azure Identity SDK](https://learn.microsoft.com/en-us/python/api/overview/azure/identity-readme)
  (`DefaultAzureCredential`, `ManagedIdentityCredential`, etc.).

See [Managed identities for Azure resources overview](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview).

### Audience / resource requirement

Request a token for resource (audience):

```text
https://management.azure.com/
```

Example IMDS URL (system-assigned identity):

```text
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

Include header `Metadata: true` when calling IMDS.

### Required header

| Header | Value |
|--------|-------|
| `Authorization` | `Bearer <azure-access-token>` |

This bearer token is the Azure managed identity access token — **not** the SingleStore
JWT from the response body.

### Example: database JWT

```shell
curl -X POST 'https://authsvc.singlestore.com/auth/iam/database?workspaceGroupID=11111111-1111-4111-8111-111111111111' \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...'
```

### Example: management API JWT

```shell
curl -X POST 'https://authsvc.singlestore.com/auth/iam/api' \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...'
```

## Common mistakes

| Mistake | What to do instead |
|---------|-------------------|
| Sending only one AWS header (e.g. access key ID alone) | Send all three: access key ID, secret access key, and session token |
| Using long-lived IAM user keys without a session token | Use temporary credentials from STS, instance profile, or IRSA |
| Wrong GCP audience (default metadata audience or another URL) | Mint the identity token with audience `https://authsvc.singlestore.com` |
| Wrong Azure resource / audience | Request token for `https://management.azure.com/` |
| Putting the response `jwt` on `Authorization` for the exchange request | Send cloud provider credentials on the exchange; use the response `jwt` for downstream SingleStore services |
| Mixing providers on one request | Pick AWS **or** GCP **or** Azure headers for each POST |
| Omitting `workspaceGroupID`, or sending a non-UUID, on database JWT requests | Add `?workspaceGroupID=<uuid>` to `/auth/iam/database` (canonical `8-4-4-4-12` form or 32 hex digits) |
| Confusing inbound vs outbound JWTs | Inbound = cloud provider token in headers; outbound = SingleStore `jwt` in JSON body |

## OpenAPI / Redoc "Authorize" button

The OpenAPI spec models AWS as **three separate header schemes** that must all be
present (logical AND). GCP and Azure use HTTP bearer schemes for their cloud provider
tokens.

Redoc's **Authorize** dialog may not fully represent multi-header AWS authentication
— you may need to enter all three AWS values manually or rely on the curl examples
and this guide rather than the interactive authorizer alone.
