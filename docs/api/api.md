---
title: SingleStore Cloud IAM Authentication API v0.1.0
language_tabs:
  - shell: curl
language_clients:
  - shell: ""
toc_footers: []
includes: []
search: false
highlight_theme: darkula
headingLevel: 2

---

<!-- Generator: Widdershins v4.0.1 -->

<h1 id="singlestore-cloud-iam-authentication-api">SingleStore Cloud IAM Authentication API v0.1.0</h1>

> Scroll down for code samples, example requests and responses. Select a language for code samples from the tabs above or the mobile navigation menu.

HTTP API for exchanging cloud provider identity credentials for SingleStore JWTs.

Customers may call these endpoints directly with their own HTTP client instead of
using the `s2iam` client libraries (Go, Python, Java). Obtain cloud-provider
credentials on the machine or workload making the request, then POST them to
the authentication service using the headers documented below.

**Production host:** `https://authsvc.singlestore.com`

**Status**
- Database (engine) JWTs: available; APIs may change before GA.
- Management API JWTs: available; APIs may change before GA.

**Related endpoints**
- JWT signing keys (JWKS): `GET /auth/oidc/op/Customer/.well-known/jwks.json`
- Validate returned JWTs against this JWKS after exchange.

**Authentication (overview)**

Send credentials for **one** cloud provider on each request:

| Provider | Headers |
|----------|---------|
| AWS | `X-AWS-Access-Key-ID`, `X-AWS-Secret-Access-Key`, `X-AWS-Session-Token` (all three required) |
| GCP | `Authorization: Bearer <identity-token>` (workload identity JWT) |
| Azure | `Authorization: Bearer <access-token>` (managed identity token) |

See the **Authentication** section below and per-endpoint examples for curl samples.

Base URLs:

* <a href="https://authsvc.singlestore.com">https://authsvc.singlestore.com</a>

License: <a href="https://www.singlestore.com/terms/">Proprietary</a>

# Authentication

* API Key (awsCredentials)
    - Parameter Name: **X-AWS-Access-Key-ID**, in: header. **AWS.** Send temporary credentials using all three headers:
`X-AWS-Access-Key-ID`, `X-AWS-Secret-Access-Key`, and `X-AWS-Session-Token`.

Obtain credentials from the instance/task role, IRSA, or STS AssumeRole on
the calling workload before POSTing to this API.

* API Key (gcpIdentityToken)
    - Parameter Name: **Authorization**, in: header. **GCP.** Send `Authorization: Bearer <identity-token>` where the token is a
workload identity JWT.

Request the identity token with audience `https://authsvc.singlestore.com`
(or the audience configured for your environment).

* API Key (azureIdentityToken)
    - Parameter Name: **Authorization**, in: header. **Azure.** Send `Authorization: Bearer <access-token>` where the token is a
managed identity access token.

Acquire the token from the instance metadata service or Azure Identity SDK
for the managed identity attached to the calling workload.

<h1 id="singlestore-cloud-iam-authentication-api-iam">IAM</h1>

Cloud IAM credential exchange

## Exchange cloud identity for a database (engine) JWT

<a id="opIdexchangeDatabaseJWT"></a>

> Code samples

```shell
# You can also use wget
curl -X POST https://authsvc.singlestore.com/auth/iam/database \
  -H 'Accept: application/json' \
  -H 'X-AWS-Access-Key-ID: API_KEY'

```

`POST /auth/iam/database`

Verifies the caller's cloud provider identity and returns a signed JWT
suitable for SingleStore engine / database access.

Send an empty body. Authentication is performed exclusively via HTTP
headers carrying cloud provider credentials (see `components.securitySchemes`).

The optional `workspaceGroupID` query parameter is sent by the reference
Go client for database JWT requests. The server verifies identity from
headers; callers using custom clients may include it for forward compatibility.

**Example requests (use one provider):**

AWS:
```shell
curl -X POST 'https://authsvc.singlestore.com/auth/iam/database' \
  -H 'X-AWS-Access-Key-ID: AKIA...' \
  -H 'X-AWS-Secret-Access-Key: ...' \
  -H 'X-AWS-Session-Token: ...'
```

GCP:
```shell
curl -X POST 'https://authsvc.singlestore.com/auth/iam/database' \
  -H 'Authorization: Bearer <identity-token>'
```

Azure:
```shell
curl -X POST 'https://authsvc.singlestore.com/auth/iam/database' \
  -H 'Authorization: Bearer <access-token>'
```

<h3 id="exchange-cloud-identity-for-a-database-(engine)-jwt-parameters">Parameters</h3>

|Name|In|Type|Required|Description|
|---|---|---|---|---|
|workspaceGroupID|query|string|false|Target workspace group (reference client sends this for database JWTs).|

> Example responses

> JWT issued successfully

```json
{
  "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.example",
  "expires_at": "2026-06-09T21:00:00Z",
  "audience": "engine"
}
```

> 401 Response

```json
{
  "message": "cloud provider authentication failed"
}
```

> 500 Response

```json
{
  "message": "string"
}
```

<h3 id="exchange-cloud-identity-for-a-database-(engine)-jwt-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|JWT issued successfully|[ServiceIdentityJWT](#schemaserviceidentityjwt)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Cloud provider authentication failed|[Error](#schemaerror)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Failed to create JWT|[Error](#schemaerror)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
awsCredentials, gcpIdentityToken, azureIdentityToken
</aside>

## Exchange cloud identity for a management API JWT

<a id="opIdexchangeAPIJWT"></a>

> Code samples

```shell
# You can also use wget
curl -X POST https://authsvc.singlestore.com/auth/iam/api \
  -H 'Accept: application/json' \
  -H 'X-AWS-Access-Key-ID: API_KEY'

```

`POST /auth/iam/api`

Verifies the caller's cloud provider identity, resolves a matching SingleStore
cloud-principal user, and returns a signed JWT for management API access.

Send an empty body. Authentication is performed via cloud provider headers.

The verified identity must be linked to an active cloud-principal user in
SingleStore; otherwise the server returns `404`.

**Example requests (use one provider):**

AWS:
```shell
curl -X POST 'https://authsvc.singlestore.com/auth/iam/api' \
  -H 'X-AWS-Access-Key-ID: AKIA...' \
  -H 'X-AWS-Secret-Access-Key: ...' \
  -H 'X-AWS-Session-Token: ...'
```

GCP:
```shell
curl -X POST 'https://authsvc.singlestore.com/auth/iam/api' \
  -H 'Authorization: Bearer <identity-token>'
```

Azure:
```shell
curl -X POST 'https://authsvc.singlestore.com/auth/iam/api' \
  -H 'Authorization: Bearer <access-token>'
```

> Example responses

> JWT issued successfully

```json
{
  "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.example",
  "expires_at": "2026-06-09T21:00:00Z",
  "audience": "portal"
}
```

> 401 Response

```json
{
  "message": "string"
}
```

> 404 Response

```json
{
  "message": "no cloud principal user matches the provided identity"
}
```

<h3 id="exchange-cloud-identity-for-a-management-api-jwt-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|JWT issued successfully|[ServiceIdentityJWT](#schemaserviceidentityjwt)|
|401|[Unauthorized](https://tools.ietf.org/html/rfc7235#section-3.1)|Cloud provider authentication failed|[Error](#schemaerror)|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|No cloud-principal user matches the verified identity|[Error](#schemaerror)|
|500|[Internal Server Error](https://tools.ietf.org/html/rfc7231#section-6.6.1)|Internal error|[Error](#schemaerror)|

<aside class="warning">
To perform this operation, you must be authenticated by means of one of the following methods:
awsCredentials, gcpIdentityToken, azureIdentityToken
</aside>

## JSON Web Key Set for validating issued JWTs

<a id="opIdgetCustomerJWKS"></a>

> Code samples

```shell
# You can also use wget
curl -X GET https://authsvc.singlestore.com/auth/oidc/op/Customer/.well-known/jwks.json \
  -H 'Accept: application/json'

```

`GET /auth/oidc/op/Customer/.well-known/jwks.json`

Public signing keys for JWTs issued by the Customer OIDC provider.
Use this document to verify `jwt` values returned by the IAM exchange endpoints.

> Example responses

> 200 Response

```json
{}
```

<h3 id="json-web-key-set-for-validating-issued-jwts-responses">Responses</h3>

|Status|Meaning|Description|Schema|
|---|---|---|---|
|200|[OK](https://tools.ietf.org/html/rfc7231#section-6.3.1)|JWKS document|Inline|
|404|[Not Found](https://tools.ietf.org/html/rfc7231#section-6.5.4)|JWKS not found|[Error](#schemaerror)|

<h3 id="json-web-key-set-for-validating-issued-jwts-responseschema">Response Schema</h3>

Status Code **200**

*RFC 7517 JSON Web Key Set*

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|

<aside class="success">
This operation does not require authentication
</aside>

# Schemas

<h2 id="tocS_ServiceIdentityJWT">ServiceIdentityJWT</h2>
<!-- backwards compatibility -->
<a id="schemaserviceidentityjwt"></a>
<a id="schema_ServiceIdentityJWT"></a>
<a id="tocSserviceidentityjwt"></a>
<a id="tocsserviceidentityjwt"></a>

```json
{
  "jwt": "string",
  "expires_at": "2019-08-24T14:15:22Z",
  "audience": "engine"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|jwt|string|true|none|Signed JWT string|
|expires_at|string(date-time)|true|none|JWT expiration time (RFC 3339)|
|audience|string|true|none|Intended audience (`engine` for database, `portal` for management API)|

#### Enumerated Values

|Property|Value|
|---|---|
|audience|engine|
|audience|portal|

<h2 id="tocS_Error">Error</h2>
<!-- backwards compatibility -->
<a id="schemaerror"></a>
<a id="schema_Error"></a>
<a id="tocSerror"></a>
<a id="tocserror"></a>

```json
{
  "message": "string"
}

```

### Properties

|Name|Type|Required|Restrictions|Description|
|---|---|---|---|---|
|message|string|false|none|none|

