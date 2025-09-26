package com.singlestore.s2iam.providers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.singlestore.s2iam.*;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

public class AzureClient extends AbstractBaseClient {
  public AzureClient(Logger logger) {
    super(logger, null);
  }

  private AzureClient(Logger logger, String assumed) {
    super(logger, assumed);
  }

  @Override
  protected CloudProviderClient newInstance(Logger logger, String assumedRole) {
    return new AzureClient(logger, assumedRole);
  }

  @Override
  public CloudProviderType getType() {
    return CloudProviderType.azure;
  }

  @Override
  public Exception detect() {
    // Env fast detection
    if (System.getenv("AZURE_FEDERATED_TOKEN_FILE") != null || System.getenv("MSI_ENDPOINT") != null
        || System.getenv("IDENTITY_ENDPOINT") != null)
      return null;
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    try {
      HttpRequest req = HttpRequest
          .newBuilder(URI.create("http://169.254.169.254/metadata/instance?api-version=2021-02-01"))
          .header("Metadata", "true").timeout(Duration.ofSeconds(2)).GET().build();
      HttpResponse<Void> resp = client.send(req, HttpResponse.BodyHandlers.discarding());
      if (resp.statusCode() == 200)
        return null;
    } catch (IOException | InterruptedException e) {
      Thread.currentThread().interrupt();
      return e;
    }
    return new IllegalStateException("not running on Azure");
  }

  @Override
  public Exception fastDetect() {
    String prop = System.getProperty("s2iam.test.azureFast", "");
    if (!prop.isEmpty())
      return null;
    String tokenFile = System.getenv("AZURE_FEDERATED_TOKEN_FILE");
    String cid = System.getenv("AZURE_CLIENT_ID");
    String tid = System.getenv("AZURE_TENANT_ID");
    if (tokenFile != null && !tokenFile.isEmpty() && cid != null && !cid.isEmpty() && tid != null
        && !tid.isEmpty())
      return null;
    return new Exception("no azure fast path");
  }

  @Override
  public IdentityHeadersResult getIdentityHeaders(Map<String, String> additionalParams) {
    String resource = additionalParams.getOrDefault("azure_resource",
        "https://management.azure.com/");
    String url = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource="
        + resource;
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    try {
      HttpRequest req = HttpRequest.newBuilder(URI.create(url)).header("Metadata", "true")
          .timeout(Duration.ofSeconds(3)).GET().build();
      HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
      if (resp.statusCode() != 200 || resp.body().isEmpty()) {
        return new IdentityHeadersResult(null, null,
            new IllegalStateException("failed to get Azure MI token status=" + resp.statusCode()));
      }
      String body = resp.body();
      ObjectMapper om = new ObjectMapper();
      JsonNode node = om.readTree(body);
      String token = node.path("access_token").asText();
      if (token == null || token.isEmpty())
        return new IdentityHeadersResult(null, null, new IllegalStateException("no access_token"));
      Map<String, String> headers = new HashMap<>();
      headers.put("Authorization", "Bearer " + token);

      // Decode JWT payload (second segment) for claims (no validation)
      String accessToken = token;
      String[] parts = accessToken.split("\\.");
      String tenantId = "";
      String principalId = ""; // prefer oid claim
      String clientId = node.path("client_id").asText();
      String subscriptionId = ""; // will become the identifier (JWT sub) to match Go
      String region = "";
      String resourceType = "unknown";
      Map<String, String> extra = new HashMap<>();

      ObjectMapper payloadMapper = om; // reuse
      if (parts.length >= 2) {
        try {
          String payloadJson = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
          JsonNode payload = payloadMapper.readTree(payloadJson);
          if (payload.has("oid"))
            principalId = payload.get("oid").asText("");
          else if (payload.has("sub"))
            principalId = payload.get("sub").asText("");
          else if (payload.has("appid"))
            principalId = payload.get("appid").asText("");
          if (payload.has("iss")) {
            String iss = payload.get("iss").asText("");
            extra.put("iss", iss);
            String[] segs = iss.split("/");
            for (int i = 0; i < segs.length; i++)
              if ("tokens".equals(segs[i]) && i > 0) {
                tenantId = segs[i - 1];
                break;
              }
          }
          if (payload.has("xms_mirid")) {
            String mirid = payload.get("xms_mirid").asText("");
            extra.put("xms_mirid", mirid);
            // try to extract subscription from /subscriptions/<uuid>/
            String[] p = mirid.split("/");
            for (int i = 0; i < p.length; i++) {
              if ("subscriptions".equals(p[i]) && i + 1 < p.length)
                subscriptionId = p[i + 1];
              if ("providers".equals(p[i]) && i + 1 < p.length)
                resourceType = p[i + 1];
            }
          }
        } catch (Exception ignored) {
        }
      }

      if (principalId.isEmpty())
        principalId = clientId; // fallback

      // Fallback: query instance metadata for subscriptionId if not already found
      if (subscriptionId.isEmpty()) {
        try {
          HttpRequest instReq = HttpRequest
              .newBuilder(
                  URI.create("http://169.254.169.254/metadata/instance?api-version=2021-02-01"))
              .header("Metadata", "true").timeout(Duration.ofSeconds(2)).GET().build();
          HttpResponse<String> instResp = client.send(instReq,
              HttpResponse.BodyHandlers.ofString());
          if (instResp.statusCode() == 200) {
            try {
              JsonNode inst = om.readTree(instResp.body());
              JsonNode compute = inst.path("compute");
              if (subscriptionId.isEmpty())
                subscriptionId = compute.path("subscriptionId").asText("");
              if (region.isEmpty())
                region = compute.path("location").asText(region);
            } catch (Exception ignored) {
            }
          }
        } catch (Exception ignored) {
        }
      }

      // Validate principal & tenant basics (GUID-ish) but don't force subscription
      // used as identifier
      Pattern guidPattern = Pattern.compile("^[0-9a-fA-F-]{32,36}$");
      if (principalId.isEmpty() || !guidPattern.matcher(principalId).find()) {
        return new IdentityHeadersResult(headers, null,
            new IllegalStateException("invalid principalId"));
      }

      if (!subscriptionId.isEmpty())
        extra.put("subscriptionId", subscriptionId);
      if (!clientId.isEmpty())
        extra.put("clientId", clientId);
      extra.put("principalId", principalId);

      CloudIdentity identity = new CloudIdentity(CloudProviderType.azure, principalId, tenantId,
          region, resourceType, extra);
      return new IdentityHeadersResult(headers, identity, null);
    } catch (Exception e) {
      return new IdentityHeadersResult(null, null, e);
    }
  }
}
