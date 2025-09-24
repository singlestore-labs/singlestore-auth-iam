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
    if (System.getenv("AZURE_FEDERATED_TOKEN_FILE") != null
        || System.getenv("MSI_ENDPOINT") != null
        || System.getenv("IDENTITY_ENDPOINT") != null) return null;
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    try {
      HttpRequest req =
          HttpRequest.newBuilder(
                  URI.create("http://169.254.169.254/metadata/instance?api-version=2021-02-01"))
              .header("Metadata", "true")
              .timeout(Duration.ofSeconds(2))
              .GET()
              .build();
      HttpResponse<Void> resp = client.send(req, HttpResponse.BodyHandlers.discarding());
      if (resp.statusCode() == 200) return null;
    } catch (IOException | InterruptedException e) {
      Thread.currentThread().interrupt();
      return e;
    }
    return new IllegalStateException("not running on Azure");
  }

  @Override
  public Exception fastDetect() {
    if (nonEmpty("AZURE_FEDERATED_TOKEN_FILE")) return null;
    if (nonEmpty("MSI_ENDPOINT")) return null;
    if (nonEmpty("IDENTITY_ENDPOINT")) return null;
    if (nonEmpty("AZURE_ENV")) return null; // generic azure env marker
    return new IllegalStateException("fast detect: not azure");
  }

  private boolean nonEmpty(String k) {
    String v = System.getenv(k);
    return v != null && !v.isEmpty();
  }

  @Override
  public IdentityHeadersResult getIdentityHeaders(Map<String, String> additionalParams) {
    String resource =
        additionalParams.getOrDefault("azure_resource", "https://management.azure.com/");
    String url =
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource="
            + resource;
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    try {
      HttpRequest req =
          HttpRequest.newBuilder(URI.create(url))
              .header("Metadata", "true")
              .timeout(Duration.ofSeconds(3))
              .GET()
              .build();
      HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
      if (resp.statusCode() != 200 || resp.body().isEmpty()) {
        return new IdentityHeadersResult(
            null,
            null,
            new IllegalStateException("failed to get Azure MI token status=" + resp.statusCode()));
      }
      // naive parse for "access_token":"..."
      String body = resp.body();
      ObjectMapper om = new ObjectMapper();
      JsonNode node = om.readTree(body);
      String token = node.path("access_token").asText();
      if (token == null || token.isEmpty())
        return new IdentityHeadersResult(null, null, new IllegalStateException("no access_token"));
      Map<String, String> headers = new HashMap<>();
      headers.put("Authorization", "Bearer " + token);
      String accessToken = token;
      // Decode JWT payload (second segment) for claims (no validation)
      String[] parts = accessToken.split("\\.");
      String tenantId = "";
      String principalId = node.path("client_id").asText();
      String region = "";
      String resourceType = "unknown";
      Map<String, String> extra = new HashMap<>();
      if (parts.length >= 2) {
        try {
          String payloadJson = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
          JsonNode payload = om.readTree(payloadJson);
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
            String[] p = mirid.split("/");
            for (int i = 0; i < p.length; i++) {
              if ("providers".equals(p[i]) && i + 1 < p.length) resourceType = p[i + 1];
            }
          }
        } catch (Exception ignored) {
        }
      }
      // Region fallback via instance metadata if empty
      if (region.isEmpty()) {
        try {
          HttpRequest instReq =
              HttpRequest.newBuilder(
                      URI.create("http://169.254.169.254/metadata/instance?api-version=2021-02-01"))
                  .header("Metadata", "true")
                  .timeout(Duration.ofSeconds(2))
                  .GET()
                  .build();
          HttpResponse<String> instResp =
              client.send(instReq, HttpResponse.BodyHandlers.ofString());
          if (instResp.statusCode() == 200) {
            try {
              JsonNode inst = om.readTree(instResp.body());
              region = inst.path("compute").path("location").asText(region);
            } catch (Exception ignored) {
            }
          }
        } catch (Exception ignored) {
        }
      }
      CloudIdentity identity =
          new CloudIdentity(
              CloudProviderType.azure, principalId, tenantId, region, resourceType, extra);
      return new IdentityHeadersResult(headers, identity, null);
    } catch (Exception e) {
      return new IdentityHeadersResult(null, null, e);
    }
  }
}
