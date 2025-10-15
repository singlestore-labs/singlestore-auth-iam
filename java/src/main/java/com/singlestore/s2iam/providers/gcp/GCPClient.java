package com.singlestore.s2iam.providers.gcp;

import com.singlestore.s2iam.*;
import com.singlestore.s2iam.providers.AbstractBaseClient;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.singlestore.s2iam.exceptions.IdentityUnavailableException;

public class GCPClient extends AbstractBaseClient {
  public GCPClient(Logger logger) {
    super(logger, null);
  }
  private GCPClient(Logger logger, String assumed) {
    super(logger, assumed);
  }
  @Override
  protected CloudProviderClient newInstance(Logger logger, String assumedRole) {
    return new GCPClient(logger, assumedRole);
  }
  @Override
  public CloudProviderType getType() {
    return CloudProviderType.gcp;
  }
  @Override
  public Exception detect() {
    if (System.getenv("GOOGLE_APPLICATION_CREDENTIALS") != null
        || System.getenv("GCE_METADATA_HOST") != null)
      return null;
  boolean debug = debugEnabled() && logger != null;
    String ep = "http://metadata.google.internal/computeMetadata/v1/instance/id";
    HttpClient client = HttpClient.newBuilder().connectTimeout(Timeouts.DETECT).build();
    try {
      HttpRequest req = HttpRequest.newBuilder(URI.create(ep)).header("Metadata-Flavor", "Google")
          .timeout(Timeouts.DETECT).GET().build();
      long start = System.nanoTime();
      HttpResponse<Void> resp = client.send(req, HttpResponse.BodyHandlers.discarding());
      long durMs = (System.nanoTime() - start) / 1_000_000L;
      if (resp.statusCode() == 200) {
        if (debug)
          logger.logf("GCPClient.detect: success endpoint=%s status=%d durationMs=%d", ep,
              resp.statusCode(), durMs);
        return null;
      } else {
        if (debug)
          logger.logf("GCPClient.detect: non-200 endpoint=%s status=%d durationMs=%d", ep,
              resp.statusCode(), durMs);
        return new IllegalStateException("metadata status=" + resp.statusCode());
      }
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
      if (debug)
        logger.logf("GCPClient.detect: interrupted endpoint=%s err=%s", ep, ie.getMessage());
      return ie;
    } catch (IOException ioe) {
      if (debug)
        logger.logf("GCPClient.detect: io error endpoint=%s err=%s class=%s", ep, ioe.getMessage(),
            ioe.getClass().getSimpleName());
      return ioe;
    } catch (Exception e) {
      if (debug)
        logger.logf("GCPClient.detect: other error endpoint=%s err=%s class=%s", ep, e.getMessage(),
            e.getClass().getSimpleName());
      return e;
    }
  }
  @Override
  public Exception fastDetect() {
    String prop = System.getProperty("s2iam.test.gcpFast", "");
    if (!prop.isEmpty())
      return null;
    String creds = System.getenv("GOOGLE_APPLICATION_CREDENTIALS");
    if (creds != null && creds.endsWith(".json"))
      return null;
    String host = System.getenv("GCE_METADATA_HOST");
    if (host != null && !host.isEmpty())
      return null;
    return new IllegalStateException("fast detect: not gcp");
  }
  @Override
  public IdentityHeadersResult getIdentityHeaders(Map<String, String> additionalParams) {
    String audience = additionalParams.getOrDefault("audience", "https://authsvc.singlestore.com/");
    if (audience.endsWith("/"))
      audience = audience.substring(0, audience.length() - 1);
    HttpClient client = HttpClient.newBuilder().connectTimeout(Timeouts.IDENTITY).build();
    try {
      String url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience="
          + audience + "&format=full";
      HttpRequest req = HttpRequest.newBuilder(URI.create(url)).header("Metadata-Flavor", "Google")
          .timeout(Timeouts.IDENTITY).GET().build();
      HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
  if (resp.statusCode() != 200 || resp.body().isEmpty()) {
    if (resp.statusCode() == 404) {
      return new IdentityHeadersResult(null, null, new IdentityUnavailableException(
      "GCP identity token unavailable (no attached service account) status=404"));
    }
    return new IdentityHeadersResult(null, null, new IllegalStateException(
    "failed to get GCP identity token status=" + resp.statusCode()));
  }
      Map<String, String> headers = new HashMap<>();
      String token = resp.body();
      headers.put("Authorization", "Bearer " + token);
      CloudIdentity identity = parseGCPIdentity(token);
      return new IdentityHeadersResult(headers, identity, null);
    } catch (Exception e) {
      return new IdentityHeadersResult(null, null, e);
    }
  }
  private CloudIdentity parseGCPIdentity(String jwt) {
    try {
      String[] parts = jwt.split("\\.");
      if (parts.length < 2) {
        return new CloudIdentity(CloudProviderType.gcp, "", "", "", "", Map.of());
      }
      String jsonStr = new String(Base64.getUrlDecoder().decode(parts[1]));
      JsonNode root = OM.readTree(jsonStr);
      String sub = optText(root, "sub");
      String email = optText(root, "email");
      String identifier = sub == null ? "" : sub;
      if (email != null && !email.isEmpty()) {
        String emailVerified = optText(root, "email_verified");
        if ("true".equalsIgnoreCase(emailVerified)) {
          identifier = email;
        }
      }
      String resourceType = "instance";
      String region = "";
      JsonNode ce = root.get("google");
      if (ce == null) {
        ce = root.get("compute_engine");
      }
      if (ce != null && ce.isObject()) {
        JsonNode zoneNode = ce.get("zone");
        if (zoneNode == null) {
          JsonNode ce2 = root.get("compute_engine");
          if (ce2 != null && ce2.get("zone") != null)
            zoneNode = ce2.get("zone");
        }
        if (zoneNode != null && zoneNode.isTextual()) {
          region = deriveRegionFromZone(zoneNode.asText());
        }
        if (ce.get("instance_id") != null)
          resourceType = "instance";
      } else {
        int idx = jsonStr.indexOf("\"zone\":\"");
        if (idx >= 0) {
          int s = idx + 8;
          int e = jsonStr.indexOf('"', s);
          if (e > s) {
            region = deriveRegionFromZone(jsonStr.substring(s, e));
          }
        }
      }
      Map<String, String> extra = new HashMap<>();
      for (String key : new String[]{"sub", "email", "aud", "iss", "azp", "kid", "project_number",
          "project_id"}) {
        String v = optText(root, key);
        if (v != null && !v.isEmpty())
          extra.put(key, v);
      }
      JsonNode ceNode = root.get("google");
      if (ceNode != null && ceNode.get("compute_engine") != null)
        ceNode = ceNode.get("compute_engine");
      if (ceNode == null)
        ceNode = root.get("compute_engine");
      if (ceNode != null && ceNode.isObject()) {
        copyIfText(extra, ceNode, "instance_id");
        copyIfText(extra, ceNode, "project_id");
        copyIfText(extra, ceNode, "zone");
      }
      return new CloudIdentity(CloudProviderType.gcp, identifier, sub == null ? identifier : sub,
          region, resourceType, extra);
    } catch (Exception e) {
      return new CloudIdentity(CloudProviderType.gcp, "", "", "", "", Map.of());
    }
  }
  private static String optText(JsonNode n, String field) {
    JsonNode c = n.get(field);
    return c != null && !c.isNull() ? c.asText() : null;
  }
  private static void copyIfText(Map<String, String> dest, JsonNode node, String field) {
    JsonNode v = node.get(field);
    if (v != null && v.isTextual())
      dest.put(field, v.asText());
  }
  private static String deriveRegionFromZone(String zoneVal) {
    String zone = zoneVal;
    if (zone.contains("/")) {
      String[] parts = zone.split("/");
      zone = parts[parts.length - 1];
    }
    String[] segs = zone.split("-");
    if (segs.length >= 3) {
      return String.join("-", java.util.Arrays.copyOf(segs, segs.length - 1));
    }
    return "";
  }
  private static final ObjectMapper OM = new ObjectMapper();
}
