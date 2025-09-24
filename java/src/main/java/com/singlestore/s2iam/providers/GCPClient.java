package com.singlestore.s2iam.providers;

import com.singlestore.s2iam.*;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

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
    // Env fast detection
    if (System.getenv("GOOGLE_APPLICATION_CREDENTIALS") != null
        || System.getenv("GCE_METADATA_HOST") != null) return null;
    // Metadata probing
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    try {
      HttpRequest req =
          HttpRequest.newBuilder(
                  URI.create("http://metadata.google.internal/computeMetadata/v1/instance/id"))
              .header("Metadata-Flavor", "Google")
              .timeout(Duration.ofSeconds(2))
              .GET()
              .build();
      HttpResponse<Void> resp = client.send(req, HttpResponse.BodyHandlers.discarding());
      if (resp.statusCode() == 200) return null;
    } catch (IOException | InterruptedException e) {
      Thread.currentThread().interrupt();
      return e;
    }
    return new IllegalStateException("not running on GCP");
  }

  @Override
  public Exception fastDetect() {
    String creds = System.getenv("GOOGLE_APPLICATION_CREDENTIALS");
    if (creds != null && !creds.isEmpty()) return null;
    String host = System.getenv("GCE_METADATA_HOST");
    if (host != null && !host.isEmpty()) return null;
    return new IllegalStateException("fast detect: not gcp");
  }

  @Override
  public IdentityHeadersResult getIdentityHeaders(Map<String, String> additionalParams) {
    String audience = additionalParams.getOrDefault("audience", "https://authsvc.singlestore.com/");
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    try {
      String url =
          "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience="
              + audience
              + "&format=full";
      HttpRequest req =
          HttpRequest.newBuilder(URI.create(url))
              .header("Metadata-Flavor", "Google")
              .timeout(Duration.ofSeconds(3))
              .GET()
              .build();
      HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
      if (resp.statusCode() != 200 || resp.body().isEmpty()) {
        return new IdentityHeadersResult(
            null,
            null,
            new IllegalStateException(
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
      if (parts.length < 2)
        return new CloudIdentity(CloudProviderType.gcp, "", "", "", "", Map.of());
      String json = new String(Base64.getUrlDecoder().decode(parts[1]));
      String sub = extract(json, "\"sub\":\"");
      String email = extract(json, "\"email\":\"");
      String emailVerified = extract(json, "\"email_verified\":");
      String identifier =
          (email != null && "true".equals(emailVerified)) ? email : (sub == null ? "" : sub);
      // Resource type / region heuristics
      String resourceType = "instance";
      String region = "";
      // extract zone if present in compute_engine section: "zone":"projects/.../zones/us-east4-c"
      int gce = json.indexOf("compute_engine");
      if (gce >= 0) {
        String zone = extract(json.substring(gce), "\"zone\":\"");
        if (zone != null) {
          String[] zp = zone.split("/");
          String last = zp[zp.length - 1];
          String[] partsZone = last.split("-");
          if (partsZone.length >= 3) {
            region = String.join("-", java.util.Arrays.copyOf(partsZone, partsZone.length - 1));
          }
        }
      }
      // Additional claims (very naive: capture selected keys)
      Map<String, String> extra = new HashMap<>();
      for (String key : new String[] {"sub", "email", "aud", "iss", "azp", "kid"}) {
        String val = extract(json, "\"" + key + "\":\"");
        if (val != null) extra.put(key, val);
      }
      // project info
      String projNumber = extract(json, "\"project_number\":\"");
      if (projNumber != null) extra.put("project_number", projNumber);
      String projId = extract(json, "\"project_id\":\"");
      if (projId != null) extra.put("project_id", projId);
      return new CloudIdentity(
          CloudProviderType.gcp,
          identifier,
          sub == null ? identifier : sub,
          region,
          resourceType,
          extra);
    } catch (Exception e) {
      return new CloudIdentity(CloudProviderType.gcp, "", "", "", "", Map.of());
    }
  }

  private static String extract(String json, String marker) {
    int i = json.indexOf(marker);
    if (i < 0) return null;
    int s = i + marker.length();
    int e = json.indexOf('"', s);
    if (e < 0) return null;
    return json.substring(s, e);
  }
}
