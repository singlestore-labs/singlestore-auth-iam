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
        || System.getenv("GCE_METADATA_HOST") != null)
      return null;
    boolean debug = "true".equals(System.getenv("S2IAM_DEBUGGING")) && logger != null;
    // Metadata probing: attempt both hostname and link-local IP; some hardened
    // images may only allow one.
    String[] endpoints = new String[]{
        "http://metadata.google.internal/computeMetadata/v1/instance/id",
        "http://169.254.169.254/computeMetadata/v1/instance/id"};
    Exception firstErr = null;
    for (String ep : endpoints) {
      HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
      try {
        HttpRequest req = HttpRequest.newBuilder(URI.create(ep)).header("Metadata-Flavor", "Google")
            .timeout(Duration.ofSeconds(3)).GET().build();
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
          if (firstErr == null)
            firstErr = new IllegalStateException("metadata status=" + resp.statusCode());
        }
      } catch (InterruptedException ie) {
        Thread.currentThread().interrupt();
        if (debug)
          logger.logf("GCPClient.detect: interrupted endpoint=%s err=%s", ep, ie.getMessage());
        if (firstErr == null)
          firstErr = ie;
      } catch (IOException ioe) {
        if (debug)
          logger.logf("GCPClient.detect: io error endpoint=%s err=%s class=%s", ep,
              ioe.getMessage(), ioe.getClass().getSimpleName());
        if (firstErr == null)
          firstErr = ioe;
      } catch (Exception e) {
        if (debug)
          logger.logf("GCPClient.detect: other error endpoint=%s err=%s class=%s", ep,
              e.getMessage(), e.getClass().getSimpleName());
        if (firstErr == null)
          firstErr = e;
      }
    }
    return firstErr == null ? new IllegalStateException("not running on GCP") : firstErr;
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
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    try {
      String url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience="
          + audience + "&format=full";
      HttpRequest req = HttpRequest.newBuilder(URI.create(url)).header("Metadata-Flavor", "Google")
          .timeout(Duration.ofSeconds(3)).GET().build();
      HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
      if (resp.statusCode() != 200 || resp.body().isEmpty()) {
        // For NO_ROLE scenario (no service account), metadata returns 404. Expose
        // recognizable error (independent of any test environment variables).
        if (resp.statusCode() == 404) {
          return new IdentityHeadersResult(null, null,
              new IllegalStateException("gcp-no-role-identity-unavailable-404"));
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
      String json = new String(Base64.getUrlDecoder().decode(parts[1]));
      String sub = extract(json, "\"sub\":\"");
      String email = extract(json, "\"email\":\"");
      // Server (Go) side uses the email when present; don't rely on email_verified
      // parsing here – be liberal to match server identity log.
      String identifier = (email != null && !email.isEmpty()) ? email : (sub == null ? "" : sub);

      // Derive region from zone if present
      String resourceType = "instance";
      String region = "";
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

      Map<String, String> extra = new HashMap<>();
      for (String key : new String[]{"sub", "email", "aud", "iss", "azp", "kid"}) {
        String val = extract(json, "\"" + key + "\":\"");
        if (val != null)
          extra.put(key, val);
      }
      String projNumber = extract(json, "\"project_number\":\"");
      if (projNumber != null)
        extra.put("project_number", projNumber);
      String projId = extract(json, "\"project_id\":\"");
      if (projId != null)
        extra.put("project_id", projId);

      return new CloudIdentity(CloudProviderType.gcp, identifier, sub == null ? identifier : sub,
          region, resourceType, extra);
    } catch (Exception e) {
      return new CloudIdentity(CloudProviderType.gcp, "", "", "", "", Map.of());
    }
  }

  private static String extract(String json, String marker) {
    int i = json.indexOf(marker);
    if (i < 0)
      return null;
    int s = i + marker.length();
    int e = json.indexOf('"', s);
    if (e < 0)
      return null;
    return json.substring(s, e);
  }
}
