package com.singlestore.s2iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import com.singlestore.s2iam.exceptions.S2IAMException;
import com.singlestore.s2iam.options.*;
import com.singlestore.s2iam.providers.AWSClient;
import com.singlestore.s2iam.providers.AzureClient;
import com.singlestore.s2iam.providers.GCPClient;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

public final class S2IAM {
  private S2IAM() {}

  private static final String DEFAULT_SERVER = "https://authsvc.singlestore.com/auth/iam/:jwtType";
  private static final Duration DEFAULT_HTTP_TIMEOUT = Duration.ofSeconds(10);

  // Convenience API (database)
  public static String getDatabaseJWT(String workspaceGroupId, JwtOption... opts)
      throws S2IAMException {
    if (workspaceGroupId == null || workspaceGroupId.isEmpty()) {
      throw new S2IAMException("workspaceGroupId is required for database JWT");
    }
    JwtOptions o = new JwtOptions();
    o.jwtType = JwtOptions.JWTType.database;
    o.workspaceGroupId = workspaceGroupId;
    o.serverUrl = DEFAULT_SERVER;
    applyJwtOptions(o, opts);
    return getJWT(o);
  }

  // Synonym for getDatabaseJWT matching other language naming style
  public static String getJwtDatabase(String workspaceGroupId, JwtOption... opts)
      throws S2IAMException {
    return getDatabaseJWT(workspaceGroupId, opts);
  }

  // Convenience API (api)
  public static String getAPIJWT(JwtOption... opts) throws S2IAMException {
    JwtOptions o = new JwtOptions();
    o.jwtType = JwtOptions.JWTType.api;
    o.serverUrl = DEFAULT_SERVER;
    applyJwtOptions(o, opts);
    return getJWT(o);
  }

  // Synonym for getAPIJWT matching other language naming style
  public static String getJwtApi(JwtOption... opts) throws S2IAMException {
    return getAPIJWT(opts);
  }

  // Provider detection
  public static CloudProviderClient detectProvider(ProviderOption... opts)
      throws NoCloudProviderDetectedException {
    ProviderOptions po = new ProviderOptions();
    for (ProviderOption opt : opts) opt.apply(po);
    if (po.logger == null && "true".equals(System.getenv("S2IAM_DEBUGGING"))) {
      po.logger = Logger.STDOUT;
    }
    if (po.clients == null) {
      po.clients =
          List.of(new AWSClient(po.logger), new GCPClient(po.logger), new AzureClient(po.logger));
    }

    // Fast detect first
    for (CloudProviderClient c : po.clients) {
      if (c.fastDetect() == null) {
        return c; // success
      }
    }

    Duration timeout = po.timeout == null ? Duration.ofSeconds(5) : po.timeout;
    ExecutorService exec = Executors.newFixedThreadPool(po.clients.size());
    CompletionService<CloudProviderClient> cs = new ExecutorCompletionService<>(exec);
    List<Future<CloudProviderClient>> futures = new ArrayList<>();
    for (CloudProviderClient c : po.clients) {
      futures.add(
          cs.submit(
              () -> {
                Exception err = c.detect();
                if (err == null) return c;
                else throw err;
              }));
    }
    exec.shutdown();
    long deadline = System.nanoTime() + timeout.toNanos();
    List<Throwable> errors = new ArrayList<>();
    for (int i = 0; i < futures.size(); i++) {
      long remainingMs = (deadline - System.nanoTime()) / 1_000_000L;
      if (remainingMs <= 0) break;
      try {
        Future<CloudProviderClient> f = cs.poll(remainingMs, TimeUnit.MILLISECONDS);
        if (f == null) break; // timeout
        return f.get();
      } catch (ExecutionException ee) {
        errors.add(ee.getCause());
      } catch (InterruptedException ie) {
        Thread.currentThread().interrupt();
        errors.add(ie);
        break;
      }
    }
    throw new NoCloudProviderDetectedException(
        "no cloud provider detected"
            + (errors.isEmpty() ? "" : (": " + errors.get(0).getMessage())));
  }

  private static void applyJwtOptions(JwtOptions o, JwtOption... opts) {
    for (JwtOption opt : opts) opt.apply(o);
    if (o.timeout == null) o.timeout = Duration.ofSeconds(5);
    if (o.serverUrl == null || o.serverUrl.isEmpty()) o.serverUrl = DEFAULT_SERVER;
  }

  private static String getJWT(JwtOptions o) throws S2IAMException {
    if (o.serverUrl == null || o.serverUrl.isEmpty()) {
      throw new S2IAMException("server URL is required");
    }
    if (o.provider == null) {
      try {
        o.provider = detectProvider();
      } catch (NoCloudProviderDetectedException e) {
        throw new S2IAMException("failed to detect cloud provider", e);
      }
    }
    CloudProviderClient provider = o.provider;
    if (o.assumeRoleIdentifier != null && !o.assumeRoleIdentifier.isEmpty()) {
      provider = provider.assumeRole(o.assumeRoleIdentifier);
    }
    CloudProviderClient.IdentityHeadersResult res = provider.getIdentityHeaders(o.additionalParams);
    if (res.error != null) throw new S2IAMException("failed to get identity headers", res.error);
    CloudIdentity identity = res.identity;
    if (identity == null) throw new S2IAMException("no identity returned by provider");

    String url =
        o.serverUrl
            .replace(":cloudProvider", identity.getProvider().name())
            .replace(":jwtType", o.jwtType.name());

    String query = "";
    if (o.jwtType == JwtOptions.JWTType.database
        && o.workspaceGroupId != null
        && !o.workspaceGroupId.isEmpty()) {
      query = "?workspaceGroupID=" + encode(o.workspaceGroupId);
    }
    HttpRequest.Builder rb =
        HttpRequest.newBuilder(URI.create(url + query))
            .timeout(DEFAULT_HTTP_TIMEOUT)
            .POST(HttpRequest.BodyPublishers.noBody());
    for (Map.Entry<String, String> e : res.headers.entrySet()) rb.header(e.getKey(), e.getValue());

    HttpClient client = HttpClient.newBuilder().connectTimeout(DEFAULT_HTTP_TIMEOUT).build();
    HttpResponse<String> response;
    try {
      response = client.send(rb.build(), HttpResponse.BodyHandlers.ofString());
    } catch (IOException | InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new S2IAMException("error calling authentication server", e);
    }
    if (response.statusCode() != 200) {
      throw new S2IAMException(
          "authentication server returned status "
              + response.statusCode()
              + ": "
              + response.body());
    }
    try {
      JsonNode node = new ObjectMapper().readTree(response.body());
      String jwt = node.path("jwt").asText();
      if (jwt == null || jwt.isEmpty()) throw new S2IAMException("received empty JWT from server");
      return jwt;
    } catch (IOException e) {
      throw new S2IAMException("cannot parse response", e);
    }
  }

  private static String encode(String s) {
    return s.replace(" ", "%20");
  }
}
