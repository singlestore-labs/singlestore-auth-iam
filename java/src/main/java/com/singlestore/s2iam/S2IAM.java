package com.singlestore.s2iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import com.singlestore.s2iam.exceptions.S2IAMException;
import com.singlestore.s2iam.options.*;
import com.singlestore.s2iam.providers.aws.AWSClient;
import com.singlestore.s2iam.providers.azure.AzureClient;
import com.singlestore.s2iam.providers.gcp.GCPClient;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

public final class S2IAM {
  private S2IAM() {
  }

  private static final String DEFAULT_SERVER = "https://authsvc.singlestore.com/auth/iam/:jwtType";
  private static final String LIB_NAME = "s2iam-java";
  private static final String LIB_VERSION = Optional
      .ofNullable(S2IAM.class.getPackage().getImplementationVersion()).orElse("dev");
  private static final String USER_AGENT = LIB_NAME + "/" + LIB_VERSION; // derived dynamically
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static boolean debugEnabled() {
    return "true".equals(System.getenv("S2IAM_DEBUGGING"));
  }

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

  // Overloads supporting provider options (primarily for builder convenience)
  public static String getDatabaseJWT(String workspaceGroupId, JwtOption[] jwtOpts,
      ProviderOption[] providerOpts) throws S2IAMException {
    if (providerOpts != null && providerOpts.length > 0) {
      // apply provider options globally before invoking regular path
      ProviderOptions po = new ProviderOptions();
      for (ProviderOption p : providerOpts)
        p.apply(po);
      // Currently only timeout/logger/clients are meaningful; we can't thread through
      // directly without refactor, so store once for detectProvider static use if
      // needed.
      // For minimal risk, just pass timeout via a thread-local.
      ProviderContext.set(po);
      try {
        return getDatabaseJWT(workspaceGroupId, jwtOpts);
      } finally {
        ProviderContext.clear();
      }
    }
    return getDatabaseJWT(workspaceGroupId, jwtOpts);
  }

  public static String getAPIJWT(JwtOption[] jwtOpts, ProviderOption[] providerOpts)
      throws S2IAMException {
    if (providerOpts != null && providerOpts.length > 0) {
      ProviderOptions po = new ProviderOptions();
      for (ProviderOption p : providerOpts)
        p.apply(po);
      ProviderContext.set(po);
      try {
        return getAPIJWT(jwtOpts);
      } finally {
        ProviderContext.clear();
      }
    }
    return getAPIJWT(jwtOpts);
  }

  // Provider detection
  public static CloudProviderClient detectProvider(ProviderOption... opts)
      throws NoCloudProviderDetectedException {
    ProviderOptions po = new ProviderOptions();
    for (ProviderOption opt : opts)
      opt.apply(po);
    // Merge thread-local provider context (builder) if present and explicit opts
    // didn't set.
    ProviderOptions ctx = ProviderContext.get();
    if (ctx != null) {
      if (po.timeout == null)
        po.timeout = ctx.timeout;
      if (po.logger == null)
        po.logger = ctx.logger;
      if (po.clients == null)
        po.clients = ctx.clients;
    }
    if (po.logger == null && debugEnabled()) {
      po.logger = Logger.STDOUT;
    }
    if (po.clients == null) {
      po.clients = List.of(new AWSClient(po.logger), new GCPClient(po.logger),
          new AzureClient(po.logger));
    }
  boolean debug = debugEnabled();
    // Fast detect first
    long fastStart = System.nanoTime();
    if (debug && po.logger != null) {
      po.logger.logf("detectProvider: starting fastDetect phase over providers=%d",
          po.clients.size());
    }
    Map<String, String> fastErrors = new LinkedHashMap<>();
    for (CloudProviderClient c : po.clients) {
      long s = System.nanoTime();
      Exception fe = c.fastDetect();
      long durMs = (System.nanoTime() - s) / 1_000_000L;
      if (fe == null) {
        if (debug && po.logger != null) {
          po.logger.logf("detectProvider: fastDetect SUCCESS provider=%s totalFastPhaseMs=%d",
              c.getClass().getSimpleName(), (System.nanoTime() - fastStart) / 1_000_000L);
        }
        return c;
      } else if (debug && po.logger != null) {
        po.logger.logf("detectProvider: fastDetect FAIL provider=%s err=%s durationMs=%d",
            c.getClass().getSimpleName(), fe.getMessage(), durMs);
      }
      fastErrors.put(c.getClass().getSimpleName(), fe.getMessage());
    }
  // Detection timeout: use centralized Timeouts.DETECT unless explicitly overridden via ProviderOption.
  // This keeps parity with other languages and allows a single tuning point. Tests rely on fast failure.
  Duration timeout = po.timeout == null ? Timeouts.DETECT : po.timeout;
    if (debug && po.logger != null) {
      po.logger.logf("detectProvider: entering concurrent detect phase timeoutMs=%d",
          timeout.toMillis());
    }
    ExecutorService exec = Executors.newFixedThreadPool(po.clients.size());
    CompletionService<CloudProviderClient> cs = new ExecutorCompletionService<>(exec);
    List<Future<CloudProviderClient>> futures = new ArrayList<>();
    for (CloudProviderClient c : po.clients) {
      futures.add(cs.submit(() -> {
        long s = System.nanoTime();
        Exception err = c.detect();
        long durMs = (System.nanoTime() - s) / 1_000_000L;
        if (debug && po.logger != null) {
          po.logger.logf("detectProvider: detect provider=%s result=%s durationMs=%d thread=%s",
              c.getClass().getSimpleName(), err == null ? "SUCCESS" : ("ERR:" + err.getMessage()),
              durMs, Thread.currentThread().getName());
        }
        if (err == null)
          return c;
        else
          throw err;
      }));
    }
    exec.shutdown();
    long deadline = System.nanoTime() + timeout.toNanos();
    List<Throwable> errors = new ArrayList<>();
    Map<String, String> detectErrors = new LinkedHashMap<>();
    for (int i = 0; i < futures.size(); i++) {
      long remainingMs = (deadline - System.nanoTime()) / 1_000_000L;
      if (remainingMs <= 0)
        break;
      try {
        Future<CloudProviderClient> f = cs.poll(remainingMs, TimeUnit.MILLISECONDS);
        if (f == null)
          break; // timeout
        CloudProviderClient found = f.get();
        for (Future<CloudProviderClient> other : futures)
          if (!other.isDone())
            other.cancel(true);
        return found;
      } catch (ExecutionException ee) {
        Throwable cause = ee.getCause();
        errors.add(cause);
        if (debug && po.logger != null) {
          po.logger.logf("detectProvider: provider failed error=%s remainingMs=%d",
              cause == null ? "<null>" : cause.getMessage(), remainingMs);
        }
        String key = cause == null ? "unknown" : cause.getClass().getSimpleName();
        detectErrors.put(key + "@" + i, cause == null ? "null" : cause.getMessage());
      } catch (InterruptedException ie) {
        Thread.currentThread().interrupt();
        errors.add(ie);
        break;
      }
    }
    for (Future<CloudProviderClient> other : futures)
      if (!other.isDone())
        other.cancel(true);
    if (debug && po.logger != null) {
      po.logger.logf("detectProvider: no provider detected errors=%d firstError=%s", errors.size(),
          errors.isEmpty() || errors.get(0) == null ? "<none>" : errors.get(0).getMessage());
    }
    throw new NoCloudProviderDetectedException(
        buildAggregateDetectMessage(fastErrors, detectErrors));
  }

  private static String safeTrunc(String s) {
    if (s == null)
      return "<null>";
    if (s.length() > 60)
      return s.substring(0, 57) + "...";
    return s;
  }

  private static String buildAggregateDetectMessage(Map<String, String> fastErrors,
      Map<String, String> detectErrors) {
    List<String> parts = new ArrayList<>();
    String fast = formatSection(fastErrors, 3);
    if (!fast.isEmpty())
      parts.add("fast=" + fast);
    String detect = formatSection(detectErrors, 3);
    if (!detect.isEmpty())
      parts.add("detect=" + detect);
    if (parts.isEmpty())
      return "no cloud provider detected";
    return "no cloud provider detected; " + String.join("; ", parts);
  }


  private static String formatSection(Map<String, String> src, int max) {
    if (src.isEmpty())
      return "";
    StringBuilder sb = new StringBuilder();
    int n = 0;
    for (var e : src.entrySet()) {
      if (n++ > 0)
        sb.append(',');
      sb.append(e.getKey()).append(':').append(safeTrunc(e.getValue()));
      if (n >= max && src.size() > max) {
        sb.append("+" + (src.size() - max) + "more");
        break;
      }
    }
    return sb.toString();
  }

  private static void applyJwtOptions(JwtOptions o, JwtOption... opts) {
    for (JwtOption opt : opts)
      opt.apply(o);
    if (o.timeout == null)
      o.timeout = Duration.ofSeconds(5);
    if (o.serverUrl == null || o.serverUrl.isEmpty())
      o.serverUrl = DEFAULT_SERVER;
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
    // Enforce that audience param (if present) only used for GCP
    if (o.additionalParams != null && o.additionalParams.containsKey("audience")) {
      CloudProviderType t = o.provider.getType();
      if (t != CloudProviderType.gcp) {
        throw new S2IAMException(
            "audience parameter is only supported for GCP provider (detected=" + t + ")");
      }
    }
  boolean debug = debugEnabled();
    CloudProviderClient provider = o.provider;
    if (o.assumeRoleIdentifier != null && !o.assumeRoleIdentifier.isEmpty()) {
      String id = o.assumeRoleIdentifier;
      switch (provider.getType()) {
        case aws: {
          if (!id.startsWith("arn:"))
            throw new S2IAMException("invalid AWS assumeRoleIdentifier (must start with 'arn:')");
          String[] arnParts = id.split(":");
          if (arnParts.length < 6 || arnParts[2].isEmpty() || arnParts[5].isEmpty())
            throw new S2IAMException("invalid AWS ARN format for assumeRoleIdentifier");
          if (!arnParts[2].equals("iam") && !arnParts[2].equals("sts"))
            throw new S2IAMException("AWS assumeRoleIdentifier service must be iam or sts");
          break;
        }
        case gcp: {
          if (!id.contains("@") || !id.endsWith(".gserviceaccount.com"))
            throw new S2IAMException(
                "invalid GCP assumeRoleIdentifier (expected service account email)");
          break;
        }
        case azure: {
          String s = id.trim();
          if (s.length() != 36 || s.chars().filter(ch -> ch == '-').count() != 4)
            throw new S2IAMException(
                "invalid Azure assumeRoleIdentifier (expected GUID format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)");
          try {
            java.util.UUID.fromString(s);
          } catch (IllegalArgumentException iae) {
            throw new S2IAMException("invalid Azure assumeRoleIdentifier (not a valid UUID)");
          }
          break;
        }
        default :
          throw new S2IAMException("assumeRoleIdentifier validation not implemented for provider: "
              + provider.getType());
      }
      provider = provider.assumeRole(id);
    }
    CloudProviderClient.IdentityHeadersResult res = provider.getIdentityHeaders(o.additionalParams);
    if (res.error != null)
      throw new S2IAMException("failed to get identity headers", res.error);
    CloudIdentity identity = res.identity;
    if (identity == null)
      throw new S2IAMException("no identity returned by provider");

    String url = o.serverUrl.replace(":cloudProvider", identity.getProvider().name())
        .replace(":jwtType", o.jwtType.name());
    String query = "";
    if (o.jwtType == JwtOptions.JWTType.database && o.workspaceGroupId != null
        && !o.workspaceGroupId.isEmpty()) {
      try {
        query = "?workspaceGroupID=" + java.net.URLEncoder.encode(o.workspaceGroupId,
            java.nio.charset.StandardCharsets.UTF_8);
      } catch (Exception e) {
        throw new S2IAMException("failed to URL encode workspaceGroupId", e);
      }
    }
    Duration httpTimeout = o.timeout != null ? o.timeout : Timeouts.IDENTITY; // apply option
                                                                              // timeout
    HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(url + query)).timeout(httpTimeout)
        .POST(HttpRequest.BodyPublishers.noBody()).header("User-Agent", USER_AGENT);
    for (Map.Entry<String, String> e : res.headers.entrySet())
      rb.header(e.getKey(), e.getValue());

    if (debug && identity.getProvider() != null) {
      Logger log = Logger.STDOUT; // simple fallback
      log.logf("getJWT: requesting jwtType=%s provider=%s url=%s timeoutMs=%d", o.jwtType,
          identity.getProvider(), url, httpTimeout.toMillis());
    }

    HttpClient client = HttpClient.newBuilder().connectTimeout(httpTimeout).build();
    HttpResponse<String> response;
    try {
      response = client.send(rb.build(), HttpResponse.BodyHandlers.ofString());
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
      throw new S2IAMException("error calling authentication server (interrupted)", ie);
    } catch (IOException ioe) {
      throw new S2IAMException("error calling authentication server", ioe);
    }
    int sc = response.statusCode();
    if (sc != 200) {
      throw new S2IAMException(
          "authentication server returned status " + sc + ": " + response.body());
    }
    try {
      JsonNode node = MAPPER.readTree(response.body());
      String jwt = node.path("jwt").asText();
      if (jwt == null || jwt.isEmpty())
        throw new S2IAMException("received empty JWT from server");
      return jwt;
    } catch (IOException e) {
      throw new S2IAMException("cannot parse response", e);
    }
  }
}
