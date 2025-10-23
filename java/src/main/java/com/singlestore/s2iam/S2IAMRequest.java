package com.singlestore.s2iam;

import com.singlestore.s2iam.exceptions.S2IAMException;
import com.singlestore.s2iam.options.JwtOption;
import com.singlestore.s2iam.options.Options;
import com.singlestore.s2iam.options.ProviderOption;
import java.time.Duration;
import java.util.*;

/**
 * Fluent builder for obtaining JWTs (database or API) with a more idiomatic
 * Java experience than the varargs functional option style. It is purely a
 * convenience layer over the existing static S2IAM methods and Options helpers.
 *
 * Usage example:
 * 
 * <pre>{@code
 * String jwt = S2IAMRequest.newRequest().databaseWorkspaceGroup("wg-123")
 *     .assumeRole("arn:aws:iam::123456789012:role/MyRole").timeout(Duration.ofSeconds(5)).get();
 * }</pre>
 */
public final class S2IAMRequest {
  private boolean apiMode = false;
  private String workspaceGroupId;
  private String assumeRoleId;
  private Duration timeout;
  private String serverUrl;
  private final Map<String, String> additionalParams = new LinkedHashMap<>();
  private CloudProviderClient provider; // optional explicit provider (skips detection)

  private S2IAMRequest() {
  }

  public static S2IAMRequest newRequest() {
    return new S2IAMRequest();
  }

  /** Select API JWT mode (no workspace group id). */
  public S2IAMRequest api() {
    this.apiMode = true;
    this.workspaceGroupId = null;
    return this;
  }

  /** Select database JWT mode and set the workspace group id. */
  public S2IAMRequest databaseWorkspaceGroup(String workspaceGroupId) {
    this.apiMode = false;
    this.workspaceGroupId = workspaceGroupId;
    return this;
  }

  /**
   * Optional assume role identifier (provider specific: AWS role ARN, GCP service
   * account email, Azure object id).
   */
  public S2IAMRequest assumeRole(String assumeRoleId) {
    this.assumeRoleId = assumeRoleId;
    return this;
  }

  /** Overall timeout applied to detection + identity HTTP calls. */
  public S2IAMRequest timeout(Duration timeout) {
    this.timeout = timeout;
    return this;
  }

  /** Override the authentication server base URL (e.g., test server). */
  public S2IAMRequest serverUrl(String serverUrl) {
    this.serverUrl = serverUrl;
    return this;
  }

  /**
   * Provide explicit provider (e.g., FakeProvider in tests) to skip detection.
   */
  public S2IAMRequest provider(CloudProviderClient provider) {
    this.provider = provider;
    return this;
  }

  /**
   * Add a raw additional parameter (forwarded as query parameter when supported).
   */
  public S2IAMRequest param(String key, String value) {
    if (key != null && value != null)
      additionalParams.put(key, value);
    return this;
  }

  /**
   * Set audience parameter (currently GCP-only). Using this when the provider is
   * not GCP will cause an error during execution for explicit clarity.
   */
  public S2IAMRequest audience(String audience) {
    if (audience != null)
      additionalParams.put("audience", audience);
    return this;
  }

  /** Execute the request and return the JWT string. */
  public String get() throws S2IAMException {
    return execute();
  }

  private String execute() throws S2IAMException {
    List<JwtOption> jwtOpts = new ArrayList<>();
    List<ProviderOption> providerOpts = new ArrayList<>();
    if (assumeRoleId != null)
      jwtOpts.add(Options.withAssumeRole(assumeRoleId));
    if (serverUrl != null)
      jwtOpts.add(Options.withServerUrl(serverUrl));
    if (timeout != null)
      providerOpts.add(Options.withTimeout(timeout));
    // Map additional params to existing explicit helpers (currently only audience)
    if (additionalParams.containsKey("audience")) {
      // Validate provider type if provider already set (explicit builder provider) or
      // later after detection
      if (provider != null && provider.getType() != CloudProviderType.gcp) {
        throw new S2IAMException(
            "audience is GCP-only and cannot be used with provider=" + provider.getType());
      }
      jwtOpts.add(Options.withAudience(additionalParams.get("audience")));
    }
    JwtOption[] jwtArr = jwtOpts.toArray(new JwtOption[0]);
    ProviderOption[] providerArr = providerOpts.toArray(new ProviderOption[0]);
    if (provider != null) {
      jwtOpts.add(com.singlestore.s2iam.options.Options.withProvider(provider));
      jwtArr = jwtOpts.toArray(new JwtOption[0]);
    }
    if (apiMode) {
      if (provider != null && additionalParams.containsKey("audience")
          && provider.getType() != CloudProviderType.gcp) {
        throw new S2IAMException(
            "audience is GCP-only and cannot be used with provider=" + provider.getType());
      }
      return S2IAM.getAPIJWT(jwtArr, providerArr);
    }
    if (workspaceGroupId == null || workspaceGroupId.isEmpty()) {
      throw new S2IAMException(
          "workspace group id required for database JWT (call api() for API JWT)");
    }
    return S2IAM.getDatabaseJWT(workspaceGroupId, jwtArr, providerArr);
  }
}
