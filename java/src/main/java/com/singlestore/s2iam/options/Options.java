package com.singlestore.s2iam.options;

import com.singlestore.s2iam.CloudProviderClient;
import java.time.Duration;

public final class Options {
  private Options() {
  }

  public static JwtOption withServerUrl(String url) {
    return o -> o.serverUrl = url;
  }

  public static JwtOption withAllowHttp() {
    return o -> o.allowHttp = true;
  }

  public static JwtOption withProvider(CloudProviderClient provider) {
    return o -> o.provider = provider;
  }

  public static JwtOption withAudience(String aud) {
    return o -> o.additionalParams.put("audience", aud);
  }

  public static JwtOption withAssumeRole(String role) {
    return o -> o.assumeRoleIdentifier = role;
  }

  public static JwtOption withAssumeRoleSessionName(String sessionName) {
    return o -> o.assumeRoleSessionName = sessionName;
  }

  /** Sets an additional provider-specific parameter forwarded to identity acquisition. */
  public static JwtOption withAdditionalParam(String key, String value) {
    return o -> o.additionalParams.put(key, value);
  }

  /** Timeout for auth-server HTTP requests (JwtOptions.timeout). */
  public static JwtOption withTimeout(Duration d) {
    return o -> o.timeout = d;
  }

  /** Timeout for provider detection (ProviderOptions.timeout). */
  public static ProviderOption withDetectTimeout(Duration d) {
    return ProviderOption.withTimeout(d);
  }

  // Re-export provider options for convenience
  public static ProviderOption withLogger(com.singlestore.s2iam.Logger l) {
    return ProviderOption.withLogger(l);
  }

  public static ProviderOption withClients(java.util.List<CloudProviderClient> c) {
    return ProviderOption.withClients(c);
  }
}
