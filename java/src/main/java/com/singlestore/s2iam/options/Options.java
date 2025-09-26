package com.singlestore.s2iam.options;

import com.singlestore.s2iam.CloudProviderClient;
import java.time.Duration;

public final class Options {
  private Options() {
  }

  public static JwtOption withServerUrl(String url) {
    return o -> o.serverUrl = url;
  }

  public static JwtOption withProvider(CloudProviderClient provider) {
    return o -> o.provider = provider;
  }

  public static JwtOption withGcpAudience(String aud) {
    return o -> o.additionalParams.put("audience", aud);
  }

  public static JwtOption withAssumeRole(String role) {
    return o -> o.assumeRoleIdentifier = role;
  }

  // Re-export provider options for convenience
  public static ProviderOption withTimeout(Duration d) {
    return ProviderOption.withTimeout(d);
  }

  public static ProviderOption withLogger(com.singlestore.s2iam.Logger l) {
    return ProviderOption.withLogger(l);
  }

  public static ProviderOption withClients(java.util.List<CloudProviderClient> c) {
    return ProviderOption.withClients(c);
  }
}
