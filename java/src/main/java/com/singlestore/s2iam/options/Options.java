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

  /**
   * Sets the AWS STS RoleSessionName used on the AssumeRole call. The session
   * name is still sent to AWS (visible in CloudTrail) but no longer affects the
   * issued identity: AWS assumed-role sessions map to the base IAM role ARN
   * regardless of session name.
   *
   * @deprecated the session name no longer affects the issued identity and this
   *             option will be removed in a future release.
   */
  @Deprecated
  public static JwtOption withAssumeRoleSessionName(String sessionName) {
    return o -> o.assumeRoleSessionName = sessionName;
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
