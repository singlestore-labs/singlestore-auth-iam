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
   * Sets the AWS STS RoleSessionName used on the library-driven AssumeRole call
   * (see {@link #withAssumeRole}). It applies only to that path, not to ambient
   * credentials (EC2 instance profiles, EKS IRSA).
   *
   * <p>
   * The session name is part of the identity under the "aws-arn" format, whose
   * JWT {@code sub} is the full STS ARN
   * {@code arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION}. When unset the
   * library uses a stable default so the full ARN is deterministic and can be
   * pre-configured as a cloud principal / database user. It does not affect the
   * "aws-iam-role-arn" (session-stripped base role ARN) format, which is the
   * default as of v0.6.0, so this option only matters when you request "aws-arn"
   * via {@link #withIdentityFormatPreference}.
   */
  public static JwtOption withAssumeRoleSessionName(String sessionName) {
    return o -> o.assumeRoleSessionName = sessionName;
  }

  /**
   * Sets the ordered identity-format preference sent to the auth service via the
   * X-S2IAM-Identity-Format-Preference header. The verifier chooses the first
   * format that is both server-supported and valid for the attested identity (for
   * example prefer "aws-iam-role-arn" and fall back to "aws-arn"). Tokens are
   * provider-prefixed, so a single list can serve a heterogeneous fleet; unknown
   * or inapplicable tokens are ignored.
   *
   * <p>
   * Precedence: this explicit option &gt; the S2IAM_IDENTITY_FORMAT_PREFERENCE
   * environment variable &gt; the built-in default, which names every provider so
   * the identity cannot move if a verifier operator changes the server-side
   * default ordering. Setting a preference that omits a provider gives that
   * provider's identity back to the verifier's ordering.
   */
  public static JwtOption withIdentityFormatPreference(String... formats) {
    return o -> {
      o.identityFormatPreference = java.util.Arrays.asList(formats);
      o.identityFormatPreferenceSet = true;
    };
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
