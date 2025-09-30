package com.singlestore.s2iam;

import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.Assumptions;

/**
 * Centralized helper for skipping tests on *NO_ROLE* hosts where cloud
 * identity/credentials are intentionally unavailable. Mirrors Go/Python
 * semantics: when S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE is set, identity retrieval
 * failures for the designated provider are expected and tests that depend on a
 * working identity should be skipped (aborted) rather than failed.
 */
final class TestSkipUtil {
  private TestSkipUtil() {
  }

  private static final String ENV_NO_ROLE = "S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE";
  private static final String ENV_EXPECT = "S2IAM_TEST_CLOUD_PROVIDER";
  private static final String ENV_ASSUME = "S2IAM_TEST_ASSUME_ROLE";

  static void skipIfNoRole(CloudProviderClient provider,
      CloudProviderClient.IdentityHeadersResult res) {
    if (System.getenv(ENV_NO_ROLE) == null)
      return; // Not a NO_ROLE run
    if (res == null || res.error == null)
      return; // Nothing to evaluate
    String msg = String.valueOf(res.error.getMessage());
    switch (provider.getType()) {
      case gcp:
        if (containsAny(msg, "gcp-no-role-identity-unavailable-404",
            "failed to get GCP identity token status=404")) {
          Assumptions.abort("GCP NO_ROLE host: identity unavailable (expected)");
        }
        break;
      case aws:
        if (containsAny(msg, "Unable to load credentials from any of the providers",
            "Failed to load credentials from IMDS")) {
          Assumptions.abort("AWS NO_ROLE host: credentials unavailable (expected)");
        }
        break;
      case azure:
        if (containsAny(msg, "failed to get Azure MI token status=400")) {
          Assumptions.abort("Azure NO_ROLE host: managed identity unavailable (expected)");
        }
        break;
      default :
        // future providers: fall through
    }
  }

  /**
   * Skip when running on an Azure host without managed identity (MI 400/403/404)
   * in a job that is NOT explicitly a cloud test (no expectation env vars). This
   * occurs on generic GitHub-hosted runners (Azure VM without MI). We treat this
   * as equivalent to "no cloud provider detected" for identity-bearing tests.
   * Real cloud test jobs always set one of the expectation env vars and therefore
   * won't skip here; they should provision MI or use *_NO_ROLE env to trigger the
   * other skip path.
   */
  static void skipIfAzureMIUnavailable(CloudProviderClient provider,
      CloudProviderClient.IdentityHeadersResult res) {
    if (provider.getType() != CloudProviderType.azure)
      return;
    if (System.getenv(ENV_EXPECT) != null || System.getenv(ENV_ASSUME) != null
        || System.getenv(ENV_NO_ROLE) != null) {
      return; // Cloud test run; let normal logic handle failures / skips
    }
    if (res == null || res.error == null)
      return;
    String msg = String.valueOf(res.error.getMessage());
    if (containsAny(msg, "failed to get Azure MI token status=400",
        "failed to get Azure MI token status=403", "failed to get Azure MI token status=404")) {
      Assumptions.abort("Azure MI unavailable on shared runner (treat as no identity)");
    }
  }

  static void skipIfNoRoleProbe(CloudProviderClient provider) {
    skipIfNoRoleProbe(provider, Collections.emptyMap());
  }

  static void skipIfNoRoleProbe(CloudProviderClient provider, Map<String, String> params) {
    if (System.getenv(ENV_NO_ROLE) == null)
      return;
    CloudProviderClient.IdentityHeadersResult res = provider.getIdentityHeaders(params);
    skipIfNoRole(provider, res);
  }

  private static boolean containsAny(String haystack, String... needles) {
    for (String n : needles)
      if (haystack.contains(n))
        return true;
    return false;
  }
}
