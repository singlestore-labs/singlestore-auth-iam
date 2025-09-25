package com.singlestore.s2iam;

import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.Assumptions;

/**
 * Centralized helper for skipping tests on *NO_ROLE* hosts where cloud identity/credentials are
 * intentionally unavailable. Mirrors Go/Python semantics: when
 * S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE is set, identity retrieval failures for the designated
 * provider are expected and tests that depend on a working identity should be skipped (aborted)
 * rather than failed.
 */
final class TestSkipUtil {
  private TestSkipUtil() {}

  private static final String ENV_NO_ROLE = "S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE";

  static void skipIfNoRole(CloudProviderClient provider, CloudProviderClient.IdentityHeadersResult res) {
    if (System.getenv(ENV_NO_ROLE) == null) return; // Not a NO_ROLE run
    if (res == null || res.error == null) return; // Nothing to evaluate
    String msg = String.valueOf(res.error.getMessage());
    switch (provider.getType()) {
      case gcp:
        if (containsAny(msg,
            "gcp-no-role-identity-unavailable-404",
            "failed to get GCP identity token status=404")) {
          Assumptions.abort("GCP NO_ROLE host: identity unavailable (expected)");
        }
        break;
      case aws:
        if (containsAny(msg,
            "Unable to load credentials from any of the providers",
            "Failed to load credentials from IMDS")) {
          Assumptions.abort("AWS NO_ROLE host: credentials unavailable (expected)");
        }
        break;
      case azure:
        if (containsAny(msg, "failed to get Azure MI token status=400")) {
          Assumptions.abort("Azure NO_ROLE host: managed identity unavailable (expected)");
        }
        break;
      default:
        // future providers: fall through
    }
  }

  static void skipIfNoRoleProbe(CloudProviderClient provider) {
    skipIfNoRoleProbe(provider, Collections.emptyMap());
  }

  static void skipIfNoRoleProbe(CloudProviderClient provider, Map<String, String> params) {
    if (System.getenv(ENV_NO_ROLE) == null) return;
    CloudProviderClient.IdentityHeadersResult res = provider.getIdentityHeaders(params);
    skipIfNoRole(provider, res);
  }

  private static boolean containsAny(String haystack, String... needles) {
    for (String n : needles) if (haystack.contains(n)) return true;
    return false;
  }
}
