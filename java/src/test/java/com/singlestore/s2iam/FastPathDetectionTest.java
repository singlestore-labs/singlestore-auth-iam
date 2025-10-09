package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/** Parity fast-path detection tests (local only, skipped on real cloud). */
public class FastPathDetectionTest {

  private boolean isCloudEnv() {
    return env("S2IAM_TEST_CLOUD_PROVIDER") || env("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
        || env("S2IAM_TEST_ASSUME_ROLE");
  }

  private boolean env(String k) {
    return System.getenv(k) != null && !System.getenv(k).isEmpty();
  }

  @Test
  void fastPathAWSViaEnv() throws Exception {
    Assumptions.assumeFalse(isCloudEnv(), "local-only fast path test");
    // simulate fast path via dedicated system property hook
    System.setProperty("s2iam.test.awsFast", "true");
    try {
      CloudProviderClient c = S2IAM.detectProvider();
      assertEquals("aws", c.getType().name());
    } catch (NoCloudProviderDetectedException e) {
      fail("expected fast path AWS detection");
    } finally {
      System.clearProperty("s2iam.test.awsFast");
    }
  }

  @Test
  void fastPathGCPViaCredentials() throws Exception {
    Assumptions.assumeFalse(isCloudEnv(), "local-only fast path test");
    System.setProperty("s2iam.test.gcpFast", "true");
    try {
      CloudProviderClient c = S2IAM.detectProvider();
      assertEquals("gcp", c.getType().name());
    } catch (NoCloudProviderDetectedException e) {
      fail("expected fast path GCP detection");
    } finally {
      System.clearProperty("s2iam.test.gcpFast");
    }
  }

  @Test
  void fastPathAzureViaFederatedToken() throws Exception {
    Assumptions.assumeFalse(isCloudEnv(), "local-only fast path test");
    System.setProperty("s2iam.test.azureFast", "true");
    try {
      CloudProviderClient c = S2IAM.detectProvider();
      assertEquals("azure", c.getType().name());
    } catch (NoCloudProviderDetectedException e) {
      fail("expected fast path Azure detection");
    } finally {
      System.clearProperty("s2iam.test.azureFast");
    }
  }

  // Local fast-path tests rely only on dedicated system properties
  // (s2iam.test.*Fast).
}
