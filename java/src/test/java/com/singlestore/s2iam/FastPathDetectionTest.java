package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/** Parity fast-path detection tests (local only, skipped on real cloud). */
public class FastPathDetectionTest {

  private boolean isCloudEnv() {
    return env("S2IAM_TEST_CLOUD_PROVIDER")
        || env("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
        || env("S2IAM_TEST_ASSUME_ROLE");
  }

  private boolean env(String k) {
    return System.getenv(k) != null && !System.getenv(k).isEmpty();
  }

  @Test
  void fastPathAWSViaEnv() throws Exception {
    if (isCloudEnv()) Assumptions.abort("local-only fast path test");
    // ensure no other provider env vars interfere
    clearIfSet(
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GCE_METADATA_HOST",
        "AZURE_FEDERATED_TOKEN_FILE",
        "AZURE_CLIENT_ID",
        "AZURE_TENANT_ID",
        "AZURE_ENV");
    System.setProperty("awsFastPathRun", "1");
    try {
      // Simulate AWS fast detection using execution env
      setEnv("AWS_EXECUTION_ENV", "AWS_EC2");
      CloudProviderClient c = S2IAM.detectProvider();
      assertEquals("aws", c.getType().name());
    } catch (NoCloudProviderDetectedException e) {
      fail("expected fast path AWS detection");
    } finally {
      clearEnv("AWS_EXECUTION_ENV");
    }
  }

  @Test
  void fastPathGCPViaCredentials() throws Exception {
    if (isCloudEnv()) Assumptions.abort("local-only fast path test");
    clearIfSet(
        "AWS_EXECUTION_ENV",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AZURE_FEDERATED_TOKEN_FILE",
        "AZURE_CLIENT_ID",
        "AZURE_TENANT_ID",
        "AZURE_ENV");
    Path p = Files.createTempFile("gcp-external-account-", ".json");
    Files.writeString(p, "{\"type\":\"external_account\"}");
    try {
      setEnv("GOOGLE_APPLICATION_CREDENTIALS", p.toString());
      CloudProviderClient c = S2IAM.detectProvider();
      assertEquals("gcp", c.getType().name());
    } catch (NoCloudProviderDetectedException e) {
      fail("expected fast path GCP detection");
    } finally {
      clearEnv("GOOGLE_APPLICATION_CREDENTIALS");
    }
  }

  @Test
  void fastPathAzureViaFederatedToken() throws Exception {
    if (isCloudEnv()) Assumptions.abort("local-only fast path test");
    clearIfSet(
        "AWS_EXECUTION_ENV",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GCE_METADATA_HOST");
    Path p = Files.createTempFile("azure-federated-token-", ".txt");
    Files.writeString(p, "dummy-token");
    try {
      setEnv("AZURE_FEDERATED_TOKEN_FILE", p.toString());
      setEnv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000000");
      setEnv("AZURE_TENANT_ID", "11111111-1111-1111-1111-111111111111");
      CloudProviderClient c = S2IAM.detectProvider();
      assertEquals("azure", c.getType().name());
    } catch (NoCloudProviderDetectedException e) {
      fail("expected fast path Azure detection");
    } finally {
      clearEnv("AZURE_FEDERATED_TOKEN_FILE");
      clearEnv("AZURE_CLIENT_ID");
      clearEnv("AZURE_TENANT_ID");
    }
  }

  // Simple utility (process-wide) - acceptable for isolated test execution.
  private static void setEnv(String key, String value) throws Exception {
    try {
      var env = System.getenv();
      var cl = env.getClass();
      var m = cl.getDeclaredField("m");
      m.setAccessible(true);
      @SuppressWarnings("unchecked")
      var map = (java.util.Map<String, String>) m.get(env);
      map.put(key, value);
    } catch (NoSuchFieldException | IllegalAccessException ex) {
      throw new IOException("cannot set env var", ex);
    }
  }

  private static void clearEnv(String key) throws Exception {
    setEnv(key, "");
  }

  private static void clearIfSet(String... keys) throws Exception {
    for (String k : keys) if (System.getenv(k) != null) clearEnv(k);
  }
}
