package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

public class S2IAMDetectionTest {

  @Test
  void testDetectionSkipOrFail() {
    String expectProvider = System.getenv("S2IAM_TEST_CLOUD_PROVIDER");
    boolean assumeRole = false;
    if (expectProvider == null) {
      String role = System.getenv("S2IAM_TEST_ASSUME_ROLE");
      if (role != null && !role.isEmpty()) {
        assumeRole = true;
        expectProvider = "aws"; // assume role only currently supported for AWS
      }
    }
    if (expectProvider == null)
      expectProvider = System.getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE");
    try {
      CloudProviderClient client = S2IAM.detectProvider();
      assertNotNull(client, "provider should not be null when detected");
      if (expectProvider != null) {
        assertEquals(expectProvider.toLowerCase(), client.getType().name().toLowerCase(),
            "detected provider mismatch");
      }
    } catch (NoCloudProviderDetectedException e) {
      if (expectProvider != null) {
        fail("Cloud provider detection failed - expected to detect provider in test environment");
      }
      Assumptions.abort("No cloud provider detected - not running in cloud environment");
    }
  }
}
