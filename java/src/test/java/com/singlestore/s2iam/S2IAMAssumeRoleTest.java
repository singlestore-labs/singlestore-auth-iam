package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * When S2IAM_TEST_ASSUME_ROLE is set we must detect the cloud provider and
 * successfully assume the specified role (fail-fast; do not skip). This
 * validates the direct assumeRole() path (identity headers only) separate from
 * JWT issuance tests.
 */
public class S2IAMAssumeRoleTest {

  @Test
  void testAssumeRoleMustSucceedWhenEnvSet() {
    String roleArn = System.getenv("S2IAM_TEST_ASSUME_ROLE");
    if (roleArn == null || roleArn.isEmpty()) {
      Assumptions.abort("S2IAM_TEST_ASSUME_ROLE not set - skipping assumeRole test");
    }
    CloudProviderClient base;
    try {
      base = S2IAM.detectProvider();
    } catch (NoCloudProviderDetectedException e) {
      fail("Expected provider detection to succeed when S2IAM_TEST_ASSUME_ROLE set: "
          + e.getMessage());
      return; // unreachable
    }
    assertNotNull(base, "provider must be detected");
    CloudProviderClient assumed = base.assumeRole(roleArn);
    assertNotNull(assumed, "assumeRole returned null client");
    CloudProviderClient.IdentityHeadersResult res = assumed.getIdentityHeaders(java.util.Map.of());
    assertNull(res.error, "assumeRole identity retrieval failed: "
        + (res.error == null ? "" : res.error.getMessage()));
    assertNotNull(res.identity, "identity missing after assumeRole");
    assertEquals(roleArn, res.identity.getIdentifier(),
        "identity identifier should match requested role ARN");
  }
}
