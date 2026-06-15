package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import com.singlestore.s2iam.providers.aws.AWSClient;
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
    CloudProviderClient.IdentityHeadersResult baseRes = base.getIdentityHeaders(java.util.Map.of());
    assertNull(baseRes.error, "base identity retrieval failed: "
        + (baseRes.error == null ? "" : baseRes.error.getMessage()));
    assertNotNull(baseRes.identity, "base identity missing");
    String originalIdentifier = baseRes.identity.getIdentifier();

    CloudProviderClient assumed = base.assumeRole(roleArn);
    assertNotNull(assumed, "assumeRole returned null client");
    CloudProviderClient.IdentityHeadersResult res = assumed.getIdentityHeaders(java.util.Map.of());
    assertNull(res.error, "assumeRole identity retrieval failed: "
        + (res.error == null ? "" : res.error.getMessage()));
    assertNotNull(res.identity, "identity missing after assumeRole");
    String assumedIdentifier = res.identity.getIdentifier();
    assertNotEquals(originalIdentifier, assumedIdentifier,
        "identity should change when assuming role");
    String roleNameFragment = roleArn.contains("/")
        ? roleArn.substring(roleArn.lastIndexOf('/') + 1)
        : roleArn;
    assertTrue(assumedIdentifier.contains(roleNameFragment),
        "assumed identifier should contain role fragment");
    if (roleArn.startsWith("arn:aws:iam:")) {
      assertTrue(assumedIdentifier.contains(AWSClient.DEFAULT_ROLE_SESSION_NAME),
          "assumed identifier should contain default session name");
    }
  }
}
