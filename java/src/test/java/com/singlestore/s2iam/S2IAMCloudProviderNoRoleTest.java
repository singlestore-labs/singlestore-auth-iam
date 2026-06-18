package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import com.singlestore.s2iam.exceptions.IdentityUnavailableException;
import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import org.junit.jupiter.api.*;

/** Mirrors Go TestCloudProviderNoRole. */
public class S2IAMCloudProviderNoRoleTest {
  @Test
  void cloudProviderNoRole() throws Exception {
    String noRole = System.getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE");
    if (noRole == null || noRole.isEmpty())
      Assumptions.abort("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE not set");

    CloudProviderClient client;
    try {
      client = S2IAM.detectProvider();
    } catch (NoCloudProviderDetectedException e) {
      return;
    }

    switch (noRole) {
      case "aws":
        assertEquals(CloudProviderType.aws, client.getType());
        break;
      case "gcp":
        assertEquals(CloudProviderType.gcp, client.getType());
        break;
      case "azure":
        assertEquals(CloudProviderType.azure, client.getType());
        break;
      default :
        fail("Unknown provider in S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE: " + noRole);
    }

    CloudProviderClient.IdentityHeadersResult res = client.getIdentityHeaders(java.util.Map.of());
    assertNotNull(res.error, "GetIdentityHeaders should fail when no role is assigned");
    assertTrue(
        res.error instanceof IdentityUnavailableException
            || res.error instanceof IllegalStateException,
        "unexpected error type: " + res.error.getClass().getName());
  }
}
