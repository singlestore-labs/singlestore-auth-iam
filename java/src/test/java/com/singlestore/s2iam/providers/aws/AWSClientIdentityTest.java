package com.singlestore.s2iam.providers.aws;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for the AWS assumed-role ARN parsing used by the canonical
 * identity mapping. Mirrors the Go TestCanonicalIdentity and Python
 * test_aws_identity.
 */
public class AWSClientIdentityTest {

  @Test
  void parsesAssumedRoleArn() {
    String[] r = AWSClient.parseAssumedRoleArn(
        "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session");
    assertNotNull(r);
    assertEquals("ExampleCloudPrincipalRole", r[0]);
    assertEquals("example-session", r[1]);
  }

  @Test
  void baseRoleArnIsSessionIndependent() {
    // The derived base role ARN depends only on account + role name, not session.
    String[] a = AWSClient.parseAssumedRoleArn(
        "arn:aws:sts::503396375767:assumed-role/NoPermissionsRole/s2iam-session");
    String[] b = AWSClient.parseAssumedRoleArn(
        "arn:aws:sts::503396375767:assumed-role/NoPermissionsRole/other-session");
    assertNotNull(a);
    assertNotNull(b);
    assertEquals(a[0], b[0]);
    assertEquals("arn:aws:iam::503396375767:role/" + a[0],
        "arn:aws:iam::503396375767:role/" + b[0]);
  }

  @Test
  void iamUserIsNotAnAssumedRole() {
    assertNull(AWSClient.parseAssumedRoleArn("arn:aws:iam::123456789012:user/Alice"));
    assertNull(AWSClient.parseAssumedRoleArn("arn:aws:iam::123456789012:role/MyRole"));
    assertNull(AWSClient.parseAssumedRoleArn("not-an-arn"));
  }
}
