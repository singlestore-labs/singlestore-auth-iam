package com.singlestore.s2iam.providers.aws;

import static org.junit.jupiter.api.Assertions.*;

import com.singlestore.s2iam.IdentityFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the AWS identity-format candidates. The raw ARN (floor) keeps
 * the session (byte-identical to today); only aws-iam-role-arn / aws-role-id
 * strip it. Mirrors the Go TestAWSCandidates and Python test_aws_identity.
 */
public class AWSClientIdentityTest {

  @Test
  void assumedRoleCandidates() {
    String arn = "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session";
    List<IdentityFormat.Candidate> c = AWSClient.awsCandidates(arn, "111122223333",
        "AROAEXAMPLE1234567890:example-session");
    assertEquals(3, c.size());
    assertEquals(new IdentityFormat.Candidate(IdentityFormat.AWS_ARN, arn), c.get(0));
    assertEquals(new IdentityFormat.Candidate(IdentityFormat.AWS_IAM_ROLE_ARN,
        "arn:aws:iam::111122223333:role/ExampleCloudPrincipalRole"), c.get(1));
    assertEquals(new IdentityFormat.Candidate(IdentityFormat.AWS_ROLE_ID, "AROAEXAMPLE1234567890"),
        c.get(2));
  }

  @Test
  void baseRoleArnIsSessionIndependent() {
    IdentityFormat.Candidate a = AWSClient
        .awsCandidates("arn:aws:sts::503396375767:assumed-role/NoPermissionsRole/s2iam-session",
            "503396375767", "AROAX:s2iam-session")
        .get(1);
    IdentityFormat.Candidate b = AWSClient
        .awsCandidates("arn:aws:sts::503396375767:assumed-role/NoPermissionsRole/other-session",
            "503396375767", "AROAX:other-session")
        .get(1);
    assertEquals(a, b);
    assertEquals("arn:aws:iam::503396375767:role/NoPermissionsRole", a.value);
  }

  @Test
  void baseRoleArnPreservesPartition() {
    // GovCloud/China: the derived base role ARN must keep the source partition so
    // it stays byte-identical to the Go verifier's issued JWT sub.
    IdentityFormat.Candidate gov = AWSClient.awsCandidates(
        "arn:aws-us-gov:sts::503396375767:assumed-role/NoPermissionsRole/s2iam-session",
        "503396375767", "AROAX:s2iam-session").get(1);
    assertEquals("arn:aws-us-gov:iam::503396375767:role/NoPermissionsRole", gov.value);
  }

  @Test
  void iamUserHasOnlyTheRawArnFloor() {
    String arn = "arn:aws:iam::123456789012:user/Alice";
    List<IdentityFormat.Candidate> c = AWSClient.awsCandidates(arn, "123456789012", "AIDAEXAMPLE");
    assertEquals(1, c.size());
    assertEquals(new IdentityFormat.Candidate(IdentityFormat.AWS_ARN, arn), c.get(0));
  }

  @Test
  void parseAssumedRoleArnRejectsNonAssumedRole() {
    assertNull(AWSClient.parseAssumedRoleArn("arn:aws:iam::123456789012:user/Alice"));
    assertNull(AWSClient.parseAssumedRoleArn("arn:aws:iam::123456789012:role/MyRole"));
    assertNull(AWSClient.parseAssumedRoleArn("not-an-arn"));
  }

  @Test
  void roleIdFromUserId() {
    assertEquals("AROAEXAMPLE", AWSClient.roleIdFromUserId("AROAEXAMPLE:session"));
    assertEquals("", AWSClient.roleIdFromUserId("AIDANOSESSION"));
    assertEquals("", AWSClient.roleIdFromUserId(null));
  }
}
