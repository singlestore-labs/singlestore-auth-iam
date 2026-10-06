package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import com.singlestore.s2iam.IdentityFormat.Candidate;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the shared identity-format negotiation (mirrors the Go models
 * tests).
 */
public class IdentityFormatTest {

  private static final List<Candidate> AWS_ASSUMED_ROLE = List.of(
      new Candidate(IdentityFormat.AWS_ARN,
          "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session"),
      new Candidate(IdentityFormat.AWS_IAM_ROLE_ARN,
          "arn:aws:iam::111122223333:role/ExampleCloudPrincipalRole"),
      new Candidate(IdentityFormat.AWS_ROLE_ID, "AROAEXAMPLE1234567890"));

  @Test
  void providerAndDefaults() {
    assertEquals(CloudProviderType.aws, IdentityFormat.provider(IdentityFormat.AWS_ARN));
    assertEquals(CloudProviderType.gcp, IdentityFormat.provider(IdentityFormat.GCP_SA_EMAIL));
    assertEquals(CloudProviderType.azure,
        IdentityFormat.provider(IdentityFormat.AZURE_RESOURCE_ID));
    assertNull(IdentityFormat.provider("future-token"));
    assertEquals(List.of(IdentityFormat.AWS_ARN),
        IdentityFormat.defaultOrder(CloudProviderType.aws));
  }

  @Test
  void parsePreference() {
    assertEquals(List.of(), IdentityFormat.parsePreference(null));
    assertEquals(List.of(IdentityFormat.AWS_IAM_ROLE_ARN, IdentityFormat.AWS_ARN),
        IdentityFormat.parsePreference("aws-iam-role-arn,aws-arn"));
    assertEquals(List.of(IdentityFormat.AWS_ARN, "future"),
        IdentityFormat.parsePreference(" aws-arn , , future "));
  }

  @Test
  void newPreferenceSelectsBaseRoleArn() {
    Candidate chosen = IdentityFormat.select(CloudProviderType.aws, AWS_ASSUMED_ROLE,
        List.of(IdentityFormat.AWS_IAM_ROLE_ARN, IdentityFormat.AWS_ARN),
        IdentityFormat.defaultOrder(CloudProviderType.aws));
    assertEquals(IdentityFormat.AWS_IAM_ROLE_ARN, chosen.format);
    assertEquals("arn:aws:iam::111122223333:role/ExampleCloudPrincipalRole", chosen.value);
  }

  @Test
  void legacyPreferenceKeepsRawArnWithSession() {
    Candidate chosen = IdentityFormat.select(CloudProviderType.aws, AWS_ASSUMED_ROLE,
        List.of(IdentityFormat.AWS_ARN), IdentityFormat.defaultOrder(CloudProviderType.aws));
    assertEquals(IdentityFormat.AWS_ARN, chosen.format);
    assertTrue(chosen.value.endsWith("/example-session"));
  }

  @Test
  void iamUserFallsBackToRawArn() {
    List<Candidate> valid = List
        .of(new Candidate(IdentityFormat.AWS_ARN, "arn:aws:iam::1:user/alice"));
    Candidate chosen = IdentityFormat.select(CloudProviderType.aws, valid,
        List.of(IdentityFormat.AWS_IAM_ROLE_ARN, IdentityFormat.AWS_ARN),
        IdentityFormat.defaultOrder(CloudProviderType.aws));
    assertEquals(IdentityFormat.AWS_ARN, chosen.format);
    assertEquals("arn:aws:iam::1:user/alice", chosen.value);
  }

  @Test
  void otherProviderAndUnknownTokensIgnored() {
    Candidate chosen = IdentityFormat.select(CloudProviderType.aws, AWS_ASSUMED_ROLE,
        List.of(IdentityFormat.GCP_SA_EMAIL, "future"),
        IdentityFormat.defaultOrder(CloudProviderType.aws));
    assertEquals(IdentityFormat.AWS_ARN, chosen.format);
  }

  @Test
  void emptyIntersectionFailsClosedToFloor() {
    List<Candidate> valid = List.of(new Candidate(IdentityFormat.AWS_ARN, "arn:aws:iam::1:user/x"));
    Candidate chosen = IdentityFormat.select(CloudProviderType.aws, valid,
        List.of(IdentityFormat.AWS_ROLE_ID), List.of(IdentityFormat.AWS_IAM_ROLE_ARN));
    assertEquals(IdentityFormat.AWS_ARN, chosen.format);
    assertEquals("arn:aws:iam::1:user/x", chosen.value);
  }
}
