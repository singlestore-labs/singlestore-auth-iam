package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the client-side identity-format vocabulary + preference
 * parsing.
 *
 * <p>
 * The negotiation algorithm itself lives only in the Go verifier; its behavior
 * is covered end-to-end by the integration tests that exercise a real Go server
 * (e.g. {@link S2IAMJwtAssumeRoleTest}). Here we only unit-test the pure
 * client-side preference parser.
 */
public class IdentityFormatTest {

  @Test
  void parsePreference() {
    assertEquals(List.of(), IdentityFormat.parsePreference(null));
    assertEquals(List.of(), IdentityFormat.parsePreference(""));
    assertEquals(List.of(IdentityFormat.AWS_IAM_ROLE_ARN, IdentityFormat.AWS_ARN),
        IdentityFormat.parsePreference("aws-iam-role-arn,aws-arn"));
    // Whitespace trimmed, empty entries dropped, unknown tokens preserved verbatim.
    assertEquals(List.of(IdentityFormat.AWS_ARN, "future"),
        IdentityFormat.parsePreference(" aws-arn , , future "));
  }
}
