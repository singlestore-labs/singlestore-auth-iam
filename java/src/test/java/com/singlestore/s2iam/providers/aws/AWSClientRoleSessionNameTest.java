package com.singlestore.s2iam.providers.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

public class AWSClientRoleSessionNameTest {
  @Test
  void resolveRoleSessionNameUsesAdditionalParams() {
    String name = AWSClient.resolveRoleSessionName(
        Map.of(AWSClient.ROLE_SESSION_NAME_PARAM, "my-custom-session"));
    assertEquals("my-custom-session", name);
  }

  @Test
  void resolveRoleSessionNameDefaultsWhenUnset() {
    String name = AWSClient.resolveRoleSessionName(null);
    assertTrue(name.startsWith("SingleStoreAuth-"));
  }
}
