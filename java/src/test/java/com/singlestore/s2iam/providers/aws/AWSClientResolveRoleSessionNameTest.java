package com.singlestore.s2iam.providers.aws;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import org.junit.jupiter.api.Test;

public class AWSClientResolveRoleSessionNameTest {
  @Test
  void defaultSessionName() {
    assertEquals(AWSClient.DEFAULT_ROLE_SESSION_NAME, AWSClient.resolveRoleSessionName(null));
    assertEquals(AWSClient.DEFAULT_ROLE_SESSION_NAME, AWSClient.resolveRoleSessionName(Map.of()));
  }

  @Test
  void customSessionName() {
    assertEquals("my-app",
        AWSClient.resolveRoleSessionName(Map.of(AWSClient.ROLE_SESSION_NAME_PARAM, "my-app")));
  }
}
