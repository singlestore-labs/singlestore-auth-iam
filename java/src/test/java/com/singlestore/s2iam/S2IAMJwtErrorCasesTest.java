package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import com.singlestore.s2iam.exceptions.S2IAMException;
import com.singlestore.s2iam.options.ServerUrlOption;
import java.nio.file.Path;
import org.junit.jupiter.api.*;

public class S2IAMJwtErrorCasesTest {
  GoTestServer base;

  @BeforeEach
  void start() throws Exception {
    base = new GoTestServer(Path.of(".").toAbsolutePath());
    base.start();
  }

  @AfterEach
  void stop() {
    if (base != null) base.stop();
  }

  private String url() {
    return base.getBaseURL() + "/auth/iam/:jwtType";
  }

  @Test
  void serverReturnsEmptyJWT() throws Exception {
    assumeOrSkip();
    // Start dedicated server with flag --return-empty-jwt
    base.stop();
    base = new GoTestServer(Path.of(".").toAbsolutePath(), "-return-empty-jwt");
    base.start();
    S2IAMException ex =
        assertThrows(
            S2IAMException.class, () -> S2IAM.getDatabaseJWT("wg", ServerUrlOption.of(url())));
    assertTrue(ex.getMessage().contains("empty"));
  }

  @Test
  void serverReturnsError() throws Exception {
    assumeOrSkip();
    base.stop();
    base = new GoTestServer(Path.of(".").toAbsolutePath(), "-return-error", "-error-code", "500");
    base.start();
    S2IAMException ex =
        assertThrows(S2IAMException.class, () -> S2IAM.getAPIJWT(ServerUrlOption.of(url())));
    assertTrue(ex.getMessage().contains("500"));
  }

  private void assumeOrSkip() throws Exception {
    boolean expectCloud = expectCloud();
    try {
      S2IAM.detectProvider();
    } catch (NoCloudProviderDetectedException e) {
      if (expectCloud) {
        fail("Cloud provider detection failed - expected to detect provider in test environment");
      } else {
        Assumptions.abort("No cloud provider detected - skipping");
      }
    }
  }

  private boolean expectCloud() {
    return System.getenv("S2IAM_TEST_CLOUD_PROVIDER") != null
        || System.getenv("S2IAM_TEST_ASSUME_ROLE") != null
        || System.getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE") != null;
  }
}
