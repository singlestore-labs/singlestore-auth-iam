package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import com.singlestore.s2iam.options.Options;
import com.singlestore.s2iam.exceptions.S2IAMException;
import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import org.junit.jupiter.api.Assumptions;
import java.nio.file.Path;
import org.junit.jupiter.api.*;

/**
 * Basic tests for the S2IAMRequest fluent builder using the local Go test
 * server.
 */
public class S2IAMRequestBuilderTest {
  GoTestServer server;

  @BeforeEach
  void start() throws Exception {
    server = new GoTestServer(Path.of(".").toAbsolutePath());
    server.start();
  }

  @AfterEach
  void stop() {
    if (server != null)
      server.stop();
  }

  private String url() {
    return server.getEndpoints().getOrDefault("auth", server.getBaseURL() + "/auth/iam/:jwtType");
  }

  @Test
  void databaseJwtViaBuilder() throws Exception {
    assumeOrSkip();
    CloudProviderClient provider = S2IAM.detectProvider();
    S2IAMRequest req = S2IAMRequest.newRequest().databaseWorkspaceGroup("wg-test").serverUrl(url())
        .timeout(java.time.Duration.ofSeconds(3));
    boolean realCloud = expectCloud();
    if (provider.getType() == CloudProviderType.gcp && realCloud) {
      req.audience("https://authsvc.singlestore.com");
    }
    // Inject provider to avoid second detection.
    req.provider(provider);
    String jwt = req.get();
    assertNotNull(jwt);
    assertFalse(jwt.isEmpty());
  }

  @Test
  void apiJwtViaBuilder() throws Exception {
    assumeOrSkip();
    CloudProviderClient provider = S2IAM.detectProvider();
    S2IAMRequest req = S2IAMRequest.newRequest().api().serverUrl(url());
    boolean realCloud = expectCloud();
    if (provider.getType() == CloudProviderType.gcp && realCloud) {
      req.audience("https://authsvc.singlestore.com");
    }
    req.provider(provider);
    String jwt = req.get();
    assertNotNull(jwt);
    assertFalse(jwt.isEmpty());
  }

  @Test
  void missingWorkspaceGroupFails() {
    S2IAMException ex = assertThrows(S2IAMException.class, () -> S2IAMRequest.newRequest().get());
    assertTrue(ex.getMessage().contains("workspace group id"));
  }

  private void assumeOrSkip() throws Exception {
    // Skip entirely on explicit NO_ROLE environments where we expect cloud
    // detection
    // to work but identity headers / JWT retrieval to fail due to missing
    // permissions
    // or intentionally unavailable metadata (e.g. GCP 404 identity, Azure 400 MI
    // token,
    // AWS missing credentials chain). These hosts set only
    // S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE.
    if (isNoRoleOnlyEnvironment()) {
      Assumptions.abort("No-role environment - skipping JWT builder tests");
      return;
    }
    boolean expect = expectCloud();
    try {
      S2IAM.detectProvider();
      if (!expect) {
        Assumptions.abort("Cloud provider not explicitly requested - skipping");
      }
    } catch (NoCloudProviderDetectedException e) {
      if (expect) {
        fail("Cloud provider detection failed - expected to detect provider in test environment");
      } else {
        Assumptions.abort("No cloud provider detected - skipping");
      }
    }
  }

  private boolean isNoRoleOnlyEnvironment() {
    String noRole = System.getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE");
    String provider = System.getenv("S2IAM_TEST_CLOUD_PROVIDER");
    String assume = System.getenv("S2IAM_TEST_ASSUME_ROLE");
    // Only skip when NO_ROLE is set and neither a normal provider selection nor
    // assume-role test
    // is in effect.
    return noRole != null && !noRole.isEmpty() && provider == null && assume == null;
  }

  private boolean expectCloud() {
    return System.getenv("S2IAM_TEST_CLOUD_PROVIDER") != null
        || System.getenv("S2IAM_TEST_ASSUME_ROLE") != null
        || System.getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE") != null;
  }

  @Test
  void audience_only_allowed_for_gcp_builder_validation() {
    S2IAMRequest r = S2IAMRequest.newRequest().api()
        .provider(new FakeProviderLocal(CloudProviderType.aws)).audience("foo");
    assertThrows(S2IAMException.class, r::get, "Audience on non-GCP provider should error");
  }

  @Test
  void audience_option_static_api_rejected_for_non_gcp_provider() {
    FakeProviderLocal awsLike = new FakeProviderLocal(CloudProviderType.aws);
    S2IAMException ex = assertThrows(S2IAMException.class,
        () -> S2IAM.getAPIJWT(Options.withProvider(awsLike), Options.withAudience("notgcp")));
    assertTrue(ex.getMessage().toLowerCase().contains("gcp"));
  }

  // Minimal local fake provider for audience validation tests (kept local so
  // static
  // analysis does not require cross-file lookup in test sources).
  static class FakeProviderLocal implements CloudProviderClient {
    private final CloudProviderType type;
    FakeProviderLocal(CloudProviderType type) {
      this.type = type;
    }
    @Override
    public CloudProviderType getType() {
      return type;
    }
    @Override
    public CloudProviderClient assumeRole(String roleIdentifier) {
      return this;
    }
    @Override
    public Exception fastDetect() {
      return null;
    }
    @Override
    public Exception detect() {
      return null;
    }
    @Override
    public IdentityHeadersResult getIdentityHeaders(
        java.util.Map<String, String> additionalParams) {
      java.util.Map<String, String> headers = new java.util.HashMap<>();
      headers.put("X-Test", "ok");
      CloudIdentity id = new CloudIdentity(type, "local", null, null, null,
          java.util.Collections.emptyMap());
      return new IdentityHeadersResult(headers, id, null);
    }
  }
}
