package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import com.singlestore.s2iam.exceptions.S2IAMException;
import com.singlestore.s2iam.options.Options;
import com.singlestore.s2iam.options.ServerUrlOption;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Paired tests proving http:// auth server URLs require explicit opt-in. */
public class S2IAMHttpsTest {
  GoTestServer server;

  @BeforeEach
  void start() throws Exception {
    server = new GoTestServer(Path.of(".").toAbsolutePath());
    server.start();
  }

  @AfterEach
  void stop() {
    if (server != null) {
      server.stop();
    }
  }

  private String url() {
    return server.getEndpoints().getOrDefault("auth", server.getBaseURL() + "/auth/iam/:jwtType");
  }

  @Test
  void validateAuthServerURL_acceptsUppercaseHttps() throws Exception {
    S2IAM.validateAuthServerURL("HTTPS://example.com/auth/iam/api", false);
  }

  @Test
  void getJWT_rejectsHttpWithoutAllowHttp() {
    FakeProvider fake = new FakeProvider();
    S2IAMException ex = assertThrows(S2IAMException.class,
        () -> S2IAM.getAPIJWT(Options.withProvider(fake), ServerUrlOption.of(url())));
    assertTrue(ex.getMessage().contains("HTTPS"));
  }

  @Test
  void getJWT_allowsHttpWithAllowHttp() throws Exception {
    CloudProviderClient provider = detectOrSkip();
    String jwt = S2IAM.getAPIJWT(Options.withProvider(provider), ServerUrlOption.of(url()),
        Options.withAllowHttp());
    assertNotNull(jwt);
    assertFalse(jwt.isEmpty());
  }

  private CloudProviderClient detectOrSkip() throws Exception {
    String expectProvider = System.getenv("S2IAM_TEST_CLOUD_PROVIDER");
    if (expectProvider == null) {
      String role = System.getenv("S2IAM_TEST_ASSUME_ROLE");
      if (role != null && !role.isEmpty()) {
        expectProvider = "aws";
      }
    }
    if (expectProvider == null) {
      expectProvider = System.getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE");
    }
    try {
      CloudProviderClient client = S2IAM.detectProvider();
      if (expectProvider == null) {
        Assumptions.abort("No cloud provider detected - not running in cloud environment");
      }
      if (System.getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE") != null
          && System.getenv("S2IAM_TEST_CLOUD_PROVIDER") == null
          && System.getenv("S2IAM_TEST_ASSUME_ROLE") == null) {
        Assumptions.abort("No-role environment - skipping JWT HTTPS allow tests");
      }
      return client;
    } catch (NoCloudProviderDetectedException e) {
      if (expectProvider != null) {
        fail("Cloud provider detection failed - expected to detect provider in test environment");
      }
      Assumptions.abort("No cloud provider detected - skipping");
      return null;
    }
  }

  static final class FakeProvider implements CloudProviderClient {
    @Override
    public CloudProviderType getType() {
      return CloudProviderType.aws;
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
      HashMap<String, String> headers = new HashMap<>();
      headers.put("X-Test", "ok");
      CloudIdentity id = new CloudIdentity(CloudProviderType.aws,
          "arn:aws:iam::123456789012:role/test", "123456789012", "us-east-1", "aws-role",
          Collections.emptyMap());
      return new IdentityHeadersResult(headers, id, null);
    }
  }
}
