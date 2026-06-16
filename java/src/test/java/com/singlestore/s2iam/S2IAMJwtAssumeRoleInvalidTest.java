package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import com.singlestore.s2iam.exceptions.S2IAMException;
import com.singlestore.s2iam.options.Options;
import com.singlestore.s2iam.options.ServerUrlOption;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.*;

/** Mirrors Go TestGetDatabaseJWT_AssumeRole_InvalidRole. */
public class S2IAMJwtAssumeRoleInvalidTest {
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

  @Test
  void assumeRoleInvalidRole() throws Exception {
    CloudProviderClient provider;
    try {
      provider = S2IAM.detectProvider();
    } catch (NoCloudProviderDetectedException e) {
      Assumptions.abort("cloud provider required");
      return;
    }

    String invalidRole;
    long ts = System.currentTimeMillis() / 1000;
    switch (provider.getType()) {
      case aws:
        invalidRole = "arn:aws:iam::123456789012:role/NonExistentRole-" + ts;
        break;
      case gcp:
        invalidRole = "projects/fake-project/serviceAccounts/nonexistent-" + ts
            + "@fake-project.iam.gserviceaccount.com";
        break;
      case azure:
        invalidRole = UUID.randomUUID().toString();
        break;
      default:
        Assumptions.abort("unsupported provider: " + provider.getType());
        return;
    }

    String url = server.getEndpoints().getOrDefault("auth", server.getBaseURL() + "/auth/iam/:jwtType");
    assertThrows(S2IAMException.class,
        () -> S2IAM.getDatabaseJWT("test-workspace", ServerUrlOption.of(url), Options.withAllowHttp(),
            Options.withAssumeRole(invalidRole)));
  }
}
