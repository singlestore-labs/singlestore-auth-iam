package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.*;
import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import com.singlestore.s2iam.exceptions.IdentityUnavailableException;
import com.singlestore.s2iam.exceptions.S2IAMException;
import com.singlestore.s2iam.options.JwtOption;
import com.singlestore.s2iam.options.Options; // for withAudience
import com.singlestore.s2iam.options.ServerUrlOption;
import java.net.*;
import java.net.http.*;
import java.nio.file.Path;
import java.util.*;
import java.util.Base64;
import org.junit.jupiter.api.*;

/** Happy path JWT acquisition tests via Go test server. */
public class S2IAMJwtHappyPathTest {
  static GoTestServer server;
  static final ObjectMapper M = new ObjectMapper();

  @BeforeAll
  static void startServer() throws Exception {
    // Skip entirely if running in cloud provider detection only environments
    // lacking local build
    // tools? assume go present.
    Path here = Path.of(".").toAbsolutePath();
    server = new GoTestServer(here);
    server.start();
  }

  @AfterAll
  static void stopServer() {
    if (server != null)
      server.stop();
  }

  @Test
  void getDatabaseJWT() throws Exception {
    assumeOrSkip();
    CloudProviderClient provider = S2IAM.detectProvider();
    Map<String, String> addl = new HashMap<>();
    boolean realCloud = expectCloud();
    if (provider.getType() == CloudProviderType.gcp && realCloud) {
      addl.put("audience", "https://authsvc.singlestore.com");
    }
    CloudProviderClient.IdentityHeadersResult idRes = provider.getIdentityHeaders(addl);
  TestSkipUtil.skipIfNoRole(provider, idRes);
  TestSkipUtil.skipIfAzureMIUnavailable(provider, idRes);
  if (idRes.error instanceof IdentityUnavailableException) {
    // Treat as expected unavailability in NO_ROLE scenarios if skip util missed; abort.
    org.junit.jupiter.api.Assumptions.abort(
      "identity unavailable (expected in no-role environment): " + idRes.error.getMessage());
  }
  assertNull(idRes.error, "identity header retrieval failed: "
    + (idRes.error == null ? "" : idRes.error.getMessage()));
    CloudIdentity cid = idRes.identity;
    assertNotNull(cid, "client identity null");

    java.util.List<JwtOption> opts = new java.util.ArrayList<>();
    // Use dynamic auth endpoint from server info (endpoints map) which already
    // includes :jwtType
    opts.add(ServerUrlOption.of(
        server.getEndpoints().getOrDefault("auth", server.getBaseURL() + "/auth/iam/:jwtType")));
    if (provider.getType() == CloudProviderType.gcp && realCloud)
      opts.add(Options.withAudience("https://authsvc.singlestore.com"));
    String jwt = S2IAM.getDatabaseJWT("wg-test", opts.toArray(new JwtOption[0]));
    assertNotNull(jwt);
    assertFalse(jwt.isEmpty());
    assertTrue(jwt.split("\\.").length >= 2, "looks like a JWT");

    // Fetch server request log and verify identity parity
    JsonNode lastReq = fetchLastRequest();
    assertNotNull(lastReq, "server request log empty");
    JsonNode identity = lastReq.path("identity");
    assertEquals(cid.getIdentifier(), identity.path("identifier").asText(),
        "client/server identifier mismatch");
    assertEquals(cid.getProvider().name(), identity.path("provider").asText());

    // Decode JWT payload (no signature verification – parity check for 'sub')
    String sub = decodeSub(jwt);
    assertEquals(cid.getIdentifier(), sub, "JWT sub mismatch");
  }

  @Test
  void getAPIJWT() throws Exception {
    assumeOrSkip();
    CloudProviderClient provider = S2IAM.detectProvider();
    Map<String, String> addl = new HashMap<>();
    boolean realCloud = expectCloud();
    if (provider.getType() == CloudProviderType.gcp && realCloud) {
      addl.put("audience", "https://authsvc.singlestore.com");
    }
    CloudProviderClient.IdentityHeadersResult idRes = provider.getIdentityHeaders(addl);
    TestSkipUtil.skipIfNoRole(provider, idRes);
    TestSkipUtil.skipIfAzureMIUnavailable(provider, idRes);
    if (idRes.error instanceof IdentityUnavailableException) {
      org.junit.jupiter.api.Assumptions.abort(
          "identity unavailable (expected in no-role environment): " + idRes.error.getMessage());
    }
    assertNull(idRes.error);
    CloudIdentity cid = idRes.identity;
    java.util.List<JwtOption> opts = new java.util.ArrayList<>();
    opts.add(ServerUrlOption.of(
        server.getEndpoints().getOrDefault("auth", server.getBaseURL() + "/auth/iam/:jwtType")));
    if (provider.getType() == CloudProviderType.gcp && realCloud)
      opts.add(Options.withAudience("https://authsvc.singlestore.com"));
    String jwt = S2IAM.getAPIJWT(opts.toArray(new JwtOption[0]));
    assertNotNull(jwt);
    assertFalse(jwt.isEmpty());
    JsonNode lastReq = fetchLastRequest();
    assertEquals(cid.getIdentifier(), lastReq.path("identity").path("identifier").asText());
    assertEquals(cid.getProvider().name(), lastReq.path("identity").path("provider").asText());
    assertEquals(cid.getIdentifier(), decodeSub(jwt));
  }

  @Test
  void getDatabaseJWT_GcpAudienceCustomLocal() throws Exception {
    assumeOrSkip();
    CloudProviderClient provider = S2IAM.detectProvider();
    if (provider.getType() != CloudProviderType.gcp) {
      Assumptions.abort("not GCP");
    }
    if (System.getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE") != null) {
      TestSkipUtil.skipIfNoRoleProbe(provider,
          Map.of("audience", "https://authsvc.singlestore.com"));
    }
    String audience = expectCloud()
        ? "https://authsvc.singlestore.com"
        : "https://test.example.com";
    String jwt = S2IAM.getDatabaseJWT("wg-test",
        ServerUrlOption.of(
            server.getEndpoints().getOrDefault("auth", server.getBaseURL() + "/auth/iam/:jwtType")),
        Options.withAudience(audience));
    assertNotNull(jwt);
    assertFalse(jwt.isEmpty());
  }

  @Test
  void missingWorkspaceGroupId() {
    S2IAMException ex = assertThrows(S2IAMException.class, () -> S2IAM.getDatabaseJWT("",
        ServerUrlOption.of(server.getBaseURL() + "/auth/iam/:jwtType")));
    assertTrue(ex.getMessage().contains("workspaceGroupId"));
  }

  private void assumeOrSkip() throws Exception {
    boolean expectCloud = expectCloud();
    try {
      // Quick detection attempt; if it fails and not expecting cloud, abort test via
      // Assumptions
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

  private JsonNode fetchLastRequest() throws Exception {
    String url = server.getBaseURL() + "/info/requests";
    HttpClient c = HttpClient.newHttpClient();
    HttpRequest r = HttpRequest.newBuilder(URI.create(url)).GET().build();
    HttpResponse<String> resp = c.send(r, HttpResponse.BodyHandlers.ofString());
    if (resp.statusCode() != 200)
      return null;
    JsonNode arr = M.readTree(resp.body());
    if (!arr.isArray() || arr.size() == 0)
      return null;
    return arr.get(arr.size() - 1);
  }

  private String decodeSub(String jwt) throws Exception {
    String[] parts = jwt.split("\\.");
    if (parts.length < 2)
      return null;
    String payload = parts[1];
    // Pad base64url if needed
    int rem = payload.length() % 4;
    if (rem > 0)
      payload += "====".substring(rem);
    byte[] decoded = Base64.getUrlDecoder().decode(payload);
    JsonNode node = M.readTree(decoded);
    return node.path("sub").asText();
  }
}
