package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import com.singlestore.s2iam.options.JwtOption;
import com.singlestore.s2iam.options.Options;
import com.singlestore.s2iam.options.ServerUrlOption;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.*;
import java.util.Base64;
import org.junit.jupiter.api.*;

/**
 * Validates assume-role changes identity in JWT and server log (mirrors Go
 * test).
 */
public class S2IAMJwtAssumeRoleTest {
  static GoTestServer server;
  static final ObjectMapper M = new ObjectMapper();

  @BeforeAll
  static void start() throws Exception {
    server = new GoTestServer(java.nio.file.Path.of(".").toAbsolutePath());
    server.start();
  }

  @AfterAll
  static void stop() {
    if (server != null)
      server.stop();
  }

  @Test
  void assumeRoleDatabaseJWT() throws Exception {
    assumeRoleDatabaseJWT(null);
  }

  @Test
  void assumeRoleDatabaseJWTWithCustomSessionName() throws Exception {
    assumeRoleDatabaseJWT("s2iam-test-session");
  }

  private void assumeRoleDatabaseJWT(String sessionName) throws Exception {
    String role = System.getenv("S2IAM_TEST_ASSUME_ROLE");
    if (role == null || role.isEmpty())
      Assumptions.abort("S2IAM_TEST_ASSUME_ROLE not set");

    CloudProviderClient base;
    try {
      base = S2IAM.detectProvider();
    } catch (NoCloudProviderDetectedException e) {
      fail("Provider detection must succeed when S2IAM_TEST_ASSUME_ROLE set");
      return;
    }

    // Original identity + JWT
    List<JwtOption> opts = new ArrayList<>();
    opts.add(ServerUrlOption.of(
        server.getEndpoints().getOrDefault("auth", server.getBaseURL() + "/auth/iam/:jwtType")));
    opts.add(Options.withAllowHttp());
    if (base.getType() == CloudProviderType.gcp)
      opts.add(Options.withAudience("https://authsvc.singlestore.com"));
    String originalJwt = S2IAM.getDatabaseJWT("test-workspace", opts.toArray(new JwtOption[0]));
    String originalSub = decodeSub(originalJwt);
    JsonNode originalReq = fetchLastRequest();
    String originalIdentifier = originalReq.path("identity").path("identifier").asText();
    assertEquals(originalIdentifier, originalSub, "pre-assume sub mismatch");

    // Assume role path
    List<JwtOption> assumeOpts = new ArrayList<>(opts);
    assumeOpts.add(Options.withAssumeRole(role));
    if (sessionName != null && !sessionName.isEmpty())
      assumeOpts.add(Options.withAssumeRoleSessionName(sessionName));
    String assumedJwt = S2IAM.getDatabaseJWT("test-workspace",
        assumeOpts.toArray(new JwtOption[0]));
    String assumedSub = decodeSub(assumedJwt);
    JsonNode assumedReq = fetchLastRequest();
    String assumedIdentifier = assumedReq.path("identity").path("identifier").asText();

    assertNotEquals(originalIdentifier, assumedIdentifier,
        "identity should change when assuming role");
    assertEquals(assumedIdentifier, assumedSub, "assumed JWT sub mismatch");
    String roleNameFragment = role.contains("/") ? role.substring(role.lastIndexOf('/') + 1) : role;
    assertTrue(assumedIdentifier.contains(roleNameFragment),
        "assumed identifier should contain role fragment");
    if (role.startsWith("arn:aws:iam:")) {
      // With the default preference the identity is the raw STS assumed-role ARN
      // (session-bearing), byte-identical to historical behavior.
      assertTrue(assumedIdentifier.startsWith("arn:aws:sts::"),
          "default AWS identity should be the raw STS assumed-role ARN, got " + assumedIdentifier);
      assertTrue(assumedIdentifier.contains(":assumed-role/" + roleNameFragment + "/"),
          "default AWS identity should be an assumed-role ARN for the role, got "
              + assumedIdentifier);
      assertEquals(IdentityFormat.AWS_ARN,
          assumedReq.path("identity").path("identityFormat").asText(),
          "default AWS identity format should be aws-arn");

      // Content negotiation: opt into the new AWS ordering and confirm the issued
      // identity collapses to the base IAM role ARN (session stripped).
      List<JwtOption> negotiatedOpts = new ArrayList<>(assumeOpts);
      negotiatedOpts.add(Options.withIdentityFormatPreference("aws-iam-role-arn", "aws-arn"));
      String negotiatedJwt = S2IAM.getDatabaseJWT("test-workspace",
          negotiatedOpts.toArray(new JwtOption[0]));
      String negotiatedSub = decodeSub(negotiatedJwt);
      JsonNode negotiatedReq = fetchLastRequest();
      // The base IAM role ARN is path-less: the STS assumed-role ARN omits any IAM
      // path, so derive the expected value from the role prefix and the role name
      // fragment rather than the (possibly path-bearing) input ARN. For a root-path
      // role this equals `role` exactly; the session name must not affect it.
      String expectedBaseRoleArn = role.substring(0, role.indexOf(":role/") + ":role/".length())
          + roleNameFragment;
      assertEquals(expectedBaseRoleArn, negotiatedSub,
          "negotiated AWS identity should be the path-less base IAM role ARN (session must not affect it)");
      assertEquals(IdentityFormat.AWS_IAM_ROLE_ARN,
          negotiatedReq.path("identity").path("identityFormat").asText(),
          "negotiated AWS identity format should be aws-iam-role-arn");
    }
  }

  private static JsonNode fetchLastRequest() throws Exception {
    HttpClient c = HttpClient.newHttpClient();
    HttpResponse<String> resp = c.send(
        HttpRequest.newBuilder(URI.create(server.getBaseURL() + "/info/requests")).GET().build(),
        HttpResponse.BodyHandlers.ofString());
    if (resp.statusCode() != 200)
      return null;
    JsonNode arr = M.readTree(resp.body());
    if (!arr.isArray() || arr.size() == 0)
      return null;
    return arr.get(arr.size() - 1);
  }

  private static String decodeSub(String jwt) throws Exception {
    String[] parts = jwt.split("\\.");
    if (parts.length < 2)
      return null;
    String payload = parts[1];
    int rem = payload.length() % 4;
    if (rem > 0)
      payload += "====".substring(rem);
    byte[] dec = Base64.getUrlDecoder().decode(payload);
    return M.readTree(dec).path("sub").asText();
  }
}
