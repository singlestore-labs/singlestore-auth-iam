package com.singlestore.s2iam;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import com.singlestore.s2iam.options.JwtOption;
import com.singlestore.s2iam.options.Options;
import com.singlestore.s2iam.options.ServerUrlOption;
import java.net.URI;
import java.net.http.*;
import java.util.*;
import java.util.Base64;
import java.util.regex.Pattern;
import org.junit.jupiter.api.*;

/**
 * Parity: provider-specific identity shape assertions (mirrors logic embedded in Go happy path
 * test).
 */
public class S2IAMIdentityShapeTest {
  static GoTestServer server;
  static final ObjectMapper M = new ObjectMapper();

  @BeforeAll
  static void start() throws Exception {
    server = new GoTestServer(java.nio.file.Path.of(".").toAbsolutePath());
    server.start();
  }

  @AfterAll
  static void stop() {
    if (server != null) server.stop();
  }

  @Test
  void identityShape() throws Exception {
    CloudProviderClient provider;
    try {
      provider = S2IAM.detectProvider();
    } catch (NoCloudProviderDetectedException e) {
      Assumptions.abort("no cloud provider");
      return;
    }

    List<JwtOption> opts = new ArrayList<>();
    opts.add(ServerUrlOption.of(server.getBaseURL() + "/auth/iam/:jwtType"));
    if (provider.getType() == CloudProviderType.gcp)
      opts.add(Options.withGcpAudience("https://authsvc.singlestore.com"));
    String jwt = S2IAM.getDatabaseJWT("test-workspace", opts.toArray(new JwtOption[0]));
    assertNotNull(jwt);
    String sub = decodeSub(jwt);
    JsonNode req = fetchLastRequest();
    JsonNode id = req.path("identity");
    String identifier = id.path("identifier").asText();
    assertEquals(identifier, sub, "sub must equal identifier");

    switch (provider.getType()) {
      case aws:
        assertTrue(identifier.startsWith("arn:aws:"), "AWS identifier should be ARN");
        String accountID = id.path("accountID").asText();
        assertTrue(accountID.matches("[0-9]{12}"), "AWS accountID should be 12 digits");
        break;
      case gcp:
        assertTrue(
            Pattern.compile("^[A-Za-z0-9_-]+@[A-Za-z0-9_-]+\\.iam\\.gserviceaccount\\.com$")
                .matcher(identifier)
                .find(),
            "GCP identifier should be service account email");
        String accountIDG = id.path("accountID").asText();
        assertTrue(accountIDG.matches("[0-9]{10,}"), "GCP accountID numeric");
        break;
      case azure:
        String subscription = id.path("accountID").asText();
        assertTrue(subscription.matches("[0-9a-fA-F-]{36}"), "Azure subscription ID format");
        break;
      default:
        fail("Unknown provider type");
    }
  }

  private static JsonNode fetchLastRequest() throws Exception {
    HttpClient c = HttpClient.newHttpClient();
    HttpResponse<String> resp =
        c.send(
            HttpRequest.newBuilder(URI.create(server.getBaseURL() + "/info/requests"))
                .GET()
                .build(),
            HttpResponse.BodyHandlers.ofString());
    if (resp.statusCode() != 200) return null;
    JsonNode arr = M.readTree(resp.body());
    if (!arr.isArray() || arr.size() == 0) return null;
    return arr.get(arr.size() - 1);
  }

  private static String decodeSub(String jwt) throws Exception {
    String[] p = jwt.split("\\.");
    if (p.length < 2) return null;
    String pay = p[1];
    int r = pay.length() % 4;
    if (r > 0) pay += "====".substring(r);
    return M.readTree(Base64.getUrlDecoder().decode(pay)).path("sub").asText();
  }
}
