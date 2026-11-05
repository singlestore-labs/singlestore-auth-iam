package com.singlestore.s2iam.providers.azure;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/** IMDS URL shape shared with the Go client. */
public class AzureClientURLTest {
  @Test
  void systemAssignedOmitsClientId() {
    String url = AzureClient.imdsTokenURL("https://management.azure.com/", null);
    assertFalse(url.contains("client_id="));
    assertTrue(url.contains("resource=https://management.azure.com/"));
  }

  @Test
  void clientIdIsQueryEscaped() {
    String id = "12345678-1234-1234-1234-123456789012";
    assertTrue(
        AzureClient.imdsTokenURL("https://management.azure.com/", id).endsWith("&client_id=" + id));

    String injected = AzureClient.imdsTokenURL("https://management.azure.com/",
        "abc&resource=https://evil.example/");
    assertFalse(injected.contains("&resource=https://evil.example/"));
    assertTrue(injected.contains("client_id=abc%26resource%3Dhttps%3A%2F%2Fevil.example%2F"));
  }
}
