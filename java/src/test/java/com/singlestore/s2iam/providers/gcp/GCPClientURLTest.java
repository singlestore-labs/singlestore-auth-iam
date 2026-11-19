package com.singlestore.s2iam.providers.gcp;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/** Impersonation URL shape shared with the Go and Python clients. */
public class GCPClientURLTest {
  @Test
  void emailIsOnePathSegment() {
    String email = "service-account@project-id.iam.gserviceaccount.com";
    assertEquals("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + email
        + ":generateIdToken", GCPClient.impersonationURL(email));
  }

  @Test
  void slashCannotAddASegment() {
    String url = GCPClient.impersonationURL("evil/other:generateAccessToken");
    assertFalse(url.contains("/evil/other"));
    assertTrue(url.contains("evil%2Fother:generateAccessToken"));
  }
}
