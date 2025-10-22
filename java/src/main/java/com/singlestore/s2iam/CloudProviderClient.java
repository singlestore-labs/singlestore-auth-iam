package com.singlestore.s2iam;

import java.util.Map;

public interface CloudProviderClient {
  Exception detect(); // Full detection (may perform network); returns null on success or exception.

  Exception fastDetect(); // Fast in-process detection only; returns null if detected; else an
                          // exception.

  CloudProviderType getType(); // Provider type.

  CloudProviderClient assumeRole(String roleIdentifier); // Returns new client with assumed role.

  IdentityHeadersResult getIdentityHeaders(Map<String, String> additionalParams);

  class IdentityHeadersResult {
    public final Map<String, String> headers;
    public final CloudIdentity identity;
    public final Exception error;

    public IdentityHeadersResult(Map<String, String> headers, CloudIdentity identity,
        Exception error) {
      this.headers = headers;
      this.identity = identity;
      this.error = error;
    }
  }
}
