package com.singlestore.s2iam;

import java.util.Map;

/**
 * Local mock provider used only for Java integration tests with Go server when
 * no cloud metadata present.
 */
class LocalMockProvider implements CloudProviderClient {
  @Override
  public Exception detect() {
    return null;
  }

  @Override
  public Exception fastDetect() {
    return null;
  }

  @Override
  public CloudProviderType getType() {
    return CloudProviderType.aws;
  }

  @Override
  public CloudProviderClient assumeRole(String roleIdentifier) {
    return this;
  }

  @Override
  public IdentityHeadersResult getIdentityHeaders(Map<String, String> additionalParams) {
    // Provide minimal headers that Go verifier will accept for AWS path: access key
    // + secret.
    Map<String, String> h = Map.of("X-AWS-Access-Key-ID", "TESTACCESSKEY",
        "X-AWS-Secret-Access-Key", "TESTSECRET");
    CloudIdentity id = new CloudIdentity(CloudProviderType.aws,
        "arn:aws:iam::000000000000:user/Test", "000000000000", "us-east-1", "iam-user", Map.of());
    return new IdentityHeadersResult(h, id, null);
  }
}
