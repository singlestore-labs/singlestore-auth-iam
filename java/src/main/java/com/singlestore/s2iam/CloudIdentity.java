package com.singlestore.s2iam;

import java.util.Map;

public class CloudIdentity {
  private final CloudProviderType provider;
  private final String identifier;
  private final String accountId;
  private final String region;
  private final String resourceType;
  private final Map<String, String> additionalClaims;

  public CloudIdentity(CloudProviderType provider, String identifier, String accountId,
      String region, String resourceType, Map<String, String> additionalClaims) {
    this.provider = provider;
    this.identifier = identifier;
    this.accountId = accountId;
    this.region = region;
    this.resourceType = resourceType;
    this.additionalClaims = additionalClaims;
  }

  public CloudProviderType getProvider() {
    return provider;
  }

  public String getIdentifier() {
    return identifier;
  }

  public String getAccountId() {
    return accountId;
  }

  public String getRegion() {
    return region;
  }

  public String getResourceType() {
    return resourceType;
  }

  public Map<String, String> getAdditionalClaims() {
    return additionalClaims;
  }
}
