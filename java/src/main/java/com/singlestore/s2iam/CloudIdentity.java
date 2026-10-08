package com.singlestore.s2iam;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class CloudIdentity {
  private final CloudProviderType provider;
  private final String identifier;
  private final String accountId;
  private final String region;
  private final String resourceType;
  private final Map<String, String> additionalClaims;
  // The format token that produced identifier (e.g. "aws-arn" or
  // "aws-iam-role-arn"). On a client-built identity this is the locally computed
  // default (the floor), not the format the verifier negotiated: the negotiated
  // token is reported by the auth service in the response identityFormat field.
  private final String identityFormat;
  // The ordered list of (format, value) pairs valid for this identity (floor
  // first), so a caller can see which representations exist and re-derive the
  // value the verifier would negotiate for a given preference.
  private final List<IdentityFormat.Candidate> candidates;

  public CloudIdentity(CloudProviderType provider, String identifier, String accountId,
      String region, String resourceType, Map<String, String> additionalClaims) {
    this(provider, identifier, accountId, region, resourceType, additionalClaims, "",
        Collections.emptyList());
  }

  public CloudIdentity(CloudProviderType provider, String identifier, String accountId,
      String region, String resourceType, Map<String, String> additionalClaims,
      String identityFormat, List<IdentityFormat.Candidate> candidates) {
    this.provider = provider;
    this.identifier = identifier;
    this.accountId = accountId;
    this.region = region;
    this.resourceType = resourceType;
    this.additionalClaims = additionalClaims;
    this.identityFormat = identityFormat;
    this.candidates = candidates == null ? Collections.emptyList() : candidates;
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

  public String getIdentityFormat() {
    return identityFormat;
  }

  public List<IdentityFormat.Candidate> getCandidates() {
    return candidates;
  }
}
