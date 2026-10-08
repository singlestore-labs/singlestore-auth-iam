package com.singlestore.s2iam.options;

import com.singlestore.s2iam.CloudProviderClient;
import java.util.HashMap;
import java.util.Map;

public class JwtOptions extends ProviderOptions {
  public enum JWTType {
    database, api
  }

  public JWTType jwtType;
  public String workspaceGroupId;
  public String serverUrl;
  public boolean allowHttp;
  public CloudProviderClient provider;
  public Map<String, String> additionalParams = new HashMap<>();
  public String assumeRoleIdentifier;
  public String assumeRoleSessionName;
  // Ordered identity-format preference sent via the preference header. When
  // identityFormatPreferenceSet is false the client falls back to the
  // S2IAM_IDENTITY_FORMAT_PREFERENCE env var, then the built-in default.
  public java.util.List<String> identityFormatPreference;
  public boolean identityFormatPreferenceSet;
}
