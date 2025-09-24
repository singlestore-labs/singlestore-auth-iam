package com.singlestore.s2iam.options;

import com.singlestore.s2iam.CloudProviderClient;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

public class JwtOptions extends ProviderOptions {
    public enum JWTType { database, api }
    public JWTType jwtType;
    public String workspaceGroupId;
    public String serverUrl;
    public CloudProviderClient provider;
    public Map<String,String> additionalParams = new HashMap<>();
    public String assumeRoleIdentifier;
}
