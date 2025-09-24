package com.singlestore.s2iam.providers;

import com.singlestore.s2iam.*;

public class AzureClient extends AbstractBaseClient {
    public AzureClient(Logger logger) { super(logger, null); }
    private AzureClient(Logger logger, String assumed) { super(logger, assumed); }

    @Override
    protected CloudProviderClient newInstance(Logger logger, String assumedRole) { return new AzureClient(logger, assumedRole); }

    @Override
    public CloudProviderType getType() { return CloudProviderType.azure; }

    @Override
    public Exception detect() {
        return new IllegalStateException("no cloud provider detected (azure stub)");
    }
}
