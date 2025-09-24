package com.singlestore.s2iam.providers;

import com.singlestore.s2iam.*;

public class GCPClient extends AbstractBaseClient {
    public GCPClient(Logger logger) { super(logger, null); }
    private GCPClient(Logger logger, String assumed) { super(logger, assumed); }

    @Override
    protected CloudProviderClient newInstance(Logger logger, String assumedRole) { return new GCPClient(logger, assumedRole); }

    @Override
    public CloudProviderType getType() { return CloudProviderType.gcp; }

    @Override
    public Exception detect() {
        return new IllegalStateException("no cloud provider detected (gcp stub)");
    }
}
