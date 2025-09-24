package com.singlestore.s2iam.providers;

import com.singlestore.s2iam.*;

public class AWSClient extends AbstractBaseClient {
    public AWSClient(Logger logger) { super(logger, null); }
    private AWSClient(Logger logger, String assumed) { super(logger, assumed); }

    @Override
    protected CloudProviderClient newInstance(Logger logger, String assumedRole) { return new AWSClient(logger, assumedRole); }

    @Override
    public CloudProviderType getType() { return CloudProviderType.aws; }

    @Override
    public Exception detect() {
        // TODO: implement real AWS metadata probing
        return new IllegalStateException("no cloud provider detected (aws stub)" );
    }
}
