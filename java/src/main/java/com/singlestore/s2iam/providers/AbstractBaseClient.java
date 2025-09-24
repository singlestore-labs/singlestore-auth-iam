package com.singlestore.s2iam.providers;

import com.singlestore.s2iam.*;

import java.util.Collections;
import java.util.Map;

/** Base client with default unsupported identity header retrieval. */
abstract class AbstractBaseClient implements CloudProviderClient {
    protected final Logger logger;
    protected final String assumedRole;

    protected AbstractBaseClient(Logger logger, String assumedRole) {
        this.logger = logger;
        this.assumedRole = assumedRole;
    }

    @Override
    public CloudProviderClient assumeRole(String roleIdentifier) {
        return newInstance(logger, roleIdentifier);
    }

    protected abstract CloudProviderClient newInstance(Logger logger, String assumedRole);

    @Override
    public IdentityHeadersResult getIdentityHeaders(Map<String, String> additionalParams) {
        return new IdentityHeadersResult(null, null, new IllegalStateException("identity retrieval not implemented"));
    }

    @Override
    public Exception fastDetect() { return new IllegalStateException("not detected"); }
}
