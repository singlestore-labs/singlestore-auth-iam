package com.singlestore.s2iam;

import com.singlestore.s2iam.exceptions.NoCloudProviderDetectedException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;

import static org.junit.jupiter.api.Assertions.*;

public class S2IAMDetectionTest {

    @Test
    void testDetectionSkipOrFail() {
        String expectProvider = System.getenv("S2IAM_TEST_CLOUD_PROVIDER");
        if (expectProvider == null) expectProvider = System.getenv("S2IAM_TEST_ASSUME_ROLE");
        if (expectProvider == null) expectProvider = System.getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE");
        try {
            CloudProviderClient client = S2IAM.detectProvider();
            assertNotNull(client, "provider should not be null when detected");
            if (expectProvider != null) {
                assertEquals(expectProvider, client.getType().name(), "detected provider mismatch");
            }
        } catch (NoCloudProviderDetectedException e) {
            if (expectProvider != null) {
                fail("Cloud provider detection failed - expected to detect provider in test environment");
            }
            Assumptions.abort("No cloud provider detected - not running in cloud environment");
        }
    }
}
