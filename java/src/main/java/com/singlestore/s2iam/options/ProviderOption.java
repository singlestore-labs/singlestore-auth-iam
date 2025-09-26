package com.singlestore.s2iam.options;

import com.singlestore.s2iam.CloudProviderClient;
import com.singlestore.s2iam.Logger;
import java.time.Duration;
import java.util.List;

public interface ProviderOption {
  void apply(ProviderOptions o);

  static ProviderOption withLogger(Logger logger) {
    return o -> o.logger = logger;
  }

  static ProviderOption withClients(List<CloudProviderClient> clients) {
    return o -> o.clients = clients;
  }

  static ProviderOption withTimeout(Duration timeout) {
    return o -> o.timeout = timeout;
  }
}
