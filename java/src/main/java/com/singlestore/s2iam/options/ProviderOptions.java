package com.singlestore.s2iam.options;

import com.singlestore.s2iam.CloudProviderClient;
import com.singlestore.s2iam.Logger;
import java.time.Duration;
import java.util.List;

public class ProviderOptions {
  public Logger logger;
  public List<CloudProviderClient> clients;
  public Duration timeout = Duration.ofSeconds(5);
}
