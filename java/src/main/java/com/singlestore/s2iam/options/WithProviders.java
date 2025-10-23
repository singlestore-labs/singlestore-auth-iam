package com.singlestore.s2iam.options;

import com.singlestore.s2iam.CloudProviderClient;
import java.util.Arrays;
import java.util.List;

public class WithProviders implements ProviderOption {
  private final List<CloudProviderClient> clients;

  public WithProviders(CloudProviderClient... c) {
    this.clients = Arrays.asList(c);
  }

  @Override
  public void apply(ProviderOptions o) {
    o.clients = clients;
  }

  public static WithProviders of(CloudProviderClient... c) {
    return new WithProviders(c);
  }
}
