package com.singlestore.s2iam.options;

public class ServerUrlOption implements JwtOption {
  private final String url;

  public ServerUrlOption(String url) {
    this.url = url;
  }

  @Override
  public void apply(JwtOptions o) {
    o.serverUrl = url;
  }

  public static ServerUrlOption of(String url) {
    return new ServerUrlOption(url);
  }
}
