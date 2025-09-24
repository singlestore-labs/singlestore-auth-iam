package com.singlestore.s2iam.exceptions;

public class NoCloudProviderDetectedException extends S2IAMException {
  public NoCloudProviderDetectedException(String msg) {
    super(msg);
  }

  public NoCloudProviderDetectedException(String msg, Throwable cause) {
    super(msg, cause);
  }
}
