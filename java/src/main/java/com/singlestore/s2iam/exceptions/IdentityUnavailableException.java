package com.singlestore.s2iam.exceptions;

/**
 * Indicates the cloud provider was detected but an identity token / credentials
 * were not available (e.g., no role attached).
 */
public class IdentityUnavailableException extends Exception {
  public IdentityUnavailableException(String message) {
    super(message);
  }
  public IdentityUnavailableException(String message, Throwable cause) {
    super(message, cause);
  }
}
