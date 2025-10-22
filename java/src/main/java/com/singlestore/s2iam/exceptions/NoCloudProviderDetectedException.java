package com.singlestore.s2iam.exceptions;

import java.util.List;
import com.singlestore.s2iam.S2IAM.DetectAttemptStatus;

public class NoCloudProviderDetectedException extends S2IAMException {
  private final List<DetectAttemptStatus> attemptStatuses; // immutable snapshot

  public NoCloudProviderDetectedException(String msg) {
    super(msg);
    this.attemptStatuses = List.of();
  }

  public NoCloudProviderDetectedException(String msg, Throwable cause) {
    super(msg, cause);
    this.attemptStatuses = List.of();
  }

  public NoCloudProviderDetectedException(String msg, List<DetectAttemptStatus> attempts) {
    super(msg);
    this.attemptStatuses = attempts == null ? List.of() : List.copyOf(attempts);
  }

  public List<DetectAttemptStatus> getAttemptStatuses() {
    return attemptStatuses;
  }
}
