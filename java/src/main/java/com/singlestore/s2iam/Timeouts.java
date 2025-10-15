package com.singlestore.s2iam;

import java.time.Duration;

/**
 * Centralized timeout constants to keep provider client behavior consistent and
 * enable quick tuning. Values chosen to keep overall test runtime low while
 * allowing a modest network RTT on real cloud VMs.
 */
public final class Timeouts {
  private Timeouts() {
  }

  // Metadata detection timeout.
  // Central tuning point used by S2IAM.detectProvider (unless caller supplies ProviderOption timeout).
  // Raised to 10s for cross-language parity (Python orchestrator global timeout) while still canceling
  // immediately upon first success. Real provider metadata responses normally arrive in <100ms, so the
  // extended window should not be reached in healthy environments.
  public static final Duration DETECT = Duration.ofSeconds(10);

  // Identity / token retrieval baseline (metadata tokens, STS, MI, etc.)
  public static final Duration IDENTITY = Duration.ofSeconds(10);

  // Secondary / follow-up metadata probes (instance details, subscription, etc.)
  public static final Duration SECONDARY = Duration.ofSeconds(5);

  // Extended identity operations (future impersonation / long STS chains)
  public static final Duration IDENTITY_EXTENDED = Duration.ofSeconds(15);
}
