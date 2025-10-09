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

  // Metadata detection (allow slower clouds / transient slowness)
  public static final Duration DETECT = Duration.ofSeconds(5);

  // Identity / token retrieval baseline (metadata tokens, STS, MI, etc.)
  public static final Duration IDENTITY = Duration.ofSeconds(10);

  // Secondary / follow-up metadata probes (instance details, subscription, etc.)
  public static final Duration SECONDARY = Duration.ofSeconds(5);

  // Extended identity operations (future impersonation / long STS chains)
  public static final Duration IDENTITY_EXTENDED = Duration.ofSeconds(15);
}
