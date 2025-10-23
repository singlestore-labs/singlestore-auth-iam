package com.singlestore.s2iam;

import com.singlestore.s2iam.options.ProviderOptions;

/**
 * Internal thread-local context allowing builder to pass provider options (e.g.
 * timeout) without widening public method signatures broadly. This is
 * intentionally minimal and not part of the public documented API.
 */
final class ProviderContext {
  private static final ThreadLocal<ProviderOptions> CURRENT = new ThreadLocal<>();
  static void set(ProviderOptions po) {
    CURRENT.set(po);
  }
  static ProviderOptions get() {
    return CURRENT.get();
  }
  static void clear() {
    CURRENT.remove();
  }
  private ProviderContext() {
  }
}
