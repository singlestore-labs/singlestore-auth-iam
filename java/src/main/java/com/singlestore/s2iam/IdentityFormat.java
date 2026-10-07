package com.singlestore.s2iam;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Shared identity-format vocabulary and content-negotiation logic.
 *
 * <p>
 * Clients send an ordered preference list of these tokens and the verifier
 * chooses the first one that is both server-supported and valid for the
 * attested identity. Tokens are stable forever and unknown/removed tokens are
 * ignored, so the vocabulary is forward- and backward-compatible across
 * client/server versions. This mirrors the Go reference
 * (go/s2iam/models/identity_format.go).
 */
public final class IdentityFormat {
  private IdentityFormat() {
  }

  // AWS: raw caller ARN (always valid; current AWS default). Session-bearing for
  // assumed-role sessions, so only pre-configurable when the session name is
  // stable
  // (e.g. the library-driven AssumeRole); otherwise prefer aws-iam-role-arn.
  public static final String AWS_ARN = "aws-arn";
  // AWS: base IAM role ARN (assumed-role sessions only).
  public static final String AWS_IAM_ROLE_ARN = "aws-iam-role-arn";
  // AWS: immutable RoleId (AROA...), the prefix of the STS UserId (assumed-role
  // only).
  public static final String AWS_ROLE_ID = "aws-role-id";
  // GCP: service-account email (verified email only); GCP default (first).
  public static final String GCP_SA_EMAIL = "gcp-sa-email";
  // GCP: numeric subject (sub), immutable; always valid; GCP default (floor).
  public static final String GCP_SA_UNIQUE_ID = "gcp-sa-unique-id";
  // Azure: oid principal GUID; Azure default and floor (keeps oid-else-sub
  // internally).
  public static final String AZURE_OBJECT_ID = "azure-object-id";
  // Azure: xms_mirid managed-identity ARM resource path (user-assigned MI only).
  public static final String AZURE_RESOURCE_ID = "azure-resource-id";

  /**
   * Request header carrying the client's ordered, comma-separated identity-format
   * preference. It is the normative wire contract for protocol-only clients.
   */
  public static final String PREFERENCE_HEADER = "X-S2IAM-Identity-Format-Preference";

  /**
   * Environment variable the client reads to populate the preference header when
   * no explicit option is given.
   */
  public static final String PREFERENCE_ENV = "S2IAM_IDENTITY_FORMAT_PREFERENCE";

  private static final Map<String, CloudProviderType> FORMAT_PROVIDER = new LinkedHashMap<>();
  private static final Map<CloudProviderType, List<String>> DEFAULT_ORDER = new LinkedHashMap<>();

  static {
    FORMAT_PROVIDER.put(AWS_ARN, CloudProviderType.aws);
    FORMAT_PROVIDER.put(AWS_IAM_ROLE_ARN, CloudProviderType.aws);
    FORMAT_PROVIDER.put(AWS_ROLE_ID, CloudProviderType.aws);
    FORMAT_PROVIDER.put(GCP_SA_EMAIL, CloudProviderType.gcp);
    FORMAT_PROVIDER.put(GCP_SA_UNIQUE_ID, CloudProviderType.gcp);
    FORMAT_PROVIDER.put(AZURE_OBJECT_ID, CloudProviderType.azure);
    FORMAT_PROVIDER.put(AZURE_RESOURCE_ID, CloudProviderType.azure);

    DEFAULT_ORDER.put(CloudProviderType.aws, List.of(AWS_ARN));
    DEFAULT_ORDER.put(CloudProviderType.gcp, List.of(GCP_SA_EMAIL, GCP_SA_UNIQUE_ID));
    DEFAULT_ORDER.put(CloudProviderType.azure, List.of(AZURE_OBJECT_ID));
  }

  /** A (format, value) pair that is valid for a verified identity. */
  public static final class Candidate {
    public final String format;
    public final String value;

    public Candidate(String format, String value) {
      this.format = format;
      this.value = value;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o)
        return true;
      if (!(o instanceof Candidate))
        return false;
      Candidate c = (Candidate) o;
      return format.equals(c.format) && value.equals(c.value);
    }

    @Override
    public int hashCode() {
      return format.hashCode() * 31 + value.hashCode();
    }

    @Override
    public String toString() {
      return "Candidate{" + format + "=" + value + "}";
    }
  }

  /** Returns the provider a format token belongs to, or null if unknown. */
  public static CloudProviderType provider(String format) {
    return FORMAT_PROVIDER.get(format);
  }

  /**
   * Returns the built-in default ordering for a provider (byte-identical to the
   * historical behavior); empty for an unknown provider.
   */
  public static List<String> defaultOrder(CloudProviderType provider) {
    return DEFAULT_ORDER.getOrDefault(provider, List.of());
  }

  /**
   * Parses a comma-separated preference list: values are trimmed and empty
   * entries dropped. Unknown tokens are preserved verbatim (ignored later during
   * negotiation).
   */
  public static List<String> parsePreference(String value) {
    if (value == null || value.isEmpty())
      return new ArrayList<>();
    return Arrays.stream(value.split(",")).map(String::trim).filter(t -> !t.isEmpty())
        .collect(Collectors.toList());
  }

  /**
   * Deterministically chooses the single identity format (and JWT sub).
   *
   * <p>
   * {@code valid} is the verifier-derived, ordered list of candidate formats
   * valid for this identity (floor first; must be non-empty). {@code clientPref}
   * is the client's requested ordering (may span providers and include unknown
   * tokens). {@code serverDefault} is the configured default ordering for this
   * provider.
   *
   * <p>
   * Algorithm: candidate order = clientPref filtered to this provider (unknown
   * and other-provider tokens dropped), else serverDefault; choose the first
   * candidate that is server-supported AND valid; fail closed to serverDefault,
   * then to the floor ({@code valid.get(0)}), which is always valid.
   */
  public static Candidate select(CloudProviderType provider, List<Candidate> valid,
      List<String> clientPref, List<String> serverDefault) {
    Map<String, String> validByFormat = new LinkedHashMap<>();
    for (Candidate c : valid)
      validByFormat.put(c.format, c.value);

    // candidate order = clientPref filtered to this provider, then the server
    // default appended as the fail-closed fallback; the first server-supported,
    // valid token wins, else the floor (valid.get(0), always valid).
    List<String> candidateOrder = new ArrayList<>();
    if (clientPref != null) {
      for (String f : clientPref)
        if (provider.equals(provider(f)))
          candidateOrder.add(f);
    }
    if (serverDefault != null)
      candidateOrder.addAll(serverDefault);

    for (String f : candidateOrder) {
      String v = validByFormat.get(f);
      if (v != null)
        return new Candidate(f, v);
    }
    return valid.get(0);
  }

  /** Convenience overload accepting a varargs client preference. */
  public static Candidate select(CloudProviderType provider, List<Candidate> valid,
      List<String> serverDefault, String... clientPref) {
    return select(provider, valid, Arrays.asList(clientPref), serverDefault);
  }
}
