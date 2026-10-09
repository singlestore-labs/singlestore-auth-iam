package com.singlestore.s2iam;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Shared identity-format vocabulary and preference parsing.
 *
 * <p>
 * Clients send an ordered preference list of these tokens and the server-side
 * verifier chooses the first one that is both server-supported and valid for
 * the attested identity. Tokens are stable forever and unknown/removed tokens
 * are ignored, so the vocabulary is forward- and backward-compatible across
 * client/server versions.
 *
 * <p>
 * The negotiation algorithm itself lives only in the Go verifier
 * (go/s2iam/models/identity_format.go, {@code SelectIdentityFormat}); this
 * client library just names the vocabulary and parses the preference list.
 * End-to-end negotiation behavior is covered by integration tests that exercise
 * a real Go server.
 */
public final class IdentityFormat {
  private IdentityFormat() {
  }

  // AWS: raw caller ARN (always valid; the AWS floor and the form issued when a
  // request carries no preference). Session-bearing for assumed-role sessions, so
  // only pre-configurable when the session name is stable
  // (e.g. the library-driven AssumeRole); otherwise prefer aws-iam-role-arn.
  public static final String AWS_ARN = "aws-arn";
  // AWS: base IAM role ARN (assumed-role sessions only); requested first by the
  // client as of v0.6.0.
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

  /**
   * Parses a comma-separated preference list: values are trimmed and empty
   * entries dropped. Unknown tokens are preserved verbatim (ignored later during
   * negotiation by the server).
   */
  public static List<String> parsePreference(String value) {
    if (value == null || value.isEmpty())
      return new ArrayList<>();
    return Arrays.stream(value.split(",")).map(String::trim).filter(t -> !t.isEmpty())
        .collect(Collectors.toList());
  }
}
