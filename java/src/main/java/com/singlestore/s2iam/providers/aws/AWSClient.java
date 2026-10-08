package com.singlestore.s2iam.providers.aws;

import com.singlestore.s2iam.*;
import com.singlestore.s2iam.providers.AbstractBaseClient;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.arns.Arn;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

public class AWSClient extends AbstractBaseClient {
  public static final String ROLE_SESSION_NAME_PARAM = "roleSessionName";
  /** Stable default when AssumeRole is used without an explicit session name. */
  public static final String DEFAULT_ROLE_SESSION_NAME = "s2iam-session";

  // AdditionalClaims keys populated for AWS identities (preserved for audit /
  // registration-preview, independent of the negotiated identity format). The
  // values match the Go and Python clients, and are distinct from
  // ROLE_SESSION_NAME_PARAM, which is an additionalParams request key.
  public static final String CLAIM_USER_ID = "UserId";
  public static final String CLAIM_ASSUMED_ROLE_ARN = "AssumedRoleArn";
  public static final String CLAIM_ROLE_SESSION_NAME = "RoleSessionName";

  // Detect order: (1) environment hints (fast), (2) IMDSv2 token endpoint, (3)
  // legacy metadata path.
  // Identity headers always reflect either the base credentials or an assumed
  // role (if provided).
  private static final String METADATA_BASE = System.getenv()
      .getOrDefault("S2IAM_AWS_METADATA_BASE", "http://169.254.169.254");
  private volatile StsClient sts;
  private AwsCredentialsProvider baseProvider;

  public AWSClient(Logger logger) {
    super(logger, null);
  }
  private AWSClient(Logger logger, String assumed) {
    super(logger, assumed);
  }

  @Override
  protected CloudProviderClient newInstance(Logger logger, String assumedRole) {
    return new AWSClient(logger, assumedRole);
  }
  @Override
  public CloudProviderType getType() {
    return CloudProviderType.aws;
  }

  @Override
  public Exception detect() {
    String[] envs = {"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_EXECUTION_ENV",
        "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_LAMBDA_FUNCTION_NAME"};
    for (String e : envs)
      if (System.getenv(e) != null && !System.getenv(e).isEmpty())
        return null;
    HttpClient client = HttpClient.newBuilder().connectTimeout(Timeouts.DETECT).build();
    boolean debug = debugEnabled() && logger != null;
    try {
      HttpRequest tokenReq = HttpRequest.newBuilder(URI.create(METADATA_BASE + "/latest/api/token"))
          .timeout(Timeouts.DETECT).header("X-aws-ec2-metadata-token-ttl-seconds", "60")
          .method("PUT", HttpRequest.BodyPublishers.noBody()).build();
      HttpResponse<String> tokenResp = client.send(tokenReq, HttpResponse.BodyHandlers.ofString());
      if (tokenResp.statusCode() == 200)
        return null;
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
      return ie;
    } catch (Exception ignored) {
      if (debug)
        logger.logf("AWSClient.detect: token endpoint error class=%s msg=%s",
            ignored.getClass().getSimpleName(), ignored.getMessage());
    }
    try {
      HttpRequest req = HttpRequest.newBuilder(URI.create(METADATA_BASE + "/latest/meta-data/"))
          .timeout(Timeouts.DETECT).GET().build();
      HttpResponse<Void> resp = client.send(req, HttpResponse.BodyHandlers.discarding());
      if (resp.statusCode() == 200)
        return null;
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
      return ie;
    } catch (IOException e) {
      if (debug)
        logger.logf("AWSClient.detect: metadata path IO error class=%s msg=%s",
            e.getClass().getSimpleName(), e.getMessage());
      return e;
    }
    return new IllegalStateException("not running on AWS");
  }

  @Override
  public Exception fastDetect() {
    String prop = System.getProperty("s2iam.test.awsFast", "");
    if (!prop.isEmpty())
      return null;
    String[] envs = {"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_EXECUTION_ENV",
        "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_LAMBDA_FUNCTION_NAME"};
    for (String e : envs) {
      String v = System.getenv(e);
      if (v != null && !v.isEmpty())
        return null;
    }
    return new Exception("no aws fast path");
  }

  @Override
  public IdentityHeadersResult getIdentityHeaders(Map<String, String> additionalParams) {
    try {
      ensureSTS();
      GetCallerIdentityResponse who = sts
          .getCallerIdentity(GetCallerIdentityRequest.builder().build());
      AwsCredentials baseCreds = baseProvider.resolveCredentials();
      Map<String, String> headers = new HashMap<>();
      headers.put("X-AWS-Access-Key-ID", baseCreds.accessKeyId());
      if (baseCreds.secretAccessKey() != null)
        headers.put("X-AWS-Secret-Access-Key", baseCreds.secretAccessKey());
      if (baseCreds instanceof AwsSessionCredentials) {
        String token = ((AwsSessionCredentials) baseCreds).sessionToken();
        if (token != null && !token.isEmpty())
          headers.put("X-AWS-Session-Token", token);
      }
      String arn;
      String account;
      String resourceType;
      String region;
      if (assumedRole != null && !assumedRole.isEmpty()) {
        String sessionName = resolveRoleSessionName(additionalParams);
        AssumeRoleResponse assume = sts.assumeRole(AssumeRoleRequest.builder().roleArn(assumedRole)
            .roleSessionName(sessionName).durationSeconds(3600).build());
        headers.put("X-AWS-Access-Key-ID", assume.credentials().accessKeyId());
        headers.put("X-AWS-Secret-Access-Key", assume.credentials().secretAccessKey());
        headers.put("X-AWS-Session-Token", assume.credentials().sessionToken());
        StsClient temp = StsClient.builder().region(sts.serviceClientConfiguration().region())
            .credentialsProvider(
                () -> AwsSessionCredentials.create(assume.credentials().accessKeyId(),
                    assume.credentials().secretAccessKey(), assume.credentials().sessionToken()))
            .build();
        GetCallerIdentityResponse assumedIdentity = temp
            .getCallerIdentity(GetCallerIdentityRequest.builder().build());
        who = assumedIdentity;
        account = assumedIdentity.account();
        arn = assumedIdentity.arn();
        region = deriveRegion(arn);
        resourceType = deriveResourceTypeDetailed(arn);
      } else {
        arn = who.arn();
        account = who.account();
        region = deriveRegion(arn);
        resourceType = deriveResourceTypeDetailed(arn);
        if (!headers.containsKey("X-AWS-Session-Token")
            && System.getenv("AWS_SESSION_TOKEN") != null) {
          headers.put("X-AWS-Session-Token", System.getenv("AWS_SESSION_TOKEN"));
        }
      }
      Map<String, String> extra = new HashMap<>();
      extra.put("account", account);
      String userId = who.userId();
      if (userId != null && !userId.isEmpty())
        extra.put(CLAIM_USER_ID, userId);
      // Build the valid identity-format candidates and default the identifier to the
      // always-valid floor (the raw caller ARN, format aws-arn), byte-identical to
      // the historical behavior. The negotiated format (chosen by the verifier from
      // the preference header) may select an alternate such as the base IAM role
      // ARN; the raw ARN and session name are preserved as claims for audit.
      String[] assumed = parseAssumedRoleArn(arn);
      if (assumed != null) {
        extra.put(CLAIM_ASSUMED_ROLE_ARN, arn);
        if (!assumed[2].isEmpty())
          extra.put(CLAIM_ROLE_SESSION_NAME, assumed[2]);
      }
      List<IdentityFormat.Candidate> candidates = awsCandidates(arn, account, userId);
      IdentityFormat.Candidate floor = candidates.get(0);
      CloudIdentity identity = new CloudIdentity(CloudProviderType.aws, floor.value, account,
          region, resourceType, extra, floor.format, candidates);
      return new IdentityHeadersResult(headers, identity, null);
    } catch (Exception e) {
      return new IdentityHeadersResult(null, null, e);
    }
  }

  static String resolveRoleSessionName(Map<String, String> additionalParams) {
    if (additionalParams != null) {
      String name = additionalParams.get(ROLE_SESSION_NAME_PARAM);
      if (name != null && !name.isEmpty())
        return name;
    }
    return DEFAULT_ROLE_SESSION_NAME;
  }

  /**
   * Returns the identity formats valid for the attested GetCallerIdentity result,
   * in natural order with the always-valid floor (the raw caller ARN) first:
   *
   * <ul>
   * <li>aws-arn (floor, always): the raw caller ARN.
   * <li>aws-iam-role-arn (assumed-role only): the base IAM role ARN.
   * <li>aws-role-id (assumed-role only): the immutable RoleId (AROA...), the
   * prefix of the STS UserId.
   * </ul>
   *
   * This must stay identical to the Go verifier so the client-computed identity
   * matches the issued JWT sub.
   */
  static List<IdentityFormat.Candidate> awsCandidates(String arn, String account, String userId) {
    List<IdentityFormat.Candidate> candidates = new ArrayList<>();
    candidates.add(new IdentityFormat.Candidate(IdentityFormat.AWS_ARN, arn));
    String[] assumed = parseAssumedRoleArn(arn);
    if (assumed != null) {
      // Preserve the source partition (aws, aws-us-gov, aws-cn); the STS
      // assumed-role ARN omits the IAM path, so this is the path-less canonical
      // form arn:PARTITION:iam::ACCOUNT:role/ROLE.
      candidates.add(new IdentityFormat.Candidate(IdentityFormat.AWS_IAM_ROLE_ARN,
          String.format("arn:%s:iam::%s:role/%s", assumed[0], account, assumed[1])));
      String roleId = roleIdFromUserId(userId);
      if (!roleId.isEmpty())
        candidates.add(new IdentityFormat.Candidate(IdentityFormat.AWS_ROLE_ID, roleId));
    }
    return candidates;
  }

  /**
   * Returns the immutable RoleId portion of an STS UserId (the segment before the
   * ':'; UserId is "AROA...:session" for assumed roles), or "" if absent.
   */
  static String roleIdFromUserId(String userId) {
    if (userId == null)
      return "";
    int i = userId.indexOf(':');
    return i >= 0 ? userId.substring(0, i) : "";
  }

  /** Parse an ARN with the AWS SDK, or null if the string is not a valid ARN. */
  private static Arn parseArn(String arn) {
    if (arn == null)
      return null;
    try {
      return Arn.fromString(arn);
    } catch (RuntimeException e) {
      return null;
    }
  }

  /**
   * Returns {partition, roleName, sessionName} for an STS assumed-role ARN
   * (arn:PARTITION:sts::ACCOUNT:assumed-role/ROLE/SESSION), or null for any other
   * ARN shape. The resource sub-structure is not modeled by the SDK's Arn type,
   * so it is split here; neither ROLE nor SESSION may contain '/'. ROLE must be
   * non-empty; SESSION may be empty (returned as "").
   */
  static String[] parseAssumedRoleArn(String arn) {
    Arn parsed = parseArn(arn);
    if (parsed == null || !"sts".equals(parsed.service()))
      return null;
    String[] seg = parsed.resourceAsString().split("/", 3);
    if (seg.length < 2 || !"assumed-role".equals(seg[0]) || seg[1].isEmpty())
      return null;
    String session = seg.length == 3 ? seg[2] : "";
    return new String[]{parsed.partition(), seg[1], session};
  }

  private void ensureSTS() {
    if (sts != null)
      return;
    synchronized (this) {
      if (sts == null) {
        String region = System.getenv().getOrDefault("AWS_REGION",
            System.getenv().getOrDefault("AWS_DEFAULT_REGION", "us-east-1"));
        baseProvider = DefaultCredentialsProvider.create();
        sts = StsClient.builder().region(Region.of(region)).credentialsProvider(baseProvider)
            .build();
      }
    }
  }
  private static String deriveRegion(String arn) {
    Arn parsed = parseArn(arn);
    return parsed != null ? parsed.region().orElse("") : "";
  }
  private static String deriveResourceTypeDetailed(String arn) {
    if (arn.contains(":instance/"))
      return "ec2";
    if (arn.contains(":assumed-role/"))
      return "assumed-role";
    if (arn.contains(":role/"))
      return "role";
    if (arn.contains(":user/"))
      return "user";
    if (arn.contains(":lambda:"))
      return "lambda";
    if (arn.contains(":task/"))
      return "ecs-task";
    if (arn.contains(":cluster/"))
      return "ecs-cluster";
    if (arn.contains(":function:"))
      return "lambda";
    if (arn.contains(":iam::"))
      return "iam";
    return "aws";
  }
}
