package com.singlestore.s2iam.providers.aws;

import com.singlestore.s2iam.*;
import com.singlestore.s2iam.providers.AbstractBaseClient;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
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
        AssumeRoleResponse assume = sts.assumeRole(AssumeRoleRequest.builder().roleArn(assumedRole)
            .roleSessionName("SingleStoreAuth-" + (System.currentTimeMillis() / 1000L))
            .durationSeconds(3600).build());
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
        account = assumedIdentity.account();
        region = deriveRegion(assumedIdentity.arn());
        resourceType = deriveResourceTypeDetailed(assumedIdentity.arn());
        arn = assumedRole;
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
      if (who.userId() != null && !who.userId().isEmpty())
        extra.put("userId", who.userId());
      CloudIdentity identity = new CloudIdentity(CloudProviderType.aws, arn, account, region,
          resourceType, extra);
      return new IdentityHeadersResult(headers, identity, null);
    } catch (Exception e) {
      return new IdentityHeadersResult(null, null, e);
    }
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
    String[] parts = arn.split(":");
    return parts.length > 3 ? parts[3] : "";
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
