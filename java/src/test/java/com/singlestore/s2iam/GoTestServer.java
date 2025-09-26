package com.singlestore.s2iam;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Lightweight manager to build and run the Go test server for integration tests.
 *
 * Updated to use the new --info-file startup contract (JSON) instead of parsing stdout/stderr
 * for a 'port NNNN' line. This mirrors the Go integration tests which rely on an atomic
 * info JSON file written by the server.
 */

/** Lightweight manager to build and run the Go test server for integration tests. */
class GoTestServer {
  private Process process;
  private int port = -1;
  private final Path goDir;
  private final List<String> flags;
  private Path infoFile; // path to JSON info file
  private Map<String, String> endpoints = new HashMap<>();

  GoTestServer(Path repoRoot, String... extraFlags) {
    this.goDir = resolveGoDir(repoRoot);
    this.flags = new ArrayList<>();
    for (String f : extraFlags) flags.add(f);
  }

  private Path resolveGoDir(Path start) {
    // If passed path has go/ then use it, else walk up a few levels
    Path p = start.toAbsolutePath();
    for (int i = 0; i < 4; i++) {
      if (Files.exists(p.resolve("go").resolve("go.mod"))) return p.resolve("go");
      p = p.getParent();
      if (p == null) break;
    }
    return start.resolve("go");
  }

  int getPort() { return port; }

  String getBaseURL() { return "http://localhost:" + port; }

  Map<String, String> getEndpoints() { return endpoints; }

  void start() throws Exception {
    if (process != null) return;
    if (!Files.exists(goDir.resolve("go.mod"))) {
      throw new IllegalStateException("go dir missing go.mod: " + goDir);
    }
    // Build server binary with size-reducing flags (-s -w) and trimpath. Retry once if ENOSPC or
    // cache corruption (.partial leftover) is detected. Avoid unconditional 'go clean' because it
    // slows builds and can introduce transient races creating partially-downloaded modules when
    // multiple servers build in quick succession.
    IllegalStateException firstFailure = null;
    try {
      run(new ProcessBuilder("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", "s2iam_test_server", "./cmd/s2iam_test_server")
          .directory(goDir.toFile()));
    } catch (IllegalStateException e) {
      firstFailure = e;
      String msg = e.getMessage() == null ? "" : e.getMessage();
      if (msg.contains("no space left") || msg.contains(".partial")) {
        // Targeted cleanup then force full rebuild of all packages
        try {
          run(new ProcessBuilder("go", "clean", "-cache", "-modcache")
              .directory(goDir.toFile()));
        } catch (Exception ignored) { }
        run(new ProcessBuilder("go", "build", "-a", "-trimpath", "-ldflags", "-s -w", "-o", "s2iam_test_server", "./cmd/s2iam_test_server")
            .directory(goDir.toFile()));
      } else {
        throw e; // Non-space issue: propagate immediately
      }
    }
    if (!Files.exists(goDir.resolve("s2iam_test_server"))) {
      // Provide context from first failure if available
      if (firstFailure != null) throw firstFailure;
      throw new IllegalStateException("build failed - no binary (unknown reason)");
    }
    // Prepare info file path inside goDir (avoids needing temp outside repo for simplicity)
  // Use a unique temp info file per server instance to avoid cross-test contention
  infoFile = Files.createTempFile(goDir, "s2iam_test_server_info", ".json");

    List<String> cmd = new ArrayList<>();
    cmd.add("./s2iam_test_server");
    cmd.add("--port");
    cmd.add("0");
    cmd.add("--info-file");
    cmd.add(infoFile.toString());
    cmd.add("--allowed-audiences");
    cmd.add("https://authsvc.singlestore.com,https://test.example.com");
    cmd.add("--timeout");
    cmd.add("2m");
    cmd.addAll(flags);

    ProcessBuilder pb = new ProcessBuilder(cmd).directory(goDir.toFile());
    // We intentionally drop stdout; errors to stderr for visibility in failures
    pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
    pb.redirectError(ProcessBuilder.Redirect.INHERIT);
    process = pb.start();

    // Poll info file for up to 5s (aligned with Go test helper baseline)
    long deadline = System.currentTimeMillis() + Duration.ofSeconds(5).toMillis();
    Exception lastErr = null;
    while (System.currentTimeMillis() < deadline) {
      if (!process.isAlive()) {
        throw new IllegalStateException("server exited early before writing info file");
      }
      if (Files.exists(infoFile)) {
        try {
          parseInfo();
          if (port > 0) return; // success
        } catch (Exception e) {
          lastErr = e;
        }
      }
      Thread.sleep(100);
    }
    throw new IllegalStateException("timeout waiting for server info file: " + (lastErr == null ? "unknown" : lastErr.getMessage()));
  }

  void stop() {
    if (process != null) {
      process.destroy();
      try {
        process.waitFor(1, TimeUnit.SECONDS);
      } catch (InterruptedException ignored) {
        Thread.currentThread().interrupt();
      }
      if (process.isAlive()) process.destroyForcibly();
    }
  }

  private void run(ProcessBuilder pb) throws Exception {
    // Capture both stdout and stderr so failures surface original command output (fail-fast rule)
    pb.redirectErrorStream(true);
    Process p = pb.start();
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    try (InputStream in = p.getInputStream()) {
      byte[] buf = new byte[8192];
      int r;
      while ((r = in.read(buf)) != -1) {
        bout.write(buf, 0, r);
      }
    }
    int code = p.waitFor();
    if (code != 0) {
      String out = bout.toString();
      throw new IllegalStateException("command failed (" + code + "):\n" + out);
    }
  }

  private void parseInfo() throws IOException {
    if (infoFile == null) return;
    ObjectMapper mapper = new ObjectMapper();
    try (Reader r = Files.newBufferedReader(infoFile)) {
      InfoFile info = mapper.readValue(r, InfoFile.class);
      if (info != null && info.server_info != null) {
        this.port = info.server_info.port;
        if (info.server_info.endpoints != null) {
          this.endpoints.clear();
          this.endpoints.putAll(info.server_info.endpoints);
        }
      }
    }
  }

  // POJOs matching test server info-file structure
  @JsonIgnoreProperties(ignoreUnknown = true)
  private static class InfoFile {
    public ServerInfo server_info; // snake case matches JSON
  }
  @JsonIgnoreProperties(ignoreUnknown = true)
  private static class ServerInfo {
    public int port;
    public java.util.Map<String,String> endpoints;
  }
}
