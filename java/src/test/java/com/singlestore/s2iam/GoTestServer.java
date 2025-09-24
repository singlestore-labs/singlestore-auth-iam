package com.singlestore.s2iam;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Lightweight manager to build and run the Go test server for integration tests. */
class GoTestServer {
  private Process process;
  private int port = -1;
  private final Path goDir;
  private final List<String> flags;

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

  int getPort() {
    return port;
  }

  String getBaseURL() {
    return "http://localhost:" + port;
  }

  void start() throws Exception {
    if (process != null) return;
    if (!Files.exists(goDir.resolve("go.mod")))
      throw new IllegalStateException("go dir missing go.mod: " + goDir);
    // Build server
    run(
        new ProcessBuilder("go", "build", "-o", "s2iam_test_server", "./cmd/s2iam_test_server")
            .directory(goDir.toFile()));
    if (!Files.exists(goDir.resolve("s2iam_test_server")))
      throw new IllegalStateException("build failed - no binary");
    // Start server on port 0
    List<String> cmd = new ArrayList<>();
    cmd.add("./s2iam_test_server");
    cmd.add("-port");
    cmd.add("0");
    cmd.add("-allowed-audiences");
    cmd.add("https://authsvc.singlestore.com,https://test.example.com");
    cmd.add("-timeout");
    cmd.add("2m");
    cmd.addAll(flags);
    ProcessBuilder pb = new ProcessBuilder(cmd).directory(goDir.toFile());
    // Capture stdout to file for port discovery
    File debugLog = goDir.resolve("test_server_debug.log").toFile();
    pb.redirectError(ProcessBuilder.Redirect.appendTo(debugLog));
    pb.redirectOutput(ProcessBuilder.Redirect.appendTo(debugLog));
    process = pb.start();
    // Wait small period for startup and parse port
    long deadline = System.currentTimeMillis() + 5000;
    Pattern p = Pattern.compile("port\\s+([0-9]{2,5})");
    while (System.currentTimeMillis() < deadline) {
      Thread.sleep(200);
      String content =
          Files.readString(goDir.resolve("test_server_debug.log"), StandardCharsets.UTF_8);
      Matcher m = p.matcher(content);
      if (m.find()) {
        port = Integer.parseInt(m.group(1));
        break;
      }
      // Fallback: read debug log if available
      try {
        String dbg = Files.readString(goDir.resolve("test_server_debug.log"));
        m = p.matcher(dbg);
        if (m.find()) {
          port = Integer.parseInt(m.group(1));
          break;
        }
      } catch (IOException ignored) {
      }
      if (!process.isAlive()) {
        throw new IllegalStateException("server exited early: " + content);
      }
    }
    if (port <= 0) throw new IllegalStateException("could not discover server port");
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
    Process p = pb.start();
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (InputStream in = p.getInputStream()) {
      in.transferTo(baos);
    }
    int code = p.waitFor();
    if (code != 0) throw new IllegalStateException("command failed (" + code + ") stdout=" + baos);
  }
}
