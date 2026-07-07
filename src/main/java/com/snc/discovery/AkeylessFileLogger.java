package com.snc.discovery;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Writes Akeyless resolver diagnostics to daily-rotated files under the MID agent {@code logs/} folder.
 * Supplements Commons Logging; does not replace MID server log integration.
 */
final class AkeylessFileLogger {
  private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
  private static final DateTimeFormatter TIMESTAMP_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
  private static final String LOG_FILE_PREFIX = "akeyless-resolver-";

  private static volatile AkeylessFileLogger instance;
  private static volatile Path logDirOverride;

  private final Object lock = new Object();
  private Path logDir;
  private String currentDate;
  private Path currentFile;

  static AkeylessFileLogger getInstance() {
    AkeylessFileLogger local = instance;
    if (local == null) {
      synchronized (AkeylessFileLogger.class) {
        local = instance;
        if (local == null) {
          local = new AkeylessFileLogger();
          instance = local;
        }
      }
    }
    return local;
  }

  static void setLogDirForTests(Path dir) {
    logDirOverride = dir;
    resetForTests();
  }

  static void resetForTests() {
    synchronized (AkeylessFileLogger.class) {
      instance = null;
    }
  }

  void info(String message) {
    write("INFO", message, null);
  }

  void warn(String message) {
    write("WARN", message, null);
  }

  void warn(String message, Throwable t) {
    write("WARN", message, t);
  }

  void error(String message) {
    write("ERROR", message, null);
  }

  void error(String message, Throwable t) {
    write("ERROR", message, t);
  }

  private void write(String level, String message, Throwable t) {
    if (message == null) {
      return;
    }
    String line = TIMESTAMP_FMT.format(LocalDateTime.now())
        + " [" + level + "] " + message;
    if (t != null) {
      line += " (" + t.getClass().getSimpleName() + ": " + safeMessage(t.getMessage()) + ")";
    }
    line += System.lineSeparator();

    synchronized (lock) {
      try {
        Path file = resolveCurrentFile();
        Files.writeString(file, line, StandardCharsets.UTF_8,
            StandardOpenOption.CREATE, StandardOpenOption.APPEND);
      } catch (IOException ignored) {
        // File logging is best-effort; MID Commons Logging remains the primary path.
      }
    }
  }

  private Path resolveCurrentFile() throws IOException {
    String today = DATE_FMT.format(LocalDate.now());
    Path dir = resolveLogDir();
    if (!today.equals(currentDate) || currentFile == null) {
      Files.createDirectories(dir);
      currentDate = today;
      currentFile = dir.resolve(LOG_FILE_PREFIX + today + ".log");
    }
    return currentFile;
  }

  private Path resolveLogDir() {
    if (logDir != null) {
      return logDir;
    }
    if (logDirOverride != null) {
      logDir = logDirOverride;
      return logDir;
    }
    logDir = resolveAgentLogDir();
    return logDir;
  }

  private static Path resolveAgentLogDir() {
    String base = resolveAgentBaseDir();
    return Path.of(base, "logs");
  }

  private static String resolveAgentBaseDir() {
    String midInstall = getMidInstallationDir();
    if (midInstall != null && !midInstall.isEmpty()) {
      return midInstall;
    }
    return ".";
  }

  private static String getMidInstallationDir() {
    try {
      Class<?> c = Class.forName("com.service_now.mid.services.Config");
      Object cfg = c.getMethod("get").invoke(null);
      for (String name : new String[]{"mid.installation.dir", "mid.home", "agent.home"}) {
        String v = (String) c.getMethod("getProperty", String.class).invoke(cfg, name);
        if (v != null && !v.isEmpty()) {
          return v;
        }
      }
    } catch (Throwable ignored) {
      // Outside MID: fall back to current working directory.
    }
    return null;
  }

  private static String safeMessage(String message) {
    return message == null ? "" : message;
  }
}
