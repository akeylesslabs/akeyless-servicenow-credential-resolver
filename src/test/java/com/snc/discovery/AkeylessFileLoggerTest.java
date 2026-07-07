package com.snc.discovery;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

public class AkeylessFileLoggerTest {

  private Path tempLogDir;

  @Before
  public void setUp() throws Exception {
    tempLogDir = Files.createTempDirectory("akeyless-file-logger-test");
    AkeylessFileLogger.setLogDirForTests(tempLogDir);
  }

  @After
  public void tearDown() throws IOException {
    AkeylessFileLogger.resetForTests();
    if (tempLogDir != null && Files.exists(tempLogDir)) {
      try (Stream<Path> paths = Files.walk(tempLogDir)) {
        paths.sorted(Comparator.reverseOrder()).forEach(path -> {
          try {
            Files.deleteIfExists(path);
          } catch (IOException ignored) {
          }
        });
      }
    }
  }

  @Test
  public void writesDailyRotatedLogFile() throws Exception {
    AkeylessFileLogger logger = AkeylessFileLogger.getInstance();
    logger.info("test info message");
    logger.warn("test warn message");

    String today = DateTimeFormatter.ofPattern("yyyy-MM-dd").format(LocalDate.now());
    Path logFile = tempLogDir.resolve("akeyless-resolver-" + today + ".log");
    Assert.assertTrue("Expected log file to exist: " + logFile, Files.exists(logFile));

    List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
    Assert.assertEquals(2, lines.size());
    Assert.assertTrue(lines.get(0).contains("[INFO] test info message"));
    Assert.assertTrue(lines.get(1).contains("[WARN] test warn message"));
  }

  @Test
  public void appendsToSameDailyFile() throws Exception {
    AkeylessFileLogger logger = AkeylessFileLogger.getInstance();
    logger.info("first");
    logger.info("second");

    String today = DateTimeFormatter.ofPattern("yyyy-MM-dd").format(LocalDate.now());
    Path logFile = tempLogDir.resolve("akeyless-resolver-" + today + ".log");
    List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
    Assert.assertEquals(2, lines.size());
    Assert.assertTrue(lines.get(0).contains("first"));
    Assert.assertTrue(lines.get(1).contains("second"));
  }

  @Test
  public void errorIncludesThrowableSummary() throws Exception {
    AkeylessFileLogger logger = AkeylessFileLogger.getInstance();
    logger.error("auth failed", new IllegalStateException("missing token"));

    String today = DateTimeFormatter.ofPattern("yyyy-MM-dd").format(LocalDate.now());
    Path logFile = tempLogDir.resolve("akeyless-resolver-" + today + ".log");
    String content = Files.readString(logFile, StandardCharsets.UTF_8);
    Assert.assertTrue(content.contains("[ERROR] auth failed"));
    Assert.assertTrue(content.contains("IllegalStateException: missing token"));
  }
}
