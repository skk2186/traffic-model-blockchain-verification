package com.traffic.wecross.crossverification.zkp;

import com.traffic.wecross.crossverification.config.ZkpVerificationProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ZokratesProcessRunnerTest {
    @TempDir
    Path tempDirectory;

    @Test
    void capturesStdoutAndStderrWithoutMergingThem() throws Exception {
        ZokratesProcessResult result = runner(5000L, 1024).run(arguments("echo"));

        assertTrue(result.isStarted());
        assertFalse(result.isTimedOut());
        assertEquals(Integer.valueOf(0), result.getExitCode());
        assertTrue(result.getStdout().contains("standard-output"));
        assertTrue(result.getStderr().contains("standard-error"));
        assertNull(result.getFailureReason());
        assertTempRootHasNoChildren();
    }

    @Test
    void reportsNonZeroExitCode() throws Exception {
        ZokratesProcessResult result = runner(5000L, 1024).run(arguments("nonzero"));

        assertEquals(Integer.valueOf(7), result.getExitCode());
        assertTrue(result.getStderr().contains("intentional-nonzero"));
        assertEquals("ZoKrates process exited with code 7", result.getFailureReason());
        assertTempRootHasNoChildren();
    }

    @Test
    void terminatesTimedOutProcess() throws Exception {
        ZokratesProcessResult result = runner(250L, 1024).run(arguments("timeout"));

        assertTrue(result.isStarted());
        assertTrue(result.isTimedOut());
        assertNotNull(result.getFailureReason());
        assertTrue(result.getFailureReason().contains("timed out"));
        assertTrue(result.getDurationMillis() < 5000L);
        assertTempRootHasNoChildren();
    }

    @Test
    void truncatesStdoutAndStderrWhileContinuingToDrainBothStreams() throws Exception {
        ZokratesProcessResult result = runner(5000L, 128).run(arguments("flood"));

        assertEquals(Integer.valueOf(0), result.getExitCode());
        assertTrue(result.getStdout().endsWith("[output truncated]"));
        assertTrue(result.getStderr().endsWith("[output truncated]"));
        assertTrue(result.getStdout().length() < 256);
        assertTrue(result.getStderr().length() < 256);
        assertTempRootHasNoChildren();
    }

    @Test
    void removesUniqueWorkingDirectoryAndFilesCreatedInsideIt() throws Exception {
        ZokratesProcessResult result = runner(5000L, 4096).run(arguments("working-directory"));

        assertEquals(Integer.valueOf(0), result.getExitCode());
        Path workingDirectory = Paths.get(result.getStdout().trim());
        assertFalse(Files.exists(workingDirectory));
        assertTempRootHasNoChildren();
    }

    @Test
    void reportsMissingExecutableBeforeStartingProcess() {
        ZkpVerificationProperties properties = new ZkpVerificationProperties();
        properties.setZokratesExecutable(tempDirectory.resolve("missing-zokrates.exe").toString());
        properties.setTempRoot(tempDirectory.resolve("runner-temp").toString());

        ZokratesProcessResult result = new ZokratesProcessRunner(properties).run(arguments("echo"));

        assertFalse(result.isStarted());
        assertFalse(result.isTimedOut());
        assertNull(result.getExitCode());
        assertTrue(result.getFailureReason().contains("ZoKrates executable does not exist"));
    }

    @Test
    void reportsTemporaryRootCreationFailureBeforeStartingProcess() throws Exception {
        Path tempRootFile = tempDirectory.resolve("not-a-directory");
        Files.write(tempRootFile, new byte[] { 1 });
        ZkpVerificationProperties properties = new ZkpVerificationProperties();
        properties.setZokratesExecutable(powershellExecutable().toString());
        properties.setTempRoot(tempRootFile.toString());

        ZokratesProcessResult result = new ZokratesProcessRunner(properties).run(arguments("echo"));

        assertFalse(result.isStarted());
        assertFalse(result.isTimedOut());
        assertNull(result.getExitCode());
        assertNotNull(result.getFailureReason());
    }

    private ZokratesProcessRunner runner(long timeoutMillis, int maxOutputBytes) {
        ZkpVerificationProperties properties = new ZkpVerificationProperties();
        properties.setZokratesExecutable(powershellExecutable().toString());
        properties.setTempRoot(tempDirectory.resolve("runner-temp").toString());
        properties.setTimeoutMillis(timeoutMillis);
        properties.setMaxOutputBytes(maxOutputBytes);
        return new ZokratesProcessRunner(properties);
    }

    private List<String> arguments(String mode) {
        Path helper = Paths.get("src", "test", "resources", "zkp", "process-helper.ps1")
                .toAbsolutePath()
                .normalize();
        return Arrays.asList(
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                helper.toString(),
                "-Mode",
                mode);
    }

    private Path powershellExecutable() {
        return Paths.get(
                System.getenv("SystemRoot"),
                "System32",
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe");
    }

    private void assertTempRootHasNoChildren() throws Exception {
        Path root = tempDirectory.resolve("runner-temp");
        if (!Files.exists(root)) {
            return;
        }
        try (Stream<Path> children = Files.list(root)) {
            assertEquals(0L, children.count());
        }
    }
}
