package com.traffic.wecross.crossverification.zkp;

import com.traffic.wecross.crossverification.config.ZkpVerificationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;

@Component
public class ZokratesProcessRunner {
    private static final Logger LOGGER = LoggerFactory.getLogger(ZokratesProcessRunner.class);
    private static final String TRUNCATION_MARKER = "\n[output truncated]";
    private static final long TERMINATION_GRACE_MILLIS = 500L;
    private static final long OUTPUT_JOIN_TIMEOUT_SECONDS = 5L;

    private final ZkpVerificationProperties properties;

    public ZokratesProcessRunner(ZkpVerificationProperties properties) {
        this.properties = properties;
    }

    public ZokratesProcessResult run(List<String> arguments) {
        return runInTemporaryDirectory(workingDirectory -> arguments);
    }

    public ZokratesProcessResult runInTemporaryDirectory(CommandFactory commandFactory) {
        long startedAt = System.nanoTime();
        Path workingDirectory = null;
        Process process = null;
        ExecutorService outputExecutor = null;
        Future<String> stdoutFuture = null;
        Future<String> stderrFuture = null;
        boolean started = false;
        boolean timedOut = false;
        Integer exitCode = null;
        String stdout = "";
        String stderr = "";
        String failureReason = null;

        try {
            Path executable = resolveExecutable();
            workingDirectory = createWorkingDirectory();
            List<String> arguments = commandFactory.create(workingDirectory);
            List<String> command = buildCommand(executable, arguments);

            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.directory(workingDirectory.toFile());
            process = processBuilder.start();
            started = true;

            outputExecutor = Executors.newFixedThreadPool(2);
            stdoutFuture = outputExecutor.submit(new BoundedStreamReader(
                    process.getInputStream(), properties.getMaxOutputBytes()));
            stderrFuture = outputExecutor.submit(new BoundedStreamReader(
                    process.getErrorStream(), properties.getMaxOutputBytes()));

            boolean finished = process.waitFor(properties.getTimeoutMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                timedOut = true;
                failureReason = "ZoKrates process timed out after " + properties.getTimeoutMillis() + " ms";
                terminateProcessTree(process);
            }
            if (!process.isAlive()) {
                exitCode = process.exitValue();
            }

            stdout = awaitOutput(stdoutFuture);
            stderr = awaitOutput(stderrFuture);
            if (!timedOut && exitCode != null && exitCode != 0) {
                failureReason = "ZoKrates process exited with code " + exitCode;
            }
        } catch (Exception e) {
            failureReason = safeMessage(e);
            if (process != null && process.isAlive()) {
                terminateProcessTree(process);
            }
            stdout = availableOutput(stdoutFuture, stdout);
            stderr = availableOutput(stderrFuture, stderr);
        } finally {
            if (outputExecutor != null) {
                outputExecutor.shutdownNow();
            }
            cleanupWorkingDirectory(workingDirectory);
        }

        return new ZokratesProcessResult(
                started,
                timedOut,
                exitCode,
                stdout,
                stderr,
                elapsedMillis(startedAt),
                failureReason);
    }

    private Path resolveExecutable() throws IOException {
        Path executable = Paths.get(properties.getZokratesExecutable()).toAbsolutePath().normalize();
        if (!Files.isRegularFile(executable)) {
            throw new IOException("ZoKrates executable does not exist: " + executable);
        }
        return executable.toRealPath();
    }

    private Path createWorkingDirectory() throws IOException {
        Path tempRoot = Paths.get(properties.getTempRoot()).toAbsolutePath().normalize();
        Files.createDirectories(tempRoot);
        return Files.createTempDirectory(tempRoot, "zokrates-");
    }

    private List<String> buildCommand(Path executable, List<String> arguments) {
        if (arguments == null) {
            throw new IllegalArgumentException("ZoKrates arguments must not be null");
        }
        List<String> command = new ArrayList<>(arguments.size() + 1);
        command.add(executable.toString());
        for (String argument : arguments) {
            if (argument == null) {
                throw new IllegalArgumentException("ZoKrates arguments must not contain null values");
            }
            command.add(argument);
        }
        return command;
    }

    private String awaitOutput(Future<String> future)
            throws InterruptedException, ExecutionException, TimeoutException {
        if (future == null) {
            return "";
        }
        return future.get(OUTPUT_JOIN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    private String availableOutput(Future<String> future, String fallback) {
        if (future == null || !future.isDone()) {
            return fallback;
        }
        try {
            return future.get();
        } catch (Exception ignored) {
            return fallback;
        }
    }

    private void terminateProcessTree(Process process) {
        destroyDescendantsReflectively(process, false);
        process.destroy();
        try {
            if (!process.waitFor(TERMINATION_GRACE_MILLIS, TimeUnit.MILLISECONDS)) {
                destroyDescendantsReflectively(process, true);
                process.destroyForcibly();
                process.waitFor(TERMINATION_GRACE_MILLIS, TimeUnit.MILLISECONDS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        }
    }

    private void destroyDescendantsReflectively(Process process, boolean forcibly) {
        try {
            Method toHandle = Process.class.getMethod("toHandle");
            Object handle = toHandle.invoke(process);
            Method descendants = handle.getClass().getMethod("descendants");
            Object descendantStream = descendants.invoke(handle);
            Method iteratorMethod = descendantStream.getClass().getMethod("iterator");
            Iterator<?> iterator = (Iterator<?>) iteratorMethod.invoke(descendantStream);
            while (iterator.hasNext()) {
                Object descendant = iterator.next();
                Method destroy = descendant.getClass().getMethod(forcibly ? "destroyForcibly" : "destroy");
                destroy.invoke(descendant);
            }
            Method close = descendantStream.getClass().getMethod("close");
            close.invoke(descendantStream);
        } catch (Exception ignored) {
            // Java 8 has no public ProcessHandle API. The root process is still terminated below.
        }
    }

    private void cleanupWorkingDirectory(Path workingDirectory) {
        if (workingDirectory == null || !Files.exists(workingDirectory)) {
            return;
        }
        try (Stream<Path> paths = Files.walk(workingDirectory)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException e) {
                    LOGGER.warn("Unable to clean ZoKrates temporary path: {}", path, e);
                }
            });
        } catch (IOException e) {
            LOGGER.warn("Unable to clean ZoKrates temporary directory: {}", workingDirectory, e);
        }
    }

    private long elapsedMillis(long startedAt) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);
    }

    private String safeMessage(Exception e) {
        String message = e.getMessage();
        return message == null || message.trim().isEmpty() ? e.getClass().getSimpleName() : message;
    }

    @FunctionalInterface
    public interface CommandFactory {
        List<String> create(Path workingDirectory) throws Exception;
    }

    private static class BoundedStreamReader implements Callable<String> {
        private final InputStream inputStream;
        private final int maxBytes;

        private BoundedStreamReader(InputStream inputStream, int maxBytes) {
            this.inputStream = inputStream;
            this.maxBytes = maxBytes;
        }

        @Override
        public String call() throws IOException {
            ByteArrayOutputStream captured = new ByteArrayOutputStream(Math.min(maxBytes, 8192));
            byte[] buffer = new byte[4096];
            int totalCaptured = 0;
            boolean truncated = false;
            int read;
            while ((read = inputStream.read(buffer)) != -1) {
                int writable = Math.min(read, maxBytes - totalCaptured);
                if (writable > 0) {
                    captured.write(buffer, 0, writable);
                    totalCaptured += writable;
                }
                if (writable < read) {
                    truncated = true;
                }
            }
            String text = new String(captured.toByteArray(), StandardCharsets.UTF_8);
            return truncated ? text + TRUNCATION_MARKER : text;
        }
    }
}
