package com.traffic.wecross.crossverification.zkp;

public class ZokratesProcessResult {
    private final boolean started;
    private final boolean timedOut;
    private final Integer exitCode;
    private final String stdout;
    private final String stderr;
    private final long durationMillis;
    private final String failureReason;

    public ZokratesProcessResult(
            boolean started,
            boolean timedOut,
            Integer exitCode,
            String stdout,
            String stderr,
            long durationMillis,
            String failureReason) {
        this.started = started;
        this.timedOut = timedOut;
        this.exitCode = exitCode;
        this.stdout = stdout;
        this.stderr = stderr;
        this.durationMillis = durationMillis;
        this.failureReason = failureReason;
    }

    public boolean isStarted() {
        return started;
    }

    public boolean isTimedOut() {
        return timedOut;
    }

    public Integer getExitCode() {
        return exitCode;
    }

    public String getStdout() {
        return stdout;
    }

    public String getStderr() {
        return stderr;
    }

    public long getDurationMillis() {
        return durationMillis;
    }

    public String getFailureReason() {
        return failureReason;
    }
}
