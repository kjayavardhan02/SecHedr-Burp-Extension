package com.securityheaders;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicLong;

public class ScanHealthTracker {

    private final AtomicLong requestsProcessed = new AtomicLong(0);
    private final AtomicLong testcasesCompleted = new AtomicLong(0);
    private final AtomicLong testcasesFailed = new AtomicLong(0);
    private final AtomicLong scanErrors = new AtomicLong(0);
    private volatile Instant lastProgressAt = Instant.now();
    private volatile Instant scanStartedAt;

    private final Deque<Instant> recentCompletions = new ConcurrentLinkedDeque<>();
    private static final int THROUGHPUT_WINDOW_SEC = 60;

    private final Deque<ErrorEntry> recentErrors = new ConcurrentLinkedDeque<>();
    private static final int MAX_ERRORS = 50;

    public record ErrorEntry(Instant timestamp, String testcaseId, String endpoint, String message) {}

    public void recordRequestProcessed() {
        requestsProcessed.incrementAndGet();
        lastProgressAt = Instant.now();
        if (scanStartedAt == null) scanStartedAt = Instant.now();
    }

    public void recordTestcaseCompleted() {
        testcasesCompleted.incrementAndGet();
        recentCompletions.addLast(Instant.now());
        pruneOldCompletions();
        lastProgressAt = Instant.now();
    }

    public void recordTestcaseFailed() {
        testcasesFailed.incrementAndGet();
        lastProgressAt = Instant.now();
    }

    public void recordError(String testcaseId, String endpoint, String message) {
        scanErrors.incrementAndGet();
        recentErrors.addLast(new ErrorEntry(Instant.now(), testcaseId, endpoint, message));
        while (recentErrors.size() > MAX_ERRORS) recentErrors.pollFirst();
        lastProgressAt = Instant.now();
    }

    public long requestsProcessed() { return requestsProcessed.get(); }
    public long testcasesCompleted() { return testcasesCompleted.get(); }
    public long testcasesFailed() { return testcasesFailed.get(); }
    public long scanErrors() { return scanErrors.get(); }
    public Instant lastProgressAt() { return lastProgressAt; }

    public double checksPerMinute() {
        pruneOldCompletions();
        return recentCompletions.size() * 60.0 / THROUGHPUT_WINDOW_SEC;
    }

    public String elapsedTime() {
        if (scanStartedAt == null) return "—";
        Duration d = Duration.between(scanStartedAt, Instant.now());
        long h = d.toHours();
        long m = d.toMinutesPart();
        long s = d.toSecondsPart();
        if (h > 0) return String.format("%dh %dm %ds", h, m, s);
        if (m > 0) return String.format("%dm %ds", m, s);
        return String.format("%ds", s);
    }

    public long heapUsedMB() {
        return ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed() / (1024 * 1024);
    }

    public long heapMaxMB() {
        long max = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getMax();
        return max > 0 ? max / (1024 * 1024) : -1;
    }

    public int heapPercent() {
        var usage = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();
        long max = usage.getMax();
        if (max <= 0) return 0;
        return (int) (usage.getUsed() * 100 / max);
    }

    public List<ErrorEntry> recentErrors() {
        return new ArrayList<>(recentErrors);
    }

    public String timeSinceLastProgress() {
        Duration d = Duration.between(lastProgressAt, Instant.now());
        long sec = d.toSeconds();
        if (sec < 5) return "just now";
        if (sec < 60) return sec + "s ago";
        if (sec < 3600) return (sec / 60) + "m ago";
        return (sec / 3600) + "h ago";
    }

    public void reset() {
        requestsProcessed.set(0);
        testcasesCompleted.set(0);
        testcasesFailed.set(0);
        scanErrors.set(0);
        recentCompletions.clear();
        recentErrors.clear();
        scanStartedAt = null;
        lastProgressAt = Instant.now();
    }

    private void pruneOldCompletions() {
        Instant cutoff = Instant.now().minusSeconds(THROUGHPUT_WINDOW_SEC);
        while (!recentCompletions.isEmpty() && recentCompletions.peekFirst().isBefore(cutoff)) {
            recentCompletions.pollFirst();
        }
    }
}
