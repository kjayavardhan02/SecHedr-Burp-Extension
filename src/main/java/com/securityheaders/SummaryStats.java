package com.securityheaders;

public final class SummaryStats {

    private final int responsesAnalyzed;
    private final int responsesWithMissing;
    private final int hostsObserved;
    private final int missingOccurrences;

    public SummaryStats(int responsesAnalyzed, int responsesWithMissing,
                        int hostsObserved, int missingOccurrences) {
        this.responsesAnalyzed = responsesAnalyzed;
        this.responsesWithMissing = responsesWithMissing;
        this.hostsObserved = hostsObserved;
        this.missingOccurrences = missingOccurrences;
    }

    public int responsesAnalyzed() { return responsesAnalyzed; }
    public int responsesWithMissing() { return responsesWithMissing; }
    public int hostsObserved() { return hostsObserved; }
    public int missingOccurrences() { return missingOccurrences; }
}
