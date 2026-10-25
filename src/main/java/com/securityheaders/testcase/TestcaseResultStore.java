package com.securityheaders.testcase;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class TestcaseResultStore {

    private final CopyOnWriteArrayList<TestcaseResult> results = new CopyOnWriteArrayList<>();
    private final Set<String> seen = ConcurrentHashMap.newKeySet();

    public void add(TestcaseResult result) {
        String key = dedupeKey(result);
        if (seen.add(key)) {
            results.add(result);
        }
    }

    public void addAll(List<TestcaseResult> batch) {
        for (TestcaseResult r : batch) {
            add(r);
        }
    }

    public List<TestcaseResult> getAll() {
        return Collections.unmodifiableList(new ArrayList<>(results));
    }

    public void clear() {
        results.clear();
        seen.clear();
    }

    public int size() {
        return results.size();
    }

    private static String dedupeKey(TestcaseResult r) {
        return r.testcaseId() + "|" + r.endpointKey() + "|" + r.mode().name();
    }
}
