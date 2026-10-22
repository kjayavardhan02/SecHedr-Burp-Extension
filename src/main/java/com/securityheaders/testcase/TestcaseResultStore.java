package com.securityheaders.testcase;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class TestcaseResultStore {

    private final CopyOnWriteArrayList<TestcaseResult> results = new CopyOnWriteArrayList<>();

    public void add(TestcaseResult result) {
        results.add(result);
    }

    public void addAll(List<TestcaseResult> batch) {
        results.addAll(batch);
    }

    public List<TestcaseResult> getAll() {
        return Collections.unmodifiableList(new ArrayList<>(results));
    }

    public void clear() {
        results.clear();
    }

    public int size() {
        return results.size();
    }
}
