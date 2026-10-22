package com.securityheaders.testcase;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class TestcaseSelector {

    private final Set<String> disabledIds = ConcurrentHashMap.newKeySet();

    public boolean isEnabled(String testcaseId) {
        return !disabledIds.contains(testcaseId);
    }

    public void setEnabled(String testcaseId, boolean enabled) {
        if (enabled) {
            disabledIds.remove(testcaseId);
        } else {
            disabledIds.add(testcaseId);
        }
    }

    public void enableAll() {
        disabledIds.clear();
    }

    public void disableAll(Set<String> allIds) {
        disabledIds.addAll(allIds);
    }

    public Set<String> getDisabledIds() {
        return Collections.unmodifiableSet(disabledIds);
    }

    public int disabledCount() {
        return disabledIds.size();
    }
}
