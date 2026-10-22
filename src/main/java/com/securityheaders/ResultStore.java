package com.securityheaders;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class ResultStore {

    private final CopyOnWriteArrayList<HeaderResult> results = new CopyOnWriteArrayList<>();
    private final Set<Long> seenIds = ConcurrentHashMap.newKeySet();

    public void add(HeaderResult result) {
        if (seenIds.add(result.id())) {
            results.add(result);
        }
    }

    public List<HeaderResult> getAll() {
        return Collections.unmodifiableList(new ArrayList<>(results));
    }

    public void clear() {
        results.clear();
        seenIds.clear();
    }

    public int size() {
        return results.size();
    }
}
