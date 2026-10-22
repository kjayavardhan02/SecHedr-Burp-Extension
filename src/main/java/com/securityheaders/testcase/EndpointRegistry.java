package com.securityheaders.testcase;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class EndpointRegistry {

    private final Set<String> observedEndpoints = ConcurrentHashMap.newKeySet();
    private final Set<String> activeScannedEndpoints = ConcurrentHashMap.newKeySet();

    public boolean registerObserved(String endpointKey) {
        return observedEndpoints.add(endpointKey);
    }

    public boolean isObserved(String endpointKey) {
        return observedEndpoints.contains(endpointKey);
    }

    public boolean markActiveScanned(String endpointKey) {
        return activeScannedEndpoints.add(endpointKey);
    }

    public boolean isActiveScanned(String endpointKey) {
        return activeScannedEndpoints.contains(endpointKey);
    }

    public int observedCount() { return observedEndpoints.size(); }
    public int activeScannedCount() { return activeScannedEndpoints.size(); }

    public void clear() {
        observedEndpoints.clear();
        activeScannedEndpoints.clear();
    }
}
