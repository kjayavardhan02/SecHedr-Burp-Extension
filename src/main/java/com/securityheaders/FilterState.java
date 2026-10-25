package com.securityheaders;

import java.util.Collections;
import java.util.Set;

public final class FilterState {

    public enum HeaderFilter {
        ALL,
        ANY_MISSING,
        ALL_MISSING,
        HSTS_MISSING,
        CACHE_CONTROL_MISSING,
        XFO_MISSING,
        XCTO_MISSING,
        ACAO_MISSING,
        CSP_MISSING
    }

    private final String searchText;
    private final String hostFilter;
    private final Set<Integer> statusCodes;
    private final HeaderFilter headerFilter;

    public FilterState(String searchText, String hostFilter,
                       Set<Integer> statusCodes, HeaderFilter headerFilter) {
        this.searchText = searchText == null ? "" : searchText.trim().toLowerCase();
        this.hostFilter = hostFilter == null || hostFilter.isBlank() ? null : hostFilter.trim().toLowerCase();
        this.statusCodes = statusCodes == null ? Collections.emptySet() : Set.copyOf(statusCodes);
        this.headerFilter = headerFilter == null ? HeaderFilter.ALL : headerFilter;
    }

    public static FilterState none() {
        return new FilterState("", null, Collections.emptySet(), HeaderFilter.ALL);
    }

    public String searchText() { return searchText; }
    public String hostFilter() { return hostFilter; }
    public Set<Integer> statusCodes() { return statusCodes; }
    public HeaderFilter headerFilter() { return headerFilter; }

    public boolean isActive() {
        return !searchText.isEmpty()
                || hostFilter != null
                || !statusCodes.isEmpty()
                || headerFilter != HeaderFilter.ALL;
    }
}
