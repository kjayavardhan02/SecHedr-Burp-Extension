package com.securityheaders;

import com.securityheaders.testcase.ExecutionMode;
import com.securityheaders.testcase.TestcaseResult;

import javax.swing.table.AbstractTableModel;
import java.util.*;
import java.util.stream.Collectors;

public class EndpointSummaryTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "Host", "Method", "URL (Path)", "Count",
        "Status Code",
        "HSTS Missing", "CC Missing", "XFO Missing",
        "XCTO Missing", "ACAO Missing", "CSP Missing",
        "Passive TC", "Active TC", "Not Executed"
    };

    private List<EndpointSummary> data = new ArrayList<>();
    private Map<String, int[]> tcCounts = new HashMap<>();

    @Override
    public int getRowCount() { return data.size(); }

    @Override
    public int getColumnCount() { return COLUMNS.length; }

    @Override
    public String getColumnName(int col) { return COLUMNS[col]; }

    @Override
    public Class<?> getColumnClass(int col) {
        return switch (col) {
            case 3, 5, 6, 7, 8, 9, 10, 11, 12, 13 -> Integer.class;
            default -> String.class;
        };
    }

    @Override
    public Object getValueAt(int row, int col) {
        EndpointSummary ep = data.get(row);
        String key = ep.host() + ":" + ep.port() + ":" + ep.method() + ":" + ep.pathAndQuery();
        int[] counts = tcCounts.getOrDefault(key, new int[]{0, 0, 0});
        return switch (col) {
            case 0 -> ep.host();
            case 1 -> ep.method();
            case 2 -> ep.pathAndQuery();
            case 3 -> ep.responses();
            case 4 -> ep.statusCodes().stream().map(String::valueOf).collect(Collectors.joining(", "));
            case 5 -> ep.hstsMissing();
            case 6 -> ep.cacheControlMissing();
            case 7 -> ep.xfoMissing();
            case 8 -> ep.xctoMissing();
            case 9 -> ep.acaoMissing();
            case 10 -> ep.cspMissing();
            case 11 -> counts[0];
            case 12 -> counts[1];
            case 13 -> counts[2];
            default -> "";
        };
    }

    public void setData(List<EndpointSummary> summaries) {
        this.data = new ArrayList<>(summaries);
        fireTableDataChanged();
    }

    public void setTestcaseCounts(List<TestcaseResult> results, int totalTestcases) {
        tcCounts.clear();
        Map<String, Set<String>> passiveIds = new HashMap<>();
        Map<String, Set<String>> activeIds = new HashMap<>();
        Map<String, Set<String>> allIds = new HashMap<>();
        for (TestcaseResult r : results) {
            String key = r.endpointKey();
            String tcId = r.testcaseId();
            allIds.computeIfAbsent(key, k -> new HashSet<>()).add(tcId);
            if (r.mode() == ExecutionMode.PASSIVE) {
                passiveIds.computeIfAbsent(key, k -> new HashSet<>()).add(tcId);
            } else if (r.mode() == ExecutionMode.ACTIVE) {
                activeIds.computeIfAbsent(key, k -> new HashSet<>()).add(tcId);
            } else {
                passiveIds.computeIfAbsent(key, k -> new HashSet<>()).add(tcId);
                activeIds.computeIfAbsent(key, k -> new HashSet<>()).add(tcId);
            }
        }
        for (String key : allIds.keySet()) {
            int passive = passiveIds.containsKey(key) ? passiveIds.get(key).size() : 0;
            int active = activeIds.containsKey(key) ? activeIds.get(key).size() : 0;
            int unique = allIds.get(key).size();
            tcCounts.put(key, new int[]{passive, active, Math.max(0, totalTestcases - unique)});
        }
    }

    public List<EndpointSummary> getData() { return data; }
}
