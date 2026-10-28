package com.securityheaders;

import com.securityheaders.policy.PolicyComplianceStatus;
import com.securityheaders.policy.PolicyEvaluationResult;
import com.securityheaders.policy.PolicyEvaluator;
import com.securityheaders.policy.PolicyProfile;
import com.securityheaders.testcase.ExecutionMode;
import com.securityheaders.testcase.ResultStatus;
import com.securityheaders.testcase.TestcaseDefinition;
import com.securityheaders.testcase.TestcaseLibrary;
import com.securityheaders.testcase.TestcaseResult;

import javax.swing.table.AbstractTableModel;
import java.util.*;

public class ResultsTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
        "Host", "Method", "URL (Path)", "Status Code",
        "HSTS", "Cache-Control", "XFO", "XCTO", "ACAO", "ACAO Checks", "CSP",
        "Passive TC", "Active TC", "Not Executed",
        "Policy Compliance"
    };

    private List<HeaderResult> results = new ArrayList<>();
    private Map<String, int[]> tcCounts = new HashMap<>();
    private int totalTc = 0;

    private PolicyEvaluator policyEvaluator;
    private PolicyProfile activePolicy;
    private final Map<Long, PolicyEvaluationResult> evalCache = new HashMap<>();

    @Override
    public int getRowCount() {
        return results.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        HeaderResult r = results.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> r.host();
            case 1 -> r.method();
            case 2 -> r.pathAndQuery();
            case 3 -> r.statusCode();
            case 4 -> presenceText(r.hstsPresent());
            case 5 -> presenceText(r.cacheControlPresent());
            case 6 -> r.xfoCoveredByCsp() ? "COVERED" : presenceText(r.xfoPresent());
            case 7 -> presenceText(r.xctoPresent());
            case 8 -> presenceText(r.acaoPresent());
            case 9 -> {
                if (!r.acaoPresent()) yield "—";
                yield r.acaoCheckFailed() ? "FAIL" : "PASS";
            }
            case 10 -> presenceText(r.cspPresent());
            case 11 -> tcCounts.getOrDefault(r.endpointKey(), new int[]{0, 0, totalTc})[0];
            case 12 -> tcCounts.getOrDefault(r.endpointKey(), new int[]{0, 0, totalTc})[1];
            case 13 -> tcCounts.getOrDefault(r.endpointKey(), new int[]{0, 0, totalTc})[2];
            case 14 -> getComplianceStatus(r).displayLabel();
            default -> "";
        };
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 3 || columnIndex == 11 || columnIndex == 12 || columnIndex == 13)
            return Integer.class;
        return String.class;
    }

    public void setData(List<HeaderResult> data) {
        this.results = new ArrayList<>(data);
        fireTableDataChanged();
    }

    public void setPolicyContext(PolicyEvaluator evaluator, PolicyProfile active) {
        this.policyEvaluator = evaluator;
        this.activePolicy = active;
        evalCache.clear();
    }

    public PolicyComplianceStatus getComplianceStatus(HeaderResult r) {
        if (policyEvaluator == null || activePolicy == null)
            return PolicyComplianceStatus.NOT_EVALUATED;
        return getEvaluation(r).overallStatus();
    }

    public PolicyEvaluationResult getEvaluation(HeaderResult r) {
        if (policyEvaluator == null || activePolicy == null)
            return PolicyEvaluationResult.notEvaluated();
        return evalCache.computeIfAbsent(r.id(),
                id -> policyEvaluator.evaluate(r, activePolicy));
    }

    public void invalidateEvalCache() {
        evalCache.clear();
    }

    public void setTestcaseCounts(List<TestcaseResult> results, int totalTestcases,
                                   TestcaseLibrary library) {
        this.totalTc = totalTestcases;
        tcCounts.clear();
        Map<String, Set<String>> passiveOnlyIds = new HashMap<>();
        Map<String, Set<String>> activeOrBothIds = new HashMap<>();
        Map<String, Set<String>> allIds = new HashMap<>();
        for (TestcaseResult r : results) {
            if (r.status() == ResultStatus.NOT_TESTED || r.status() == ResultStatus.UNSUPPORTED) continue;
            String key = r.endpointKey();
            String tcId = r.testcaseId();
            allIds.computeIfAbsent(key, k -> new HashSet<>()).add(tcId);
            TestcaseDefinition def = library.get(tcId);
            if (def != null && def.mode() == ExecutionMode.PASSIVE) {
                passiveOnlyIds.computeIfAbsent(key, k -> new HashSet<>()).add(tcId);
            } else {
                activeOrBothIds.computeIfAbsent(key, k -> new HashSet<>()).add(tcId);
            }
        }
        for (String key : allIds.keySet()) {
            int passive = passiveOnlyIds.getOrDefault(key, Set.of()).size();
            int active = activeOrBothIds.getOrDefault(key, Set.of()).size();
            int unique = allIds.get(key).size();
            tcCounts.put(key, new int[]{passive, active, Math.max(0, totalTestcases - unique)});
        }
    }

    public HeaderResult getResultAt(int row) {
        return results.get(row);
    }

    public List<HeaderResult> getData() {
        return results;
    }

    private static String presenceText(boolean present) {
        return present ? "PRESENT" : "MISSING";
    }
}
