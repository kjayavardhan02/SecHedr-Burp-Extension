package com.securityheaders;

import com.securityheaders.testcase.TestcaseDefinition;
import com.securityheaders.testcase.TestcaseLibrary;
import com.securityheaders.testcase.TestcaseResult;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class TestcaseResultsTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "Testcase", "Description", "Host", "Path", "Status Code", "Mode",
        "HSTS", "Cache-Control", "XFO", "XCTO", "ACAO", "ACAO Checks", "CSP"
    };

    private static final String[] HEADER_KEYS = {
        "strict-transport-security", "cache-control", "x-frame-options",
        "x-content-type-options", "access-control-allow-origin", "content-security-policy"
    };

    private final TestcaseLibrary library;
    private List<TestcaseResult> data = new ArrayList<>();

    public TestcaseResultsTableModel(TestcaseLibrary library) {
        this.library = library;
    }

    public void setData(List<TestcaseResult> data) {
        this.data = new ArrayList<>(data);
        fireTableDataChanged();
    }

    public List<TestcaseResult> getData() { return data; }

    @Override public int getRowCount() { return data.size(); }
    @Override public int getColumnCount() { return COLUMNS.length; }
    @Override public String getColumnName(int col) { return COLUMNS[col]; }

    @Override
    public Class<?> getColumnClass(int col) {
        if (col == 4) return Integer.class;
        return String.class;
    }

    @Override
    public Object getValueAt(int row, int col) {
        TestcaseResult r = data.get(row);
        return switch (col) {
            case 0 -> r.testcaseId();
            case 1 -> {
                TestcaseDefinition def = library.get(r.testcaseId());
                yield def != null ? def.description() : "";
            }
            case 2 -> r.host();
            case 3 -> r.pathAndQuery();
            case 4 -> r.statusCode();
            case 5 -> r.mode().name();
            case 6 -> deriveHeaderStatus(r, 0);
            case 7 -> deriveHeaderStatus(r, 1);
            case 8 -> deriveHeaderStatus(r, 2);
            case 9 -> deriveHeaderStatus(r, 3);
            case 10 -> deriveHeaderStatus(r, 4);
            case 11 -> deriveAcaoChecks(r);
            case 12 -> deriveHeaderStatus(r, 5);
            default -> "";
        };
    }

    private String deriveHeaderStatus(TestcaseResult r, int headerIdx) {
        String tcId = r.testcaseId();
        String status = r.status().name();
        String actual = r.actual();

        // For ACAO column, show PRESENT/MISSING based on header presence
        // Only when the testcase was actually executed (PASS or FAIL)
        if (headerIdx == 4
                && (r.status() == com.securityheaders.testcase.ResultStatus.PASS
                    || r.status() == com.securityheaders.testcase.ResultStatus.FAIL)) {
            String acaoPresence = deriveAcaoPresence(r);
            if (acaoPresence != null) return acaoPresence;
        }

        // CORS / ACAO testcases → ACAO column + check baseline headers
        if (tcId.startsWith("CORS-") || tcId.startsWith("ACAO-")) {
            if (actual == null || actual.isEmpty()) return headerIdx == 4 ? status : "—";
            // If actual mentions missing baseline headers, derive per-header
            return deriveFromActual(actual, headerIdx, status);
        }

        // All other testcases check ALL baseline headers
        // Parse the actual field to determine per-header status
        if (actual == null || actual.isEmpty()) return "—";
        return deriveFromActual(actual, headerIdx, status);
    }

    private String deriveAcaoPresence(TestcaseResult r) {
        String resp = r.responseData();
        if (resp == null || resp.isEmpty()) return null;

        String headersPart = resp.contains("\r\n\r\n")
                ? resp.substring(0, resp.indexOf("\r\n\r\n"))
                : (resp.contains("\n\n") ? resp.substring(0, resp.indexOf("\n\n")) : resp);

        for (String line : headersPart.split("\\r?\\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("access-control-allow-origin:")) {
                return "PRESENT";
            }
        }
        return "MISSING";
    }

    private String deriveAcaoChecks(TestcaseResult r) {
        if (r.status() != com.securityheaders.testcase.ResultStatus.PASS
                && r.status() != com.securityheaders.testcase.ResultStatus.FAIL) return "—";
        String resp = r.responseData();
        if (resp == null || resp.isEmpty()) return "—";

        String headersPart = resp.contains("\r\n\r\n")
                ? resp.substring(0, resp.indexOf("\r\n\r\n"))
                : (resp.contains("\n\n") ? resp.substring(0, resp.indexOf("\n\n")) : resp);

        String acaoValue = null;
        for (String line : headersPart.split("\\r?\\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("access-control-allow-origin:")) {
                acaoValue = line.substring("access-control-allow-origin:".length()).trim();
                break;
            }
        }

        if (acaoValue == null) return "—";

        if ("*".equals(acaoValue)) return "FAIL";
        if ("null".equalsIgnoreCase(acaoValue)) return "FAIL";

        String reqData = r.requestData();
        if (reqData != null && !reqData.isEmpty()) {
            String originValue = null;
            String reqHeaders = reqData.contains("\r\n\r\n")
                    ? reqData.substring(0, reqData.indexOf("\r\n\r\n"))
                    : (reqData.contains("\n\n") ? reqData.substring(0, reqData.indexOf("\n\n")) : reqData);
            for (String line : reqHeaders.split("\\r?\\n")) {
                if (line.toLowerCase(Locale.ROOT).startsWith("origin:")) {
                    originValue = line.substring("origin:".length()).trim();
                    break;
                }
            }
            if (originValue != null && !originValue.isEmpty()
                    && acaoValue.equalsIgnoreCase(originValue)) {
                return "FAIL";
            }
        }

        return "PASS";
    }

    private String deriveAcaoFromResponse(TestcaseResult r) {
        String resp = r.responseData();
        if (resp == null || resp.isEmpty()) return null;

        String headersPart = resp.contains("\r\n\r\n")
                ? resp.substring(0, resp.indexOf("\r\n\r\n"))
                : (resp.contains("\n\n") ? resp.substring(0, resp.indexOf("\n\n")) : resp);

        String acaoValue = null;
        for (String line : headersPart.split("\\r?\\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("access-control-allow-origin:")) {
                acaoValue = line.substring("access-control-allow-origin:".length()).trim();
                break;
            }
        }

        if (acaoValue == null) return "MISSING";

        if ("*".equals(acaoValue)) return "FAIL";
        if ("null".equalsIgnoreCase(acaoValue)) return "FAIL";

        String reqData = r.requestData();
        if (reqData != null && !reqData.isEmpty()) {
            String originValue = null;
            String reqHeaders = reqData.contains("\r\n\r\n")
                    ? reqData.substring(0, reqData.indexOf("\r\n\r\n"))
                    : (reqData.contains("\n\n") ? reqData.substring(0, reqData.indexOf("\n\n")) : reqData);
            for (String line : reqHeaders.split("\\r?\\n")) {
                if (line.toLowerCase(Locale.ROOT).startsWith("origin:")) {
                    originValue = line.substring("origin:".length()).trim();
                    break;
                }
            }
            if (originValue != null && !originValue.isEmpty()
                    && acaoValue.equalsIgnoreCase(originValue)) {
                return "FAIL";
            }
        }

        return "PASS";
    }

    private String deriveFromActual(String actual, int headerIdx, String overallStatus) {
        if (actual == null || actual.isEmpty()) return "—";

        String actualLower = actual.toLowerCase(Locale.ROOT);

        // "All present" or "All match" → all headers pass
        if (actualLower.contains("all present") || actualLower.contains("all match")
                || actualLower.contains("no duplicates") || actualLower.contains("no wildcards")
                || actualLower.contains("no unsafe wildcard")) {
            if (headerIdx == 2 && actualLower.contains("xfo covered")) return "COVERED";
            return "PASS";
        }

        // "N/A" → not tested
        if ("n/a".equals(actualLower) || actualLower.startsWith("n/a")) {
            return overallStatus;
        }

        // "Missing: header1, header2" pattern
        if (actualLower.startsWith("missing:") || actualLower.contains("missing:")) {
            String missingPart = actualLower.contains("missing:") ?
                    actualLower.substring(actualLower.indexOf("missing:") + "missing:".length()) : actualLower;
            return missingPart.contains(HEADER_KEYS[headerIdx]) ? "FAIL" : "PASS";
        }

        // Check if specific header is mentioned in issues
        if (actualLower.contains(HEADER_KEYS[headerIdx])) {
            return "FAIL";
        }

        // For ACAO-specific results in ACAO column
        if (headerIdx == 4 && (actualLower.contains("acao") || actualLower.contains("access-control"))) {
            return overallStatus;
        }

        // Default: if overall status is PASS, all headers pass
        if ("PASS".equals(overallStatus)) return "PASS";
        if ("NOT_TESTED".equals(overallStatus) || "UNSUPPORTED".equals(overallStatus)) return overallStatus;

        return "—";
    }
}
