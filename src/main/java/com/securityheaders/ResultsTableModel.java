package com.securityheaders;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class ResultsTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
        "Host", "Method", "URL (Path)", "Status Code",
        "HSTS", "Cache-Control", "XFO", "XCTO", "ACAO", "ACAO Checks", "CSP"
    };

    private List<HeaderResult> results = new ArrayList<>();

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
            default -> "";
        };
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 3) return Integer.class;
        return String.class;
    }

    public void setData(List<HeaderResult> data) {
        this.results = new ArrayList<>(data);
        fireTableDataChanged();
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
