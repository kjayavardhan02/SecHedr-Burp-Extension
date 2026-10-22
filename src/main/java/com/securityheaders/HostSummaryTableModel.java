package com.securityheaders;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class HostSummaryTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "Host", "Responses", "Unique Endpoints", "With Missing",
        "HSTS Missing", "CC Missing", "XFO Missing",
        "XCTO Missing", "ACAO Missing", "CSP Missing"
    };

    private List<HostSummary> data = new ArrayList<>();

    @Override
    public int getRowCount() { return data.size(); }

    @Override
    public int getColumnCount() { return COLUMNS.length; }

    @Override
    public String getColumnName(int col) { return COLUMNS[col]; }

    @Override
    public Class<?> getColumnClass(int col) {
        return col == 0 ? String.class : Integer.class;
    }

    @Override
    public Object getValueAt(int row, int col) {
        HostSummary h = data.get(row);
        return switch (col) {
            case 0 -> h.host();
            case 1 -> h.responses();
            case 2 -> h.uniqueEndpoints();
            case 3 -> h.responsesWithMissing();
            case 4 -> h.hstsMissing();
            case 5 -> h.cacheControlMissing();
            case 6 -> h.xfoMissing();
            case 7 -> h.xctoMissing();
            case 8 -> h.acaoMissing();
            case 9 -> h.cspMissing();
            default -> "";
        };
    }

    public void setData(List<HostSummary> summaries) {
        this.data = new ArrayList<>(summaries);
        fireTableDataChanged();
    }

    public HostSummary getRowData(int row) {
        return data.get(row);
    }

    public List<HostSummary> getData() { return data; }
}
