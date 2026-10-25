package com.securityheaders;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class HostSummaryTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "Host", "Unique Endpoints",
        "HSTS Missing", "CC Missing", "XFO Missing",
        "XCTO Missing", "ACAO Missing", "CSP Missing", "ACAO Fail"
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
            case 1 -> h.uniqueEndpoints();
            case 2 -> h.hstsMissing();
            case 3 -> h.cacheControlMissing();
            case 4 -> h.xfoMissing();
            case 5 -> h.xctoMissing();
            case 6 -> h.acaoMissing();
            case 7 -> h.cspMissing();
            case 8 -> h.acaoFail();
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
