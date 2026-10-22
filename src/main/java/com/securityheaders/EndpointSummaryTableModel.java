package com.securityheaders;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class EndpointSummaryTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "Host", "Port", "Method", "URL (Path)", "Responses",
        "Status Codes", "With Missing",
        "HSTS Missing", "CC Missing", "XFO Missing",
        "XCTO Missing", "ACAO Missing", "CSP Missing",
        "Headers Ever Missing"
    };

    private List<EndpointSummary> data = new ArrayList<>();

    @Override
    public int getRowCount() { return data.size(); }

    @Override
    public int getColumnCount() { return COLUMNS.length; }

    @Override
    public String getColumnName(int col) { return COLUMNS[col]; }

    @Override
    public Class<?> getColumnClass(int col) {
        return switch (col) {
            case 1, 4, 6, 7, 8, 9, 10, 11, 12 -> Integer.class;
            default -> String.class;
        };
    }

    @Override
    public Object getValueAt(int row, int col) {
        EndpointSummary ep = data.get(row);
        return switch (col) {
            case 0 -> ep.host();
            case 1 -> ep.port();
            case 2 -> ep.method();
            case 3 -> ep.pathAndQuery();
            case 4 -> ep.responses();
            case 5 -> ep.statusCodes().stream().map(String::valueOf).collect(Collectors.joining(", "));
            case 6 -> ep.responsesWithMissing();
            case 7 -> ep.hstsMissing();
            case 8 -> ep.cacheControlMissing();
            case 9 -> ep.xfoMissing();
            case 10 -> ep.xctoMissing();
            case 11 -> ep.acaoMissing();
            case 12 -> ep.cspMissing();
            case 13 -> String.join(", ", ep.headersEverMissing());
            default -> "";
        };
    }

    public void setData(List<EndpointSummary> summaries) {
        this.data = new ArrayList<>(summaries);
        fireTableDataChanged();
    }

    public List<EndpointSummary> getData() { return data; }
}
