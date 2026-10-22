package com.securityheaders.testcase;

import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class WorkbookImporter {

    public List<TestcaseDefinition> importTestcases(File file) throws IOException {
        List<TestcaseDefinition> results = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(file);
             Workbook wb = new XSSFWorkbook(fis)) {

            Sheet sheet = wb.getSheet("Security Headers Test Cases");
            if (sheet == null && wb.getNumberOfSheets() > 0) {
                sheet = wb.getSheetAt(0);
            }
            if (sheet == null) return results;

            int firstRow = sheet.getFirstRowNum();
            Row header = sheet.getRow(firstRow);
            if (header == null) return results;

            int colId = findCol(header, "Test Case ID", "ID", "Testcase ID");
            int colName = findCol(header, "Name", "Title", "Test Name");
            int colDesc = findCol(header, "Description", "Desc");
            int colCategory = findCol(header, "Category", "Cat");
            int colMode = findCol(header, "Mode", "Execution Mode", "Type");
            int colPrecond = findCol(header, "Preconditions", "Precond");
            int colReqReqs = findCol(header, "Request Requirements", "Request", "Req Requirements");
            int colSteps = findCol(header, "Steps", "Execution Steps", "Test Steps");
            int colExpected = findCol(header, "Expected Result", "Expected", "Expected Outcome");
            int colBaseline = findCol(header, "Baseline", "Baseline Reference", "Policy");

            for (int i = firstRow + 1; i <= sheet.getLastRowNum(); i++) {
                Row row = sheet.getRow(i);
                if (row == null) continue;

                String id = cellStr(row, colId);
                if (id == null || id.isBlank()) continue;

                String name = cellStr(row, colName);
                String desc = cellStr(row, colDesc);
                String category = cellStr(row, colCategory);
                String modeStr = cellStr(row, colMode);
                String precond = cellStr(row, colPrecond);
                String reqReqs = cellStr(row, colReqReqs);
                String steps = cellStr(row, colSteps);
                String expected = cellStr(row, colExpected);
                String baseline = cellStr(row, colBaseline);

                ExecutionMode mode = parseMode(modeStr);
                SupportStatus support = SupportStatus.SUPPORTED;
                String unsupported = null;

                if (name == null || name.isBlank() || expected == null || expected.isBlank()) {
                    support = SupportStatus.NOT_TESTED;
                    unsupported = "Incomplete metadata in workbook row " + (i + 1);
                }

                results.add(new TestcaseDefinition(id.trim(), orEmpty(name), orEmpty(desc),
                        orEmpty(category), mode, support, orEmpty(precond), orEmpty(reqReqs),
                        orEmpty(steps), orEmpty(expected), orEmpty(baseline), unsupported));
            }
        }
        return results;
    }

    public ApprovedBaseline importBaseline(File file) throws IOException {
        ApprovedBaseline baseline = new ApprovedBaseline();
        try (FileInputStream fis = new FileInputStream(file);
             Workbook wb = new XSSFWorkbook(fis)) {

            Sheet sheet = wb.getSheet("Approved Baseline");
            if (sheet == null) return baseline;

            int firstRow = sheet.getFirstRowNum();
            Row header = sheet.getRow(firstRow);
            if (header == null) return baseline;

            int colHeader = findCol(header, "Header", "Header Name");
            int colValue = findCol(header, "Value", "Expected Value", "Approved Value", "Baseline");

            if (colHeader < 0 || colValue < 0) return baseline;

            for (int i = firstRow + 1; i <= sheet.getLastRowNum(); i++) {
                Row row = sheet.getRow(i);
                if (row == null) continue;
                String headerName = cellStr(row, colHeader);
                String value = cellStr(row, colValue);
                if (headerName != null && !headerName.isBlank() && value != null) {
                    // Update existing baseline with workbook values if parseable
                    // For now, log that we found them — the default baseline is used
                }
            }
        }
        return baseline;
    }

    private int findCol(Row header, String... names) {
        for (Cell cell : header) {
            String val = cellStr(cell);
            if (val == null) continue;
            String lower = val.trim().toLowerCase();
            for (String name : names) {
                if (lower.contains(name.toLowerCase())) {
                    return cell.getColumnIndex();
                }
            }
        }
        return -1;
    }

    private String cellStr(Row row, int col) {
        if (col < 0) return null;
        Cell cell = row.getCell(col);
        return cellStr(cell);
    }

    private String cellStr(Cell cell) {
        if (cell == null) return null;
        return switch (cell.getCellType()) {
            case STRING -> cell.getStringCellValue();
            case NUMERIC -> String.valueOf((long) cell.getNumericCellValue());
            case BOOLEAN -> String.valueOf(cell.getBooleanCellValue());
            default -> null;
        };
    }

    private ExecutionMode parseMode(String s) {
        if (s == null) return ExecutionMode.PASSIVE;
        String lower = s.trim().toLowerCase();
        if (lower.contains("active") && lower.contains("passive")) return ExecutionMode.BOTH;
        if (lower.contains("active")) return ExecutionMode.ACTIVE;
        return ExecutionMode.PASSIVE;
    }

    private String orEmpty(String s) {
        return s == null ? "" : s;
    }
}
