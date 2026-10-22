package com.securityheaders;

import com.securityheaders.testcase.TestcaseResult;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class CsvExportService {

    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private static final byte[] UTF8_BOM = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};

    public void exportRawResults(File file, List<HeaderResult> results) throws IOException {
        try (OutputStream os = new FileOutputStream(file);
             BufferedWriter w = newUtf8Writer(os)) {
            w.write("Observed At,Host,Port,Method,URL (Path),Status,HSTS,Cache-Control,XFO,XCTO,ACAO,CSP");
            w.newLine();
            for (HeaderResult r : results) {
                w.write(csvField(TS_FMT.format(r.observedAt())));
                w.write(','); w.write(csvField(r.host()));
                w.write(','); w.write(String.valueOf(r.port()));
                w.write(','); w.write(csvField(r.method()));
                w.write(','); w.write(csvField(r.pathAndQuery()));
                w.write(','); w.write(String.valueOf(r.statusCode()));
                w.write(','); w.write(presence(r.hstsPresent()));
                w.write(','); w.write(presence(r.cacheControlPresent()));
                w.write(','); w.write(r.xfoCoveredByCsp() ? "COVERED" : presence(r.xfoPresent()));
                w.write(','); w.write(presence(r.xctoPresent()));
                w.write(','); w.write(presence(r.acaoPresent()));
                w.write(','); w.write(presence(r.cspPresent()));
                w.newLine();
            }
        }
    }

    public void exportHostSummary(File file, List<HostSummary> summaries) throws IOException {
        try (OutputStream os = new FileOutputStream(file);
             BufferedWriter w = newUtf8Writer(os)) {
            w.write("Host,Responses,Unique Endpoints,Responses with Missing Headers,"
                    + "HSTS Missing,Cache-Control Missing,XFO Missing,XCTO Missing,ACAO Missing,CSP Missing");
            w.newLine();
            for (HostSummary h : summaries) {
                w.write(csvField(h.host()));
                w.write(','); w.write(String.valueOf(h.responses()));
                w.write(','); w.write(String.valueOf(h.uniqueEndpoints()));
                w.write(','); w.write(String.valueOf(h.responsesWithMissing()));
                w.write(','); w.write(String.valueOf(h.hstsMissing()));
                w.write(','); w.write(String.valueOf(h.cacheControlMissing()));
                w.write(','); w.write(String.valueOf(h.xfoMissing()));
                w.write(','); w.write(String.valueOf(h.xctoMissing()));
                w.write(','); w.write(String.valueOf(h.acaoMissing()));
                w.write(','); w.write(String.valueOf(h.cspMissing()));
                w.newLine();
            }
        }
    }

    public void exportEndpointSummary(File file, List<EndpointSummary> summaries) throws IOException {
        try (OutputStream os = new FileOutputStream(file);
             BufferedWriter w = newUtf8Writer(os)) {
            w.write("Host,Port,Method,URL (Path),Responses,Status Codes,"
                    + "Responses with Missing Headers,HSTS Missing,Cache-Control Missing,"
                    + "XFO Missing,XCTO Missing,ACAO Missing,CSP Missing,Headers Ever Missing");
            w.newLine();
            for (EndpointSummary ep : summaries) {
                w.write(csvField(ep.host()));
                w.write(','); w.write(String.valueOf(ep.port()));
                w.write(','); w.write(csvField(ep.method()));
                w.write(','); w.write(csvField(ep.pathAndQuery()));
                w.write(','); w.write(String.valueOf(ep.responses()));
                w.write(','); w.write(csvField(
                        ep.statusCodes().stream().map(String::valueOf).collect(Collectors.joining("; "))));
                w.write(','); w.write(String.valueOf(ep.responsesWithMissing()));
                w.write(','); w.write(String.valueOf(ep.hstsMissing()));
                w.write(','); w.write(String.valueOf(ep.cacheControlMissing()));
                w.write(','); w.write(String.valueOf(ep.xfoMissing()));
                w.write(','); w.write(String.valueOf(ep.xctoMissing()));
                w.write(','); w.write(String.valueOf(ep.acaoMissing()));
                w.write(','); w.write(String.valueOf(ep.cspMissing()));
                w.write(','); w.write(csvField(String.join("; ", ep.headersEverMissing())));
                w.newLine();
            }
        }
    }

    public void exportTestcaseResults(File file, List<TestcaseResult> results) throws IOException {
        try (OutputStream os = new FileOutputStream(file);
             BufferedWriter w = newUtf8Writer(os)) {
            w.write("Result ID,Testcase ID,Host,Path,Status Code,Mode,Status,Summary,Expected,Actual,Evidence,Error,Observed At,Completed At");
            w.newLine();
            for (TestcaseResult r : results) {
                w.write(String.valueOf(r.resultId()));
                w.write(','); w.write(csvField(r.testcaseId()));
                w.write(','); w.write(csvField(r.host()));
                w.write(','); w.write(csvField(r.pathAndQuery()));
                w.write(','); w.write(String.valueOf(r.statusCode()));
                w.write(','); w.write(r.mode().name());
                w.write(','); w.write(r.status().name());
                w.write(','); w.write(csvField(r.summary()));
                w.write(','); w.write(csvField(r.expected()));
                w.write(','); w.write(csvField(r.actual()));
                w.write(','); w.write(csvField(r.evidence()));
                w.write(','); w.write(csvField(r.errorDetails() != null ? r.errorDetails() : ""));
                w.write(','); w.write(csvField(TS_FMT.format(r.observedAt())));
                w.write(','); w.write(csvField(TS_FMT.format(r.completedAt())));
                w.newLine();
            }
        }
    }

    public void exportAllZip(File file, List<HeaderResult> rawResults,
                             List<HostSummary> hostSummaries,
                             List<EndpointSummary> endpointSummaries) throws IOException {
        exportAllZipWithTestcases(file, rawResults, hostSummaries, endpointSummaries, List.of());
    }

    public void exportAllZipWithTestcases(File file, List<HeaderResult> rawResults,
                             List<HostSummary> hostSummaries,
                             List<EndpointSummary> endpointSummaries,
                             List<TestcaseResult> testcaseResults) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(
                new BufferedOutputStream(new FileOutputStream(file)), StandardCharsets.UTF_8)) {
            zos.putNextEntry(new ZipEntry("raw_results.csv"));
            writeRawResultsToStream(zos, rawResults);
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("host_summary.csv"));
            writeHostSummaryToStream(zos, hostSummaries);
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("endpoint_summary.csv"));
            writeEndpointSummaryToStream(zos, endpointSummaries);
            zos.closeEntry();

            if (testcaseResults != null && !testcaseResults.isEmpty()) {
                zos.putNextEntry(new ZipEntry("testcase_results.csv"));
                writeTestcaseResultsToStream(zos, testcaseResults);
                zos.closeEntry();
            }
        }
    }

    private void writeRawResultsToStream(OutputStream os, List<HeaderResult> results) throws IOException {
        BufferedWriter w = newUtf8WriterNoClose(os);
        w.write("Observed At,Host,Port,Method,URL (Path),Status,HSTS,Cache-Control,XFO,XCTO,ACAO,CSP");
        w.newLine();
        for (HeaderResult r : results) {
            w.write(csvField(TS_FMT.format(r.observedAt())));
            w.write(','); w.write(csvField(r.host()));
            w.write(','); w.write(String.valueOf(r.port()));
            w.write(','); w.write(csvField(r.method()));
            w.write(','); w.write(csvField(r.pathAndQuery()));
            w.write(','); w.write(String.valueOf(r.statusCode()));
            w.write(','); w.write(presence(r.hstsPresent()));
            w.write(','); w.write(presence(r.cacheControlPresent()));
            w.write(','); w.write(r.xfoCoveredByCsp() ? "COVERED" : presence(r.xfoPresent()));
            w.write(','); w.write(presence(r.xctoPresent()));
            w.write(','); w.write(presence(r.acaoPresent()));
            w.write(','); w.write(presence(r.cspPresent()));
            w.newLine();
        }
        w.flush();
    }

    private void writeHostSummaryToStream(OutputStream os, List<HostSummary> summaries) throws IOException {
        BufferedWriter w = newUtf8WriterNoClose(os);
        w.write("Host,Responses,Unique Endpoints,Responses with Missing Headers,"
                + "HSTS Missing,Cache-Control Missing,XFO Missing,XCTO Missing,ACAO Missing,CSP Missing");
        w.newLine();
        for (HostSummary h : summaries) {
            w.write(csvField(h.host()));
            w.write(','); w.write(String.valueOf(h.responses()));
            w.write(','); w.write(String.valueOf(h.uniqueEndpoints()));
            w.write(','); w.write(String.valueOf(h.responsesWithMissing()));
            w.write(','); w.write(String.valueOf(h.hstsMissing()));
            w.write(','); w.write(String.valueOf(h.cacheControlMissing()));
            w.write(','); w.write(String.valueOf(h.xfoMissing()));
            w.write(','); w.write(String.valueOf(h.xctoMissing()));
            w.write(','); w.write(String.valueOf(h.acaoMissing()));
            w.write(','); w.write(String.valueOf(h.cspMissing()));
            w.newLine();
        }
        w.flush();
    }

    private void writeEndpointSummaryToStream(OutputStream os, List<EndpointSummary> summaries) throws IOException {
        BufferedWriter w = newUtf8WriterNoClose(os);
        w.write("Host,Port,Method,URL (Path),Responses,Status Codes,"
                + "Responses with Missing Headers,HSTS Missing,Cache-Control Missing,"
                + "XFO Missing,XCTO Missing,ACAO Missing,CSP Missing,Headers Ever Missing");
        w.newLine();
        for (EndpointSummary ep : summaries) {
            w.write(csvField(ep.host()));
            w.write(','); w.write(String.valueOf(ep.port()));
            w.write(','); w.write(csvField(ep.method()));
            w.write(','); w.write(csvField(ep.pathAndQuery()));
            w.write(','); w.write(String.valueOf(ep.responses()));
            w.write(','); w.write(csvField(
                    ep.statusCodes().stream().map(String::valueOf).collect(Collectors.joining("; "))));
            w.write(','); w.write(String.valueOf(ep.responsesWithMissing()));
            w.write(','); w.write(String.valueOf(ep.hstsMissing()));
            w.write(','); w.write(String.valueOf(ep.cacheControlMissing()));
            w.write(','); w.write(String.valueOf(ep.xfoMissing()));
            w.write(','); w.write(String.valueOf(ep.xctoMissing()));
            w.write(','); w.write(String.valueOf(ep.acaoMissing()));
            w.write(','); w.write(String.valueOf(ep.cspMissing()));
            w.write(','); w.write(csvField(String.join("; ", ep.headersEverMissing())));
            w.newLine();
        }
        w.flush();
    }

    private void writeTestcaseResultsToStream(OutputStream os, List<TestcaseResult> results) throws IOException {
        BufferedWriter w = newUtf8WriterNoClose(os);
        w.write("Result ID,Testcase ID,Host,Path,Status Code,Mode,Status,Summary,Expected,Actual,Evidence,Error,Observed At,Completed At");
        w.newLine();
        for (TestcaseResult r : results) {
            w.write(String.valueOf(r.resultId()));
            w.write(','); w.write(csvField(r.testcaseId()));
            w.write(','); w.write(csvField(r.host()));
            w.write(','); w.write(csvField(r.pathAndQuery()));
            w.write(','); w.write(String.valueOf(r.statusCode()));
            w.write(','); w.write(r.mode().name());
            w.write(','); w.write(r.status().name());
            w.write(','); w.write(csvField(r.summary()));
            w.write(','); w.write(csvField(r.expected()));
            w.write(','); w.write(csvField(r.actual()));
            w.write(','); w.write(csvField(r.evidence()));
            w.write(','); w.write(csvField(r.errorDetails() != null ? r.errorDetails() : ""));
            w.write(','); w.write(csvField(TS_FMT.format(r.observedAt())));
            w.write(','); w.write(csvField(TS_FMT.format(r.completedAt())));
            w.newLine();
        }
        w.flush();
    }

    private BufferedWriter newUtf8Writer(OutputStream os) throws IOException {
        os.write(UTF8_BOM);
        return new BufferedWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8));
    }

    private BufferedWriter newUtf8WriterNoClose(OutputStream os) throws IOException {
        os.write(UTF8_BOM);
        return new BufferedWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8) {
            @Override public void close() { /* don't close underlying stream */ }
        });
    }

    static String csvField(String value) {
        if (value == null) return "";
        String safe = sanitizeFormulaInjection(value);
        if (safe.contains(",") || safe.contains("\"") || safe.contains("\n") || safe.contains("\r")) {
            return "\"" + safe.replace("\"", "\"\"") + "\"";
        }
        return safe;
    }

    private static String sanitizeFormulaInjection(String value) {
        if (value.isEmpty()) return value;
        char first = value.charAt(0);
        if (first == '=' || first == '+' || first == '-' || first == '@'
                || first == '\t' || first == '\r') {
            return "'" + value;
        }
        return value;
    }

    private static String presence(boolean present) {
        return present ? "PRESENT" : "MISSING";
    }
}
