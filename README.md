# SecHedr — Burp Suite Security Headers Extension

A Burp Suite extension that passively and actively analyzes HTTP security headers across your target application. It identifies missing, misconfigured, or weak security headers in real-time as you browse, with 108 built-in testcases covering OWASP best practices.

---

## Features

### Header Analysis
- Checks 6 critical security headers on every response:
  - `Strict-Transport-Security` (HSTS)
  - `Cache-Control`
  - `X-Frame-Options` (XFO)
  - `X-Content-Type-Options` (XCTO)
  - `Access-Control-Allow-Origin` (ACAO)
  - `Content-Security-Policy` (CSP)
- Detects when CSP `frame-ancestors` covers the role of X-Frame-Options
- Deduplicates requests — each unique endpoint is checked only once

### Scanning Engines
| Engine | Description |
|--------|-------------|
| **Passive** | Automatically analyzes every proxied response without sending additional traffic |
| **Active** | Sends modified requests (method variations, origin injection, path mutations, etc.) to test header behavior |

Both engines can be toggled independently from the toolbar.

### 108 Built-in Testcases

| Category | IDs | What it Tests |
|----------|-----|---------------|
| Endpoint / Content Type | TC-HDR-001 → 011 | Headers on HTML, JSON, CSS, JS, images, fonts, downloads, auth, health, webhooks, GraphQL |
| HTTP Status Codes | TC-STATUS-* | Headers across 27 status codes (2xx, 3xx, 4xx, 5xx) |
| Redirect Chain | TC-REDIRECT-001 | Headers at each hop in a redirect chain |
| Path / Query Variations | TC-PATH-001 → 006 | Root path, traversal, trailing slash, 404, query params, encoding |
| HTTP Methods | TC-METHOD-* | Headers for GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT, QUERY |
| CORS / Origin | TC-ACAO-001 → 008 | No origin, approved, unapproved, attacker, null, subdomain, scheme, port |
| User-Agent Variations | TC-UA-001 → 006 | Different browser/bot user agents |
| Authentication / Cookies | TC-COOKIE-001 → 005 | Cookie-related header behavior |
| Header Validation | Edge Cases | Malformed, duplicate, and boundary-condition headers |

Testcases can also be imported from an Excel workbook.

---

## Tabs Overview

| Tab | Purpose |
|-----|---------|
| **Raw Results** | Every captured HTTP response with per-header present/missing status |
| **Host Summary** | Aggregated stats per domain — response count, unique endpoints, per-header missing counts |
| **Endpoint Summary** | Aggregated stats per endpoint (host + method + path) — all status codes seen, per-header missing counts |
| **Testcase Results** | Output from passive and active scanning engines — testcase ID, result (PASS/FAIL/ERROR), endpoint |
| **Repeater Requests** | Header analysis for Repeater-only traffic, kept separate from proxy captures (no testcases) |
| **Testcase Catalog** | Reference list of all 108 testcases with ID, name, description, category, and mode |
| **Scope & Export** | Burp-style allowlist/blocklist scope tables + CSV/ZIP export |

---

## Installation

### Pre-built JAR
1. Download `burp-security-headers-4.0.0.jar` from the `target/` folder
2. Open Burp Suite → **Extensions** → **Installed** → **Add**
3. Set Extension type to **Java**
4. Select the downloaded JAR file
5. The **SecHedr** tab appears in Burp's tab bar

### Build from Source
**Requirements:** Java 17+, Maven 3.6+

```bash
git clone https://github.com/kjayavardhan02/SecHedr-Burp-Extension.git
cd SecHedr-Burp-Extension
mvn clean package
```

The fat JAR is generated at `target/burp-security-headers-4.0.0.jar`.

---

## Usage

### 1. Set Scope
Go to **Scope & Export** tab → add target hosts to the **Include in scope** table.
- Supports wildcards: `*.example.com` matches all subdomains
- Blocklist takes precedence over allowlist
- If allowlist is empty, all hosts are in scope

### 2. Browse
Browse your target application through Burp's proxy. SecHedr automatically:
- Captures every unique response in **Raw Results**
- Runs passive testcases against each response
- Triggers active testcases for discovered endpoints
- Builds summaries in **Host Summary** and **Endpoint Summary**

### 3. Review
- Click any row to view the full **raw request and response** in a split pane
- Use **arrow keys** to navigate between results while the viewer is open
- Use filters (auto-applied on selection) to narrow down results by host, status code, or missing header
- Press **Enter** in any search field to filter by text

### 4. Export
From the **Scope & Export** tab:
- **Filtered Raw CSV** — exports currently filtered results
- **All Raw CSV** — exports all captured results
- **Testcase CSV** — exports testcase results
- **All Datasets ZIP** — everything bundled in one archive

---

## UI Controls

| Control | Location | Function |
|---------|----------|----------|
| **Passive Scan** | Top-right banner | Toggle passive scanning engine on/off |
| **Active Scan** | Top-right banner | Toggle active scanning engine on/off |
| **Enabled** | Top-right banner | Master switch — pause/resume all capture |
| **Clear** | Top-right banner | Wipe all results, summaries, and testcase data |

> Disabling Passive/Active scan only stops testcases. Basic header presence checks always run while Enabled is on.

---

## Summary Cards

The dashboard shows 8 live counters at the top:

| Card | Meaning |
|------|---------|
| Responses | Total HTTP responses analyzed |
| Missing Headers | Responses with at least one missing header |
| Hosts | Unique domains observed |
| Missing Total | Sum of all individual missing header occurrences |
| Testcases | Total testcase executions |
| Passed | Testcases that passed |
| Failed | Testcases that failed |
| Errors | Testcases that errored or were inconclusive |

---

## Tech Stack

- **Java 17** — Burp Montoya API v2025.5
- **Swing** — Custom dark UI with blue-accent theme
- **Apache POI** — Excel workbook import for testcases
- **Maven Shade** — Fat JAR packaging

---

## Project Structure

```
src/main/java/com/securityheaders/
├── SecurityHeadersExtension.java    # Entry point — registers handler + tab
├── SecurityHeadersTab.java          # Full Swing UI (tabs, filters, popups)
├── HeaderCheckHttpHandler.java      # HTTP handler — intercepts proxy/repeater traffic
├── HeaderResult.java                # Data model for a single header check result
├── ResultStore.java                 # Thread-safe result storage
├── ResultsTableModel.java           # Table model for Raw Results / Repeater
├── HostSummary.java                 # Aggregated host-level stats
├── HostSummaryTableModel.java       # Table model for Host Summary
├── EndpointSummary.java             # Aggregated endpoint-level stats
├── EndpointSummaryTableModel.java   # Table model for Endpoint Summary
├── TestcaseResultsTableModel.java   # Table model for Testcase Results
├── ScopeManager.java                # Allowlist/blocklist host matching
├── FilterState.java                 # Filter configuration object
├── ResultFilterService.java         # Applies filters to result lists
├── SummaryService.java              # Computes host/endpoint summaries
├── SummaryStats.java                # Dashboard card stats
├── CsvExportService.java            # CSV + ZIP export
└── testcase/
    ├── TestcaseLibrary.java         # 108 built-in testcase definitions
    ├── TestcaseDefinition.java      # Testcase data model
    ├── PassiveEngine.java           # Passive analysis engine
    ├── ActiveRunner.java            # Active scanning engine
    ├── TestcaseResult.java          # Testcase execution result
    ├── TestcaseResultStore.java     # Stores testcase results
    ├── TestcaseSelector.java        # Testcase enable/disable control
    ├── BaselineEvaluator.java       # Evaluates against approved baselines
    ├── ApprovedBaseline.java        # Baseline rule definitions
    ├── EndpointRegistry.java        # Tracks observed endpoints
    ├── WorkbookImporter.java        # Excel testcase importer
    ├── ExecutionMode.java           # PASSIVE / ACTIVE enum
    ├── ResultStatus.java            # PASS / FAIL / ERROR enum
    └── SupportStatus.java           # Support status enum
```

---

## License

This project is provided as-is for security testing and educational purposes.
