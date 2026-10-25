# SecHedr — Burp Suite Security Headers Extension

A Burp Suite extension that passively and actively analyzes HTTP security headers across your target application. It identifies missing, misconfigured, or weak security headers in real-time as you browse, with 104 built-in testcases covering OWASP best practices.

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

### ACAO Validation
- Detects insecure CORS configurations beyond simple presence checks:
  - Wildcard `*` in Access-Control-Allow-Origin
  - Reflected Origin (server mirrors the request Origin header)
  - `null` value in ACAO
- ACAO Checks column in Raw Results, Repeater, and Testcase Results tabs shows PASS/FAIL
- ACAO Fail count in Host Summary tab

### Scanning Engines
| Engine | Description |
|--------|-------------|
| **Passive** | Automatically analyzes every proxied response without sending additional traffic |
| **Active** | Sends modified requests (method variations, origin injection, path mutations, etc.) to test header behavior |

Both engines can be toggled independently from the toolbar.

### 104 Built-in Testcases

| Category | IDs | What it Tests |
|----------|-----|---------------|
| Endpoint / Content Type | TC-HDR-001 → 011 | Headers on HTML, JSON, CSS, JS, images, fonts, downloads, auth, health, webhooks, GraphQL |
| HTTP Status Codes | TC-STATUS-* | Headers across 27 status codes (2xx, 3xx, 4xx, 5xx) |
| Redirect Chain | TC-REDIRECT-001 | Headers at each hop in a redirect chain |
| Path / Query Variations | TC-PATH-001 → 006 | Root path, traversal, trailing slash, 404, query params, encoding |
| HTTP Methods | TC-METHOD-* | Headers for GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT, QUERY |
| CORS / Origin | TC-ACAO-001 → 008, TC-CORS-001 → 005 | No origin, approved, unapproved, attacker, null, subdomain, scheme, port, credentials, preflight |
| User-Agent Variations | TC-UA-001 → 006 | Desktop, mobile, bot, cURL, empty, absent user agents |
| Sec-Fetch | TC-SECFETCH-001 → 004 | Navigate, cors, cross-site iframe, all removed |
| Referer | TC-REFERER-001 → 005 | Absent, same-origin, cross-origin, suspicious, empty |
| Forwarded Headers | TC-XFP/XFH/XFF-* | X-Forwarded-Proto, X-Forwarded-Host, X-Forwarded-For variations |
| Authentication / Cookies | TC-COOKIE-001 → 005, TC-AUTH-001 → 003 | No cookie, tampered, expired, unknown, malformed, auth comparison |
| Header Validation | TC-EDGE-001 → 005 | Duplicate headers, exact syntax, wildcards, error-page conflicts |

Testcases can also be imported from an Excel workbook.

---

## Tabs Overview

| Tab | Purpose |
|-----|---------|
| **Dashboard** | Live KPI cards (scan overview, header coverage bars, security posture, scan health), auto-refreshes every 5 seconds |
| **Raw Results** | Every captured HTTP response with per-header present/missing status and ACAO Checks |
| **Host Summary** | Aggregated stats per domain — unique endpoints, per-header missing counts, ACAO Fail count |
| **Endpoint Summary** | Aggregated stats per endpoint — request count, status codes, per-header missing counts, testcase execution counts (Passive TC, Active TC, Not Executed) |
| **Repeater Requests** | Header analysis for Repeater-only traffic, kept separate from proxy captures |
| **Testcase Catalog** | Reference list of all 104 testcases with ID, name, description, category, and mode (Passive/Active) |
| **Testcase Results** | Output from passive and active scanning engines with per-header and ACAO Checks status |
| **Scope & Export** | Burp-style allowlist/blocklist scope tables + CSV export |

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
- Updates the **Dashboard** every 5 seconds with live metrics

### 3. Review
- Click any row to view the full **raw request and response headers** in a split pane
- Use **arrow keys** to navigate between results while the viewer is open
- Use filters (host, status code, header) to narrow down results — default filter is "None"
- "Any Missing" filter shows responses with at least one missing header
- "All Missing" filter shows responses where every header is missing
- Press **Enter** in any search field to filter by text

### 4. Export
From the **Scope & Export** tab:
- **Filtered Raw Results CSV** — exports currently filtered results
- **Raw Results CSV** — exports all captured results
- **Testcase Results CSV** — exports testcase results

---

## Dashboard

The dashboard provides a real-time overview with four sections:

### Scan Overview
| Card | Meaning |
|------|---------|
| Hosts | Unique domains observed |
| Endpoints | Unique endpoints assessed |
| Assessed | Total HTTP responses analyzed |
| Testcases | Total testcase executions |
| Missing | Responses with at least one missing header |
| Errors | Testcases that errored |

### Header Coverage
Six progress bars showing per-header presence rates across all responses (HSTS, Cache-Control, XFO, XCTO, ACAO, CSP). Click any bar to filter Raw Results by that header.

### Security Posture
| Card | Meaning |
|------|---------|
| Affected Endpoints | Unique endpoints with at least one missing header (click to filter) |
| Fully Compliant | Unique endpoints with all headers present (click to filter) |
| Header Compliance | Overall percentage: passed header checks / total checks |

### Scan Health
| Card | Meaning |
|------|---------|
| Processed | Total requests processed by the handler |
| Checks/min | Rolling throughput over the last 60 seconds |
| Heap Used | JVM heap memory usage |
| Elapsed | Time since scan started |
| Last Update | Time since last processed request |
| TC Errors | Total testcase errors |

---

## UI Controls

| Control | Location | Function |
|---------|----------|----------|
| **Passive Scan** | Top-right banner | Toggle passive scanning engine on/off |
| **Active Scan** | Top-right banner | Toggle active scanning engine on/off |
| **Enabled** | Top-right banner | Master switch — pause/resume all capture |
| **Clear** | Top-right banner (red) | Wipe all results, summaries, and testcase data (with confirmation dialog) |

> Disabling Passive/Active scan only stops testcases. Basic header presence checks always run while Enabled is on.

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
├── SecurityHeadersTab.java          # Full Swing UI (tabs, filters, dashboard, popups)
├── HeaderCheckHttpHandler.java      # HTTP handler — intercepts proxy/repeater traffic
├── HeaderResult.java                # Data model for a single header check result
├── ResultStore.java                 # Thread-safe result storage
├── ResultsTableModel.java           # Table model for Raw Results / Repeater
├── HostSummary.java                 # Aggregated host-level stats
├── HostSummaryTableModel.java       # Table model for Host Summary
├── EndpointSummary.java             # Aggregated endpoint-level stats
├── EndpointSummaryTableModel.java   # Table model for Endpoint Summary
├── TestcaseResultsTableModel.java   # Table model for Testcase Results
├── ScanHealthTracker.java           # Tracks throughput, heap, errors, timing
├── ScopeManager.java                # Allowlist/blocklist host matching
├── FilterState.java                 # Filter configuration object
├── ResultFilterService.java         # Applies filters to result lists
├── SummaryService.java              # Computes host/endpoint summaries
├── SummaryStats.java                # Dashboard card stats
├── CsvExportService.java            # CSV export
└── testcase/
    ├── TestcaseLibrary.java         # 104 built-in testcase definitions
    ├── TestcaseDefinition.java      # Testcase data model
    ├── PassiveEngine.java           # Passive analysis engine
    ├── ActiveRunner.java            # Active scanning engine
    ├── TestcaseResult.java          # Testcase execution result
    ├── TestcaseResultStore.java     # Deduplicated testcase result storage
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
