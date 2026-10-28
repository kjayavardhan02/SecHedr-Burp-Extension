# 🛡️ SecHedr — Burp Suite Security Headers Extension

## The Problem

Web applications rely on HTTP security headers to defend against common attacks — clickjacking (`X-Frame-Options`), MIME sniffing (`X-Content-Type-Options`), man-in-the-middle (`Strict-Transport-Security`), cross-site scripting (`Content-Security-Policy`), data leaks (`Cache-Control`), and insecure cross-origin access (`Access-Control-Allow-Origin`).

In practice, these headers are frequently missing, misconfigured, or inconsistent across endpoints. A login page might have HSTS while the API doesn't. Static assets might cache sensitive data. CORS might reflect any origin. Manually checking every response across an entire application is tedious and error-prone.

## The Solution

**SecHedr** is a Burp Suite extension that **automatically analyzes every HTTP response** flowing through your proxy for six critical security headers. It runs **104 built-in testcases** covering OWASP best practices, and lets you define **custom compliance policies** with content-type-aware rules — so your HTML pages, API responses, and static assets are each validated against the right security requirements.

No manual checking. No spreadsheets. Just browse your target and get a real-time security headers audit.

---

## ⚡ Quick Start

1. Download `burp-security-headers-4.0.0.jar` from `target/`
2. Burp Suite → **Extensions** → **Add** → select the JAR
3. The **SecHedr** tab appears — set your scope and start browsing

**Build from source** (Java 17+, Maven 3.6+):
```bash
git clone https://github.com/kjayavardhan02/SecHedr-Burp-Extension.git
cd SecHedr-Burp-Extension
mvn clean package
```

---

## 🔍 Headers Analyzed

Every proxied response is checked for these six headers:

| Header | Why It Matters | What SecHedr Checks |
|--------|---------------|-------------------|
| **Strict-Transport-Security** | Forces HTTPS, prevents downgrade attacks | Presence, `max-age` value, `includeSubDomains`, `preload` |
| **Cache-Control** | Prevents browsers/proxies from storing sensitive data | Required directives (e.g. `no-store`), prohibited directives (e.g. `public`) |
| **X-Frame-Options** | Prevents clickjacking via iframe embedding | Allowed values (`DENY`, `SAMEORIGIN`), detects CSP `frame-ancestors` coverage |
| **X-Content-Type-Options** | Prevents MIME type sniffing attacks | `nosniff` value |
| **Access-Control-Allow-Origin** | Controls cross-origin resource sharing | Wildcard `*`, reflected origin, `null` value, same-origin detection |
| **Content-Security-Policy** | Restricts resource loading to prevent XSS | Required directives, prohibited sources (`unsafe-inline`, `unsafe-eval`) |

### ACAO Checks — Beyond Presence

Most tools only check if the ACAO header exists. SecHedr goes deeper:

- **Wildcard `*`** — open to all origins (flagged as FAIL)
- **Origin reflection** — server mirrors back whatever Origin was sent (FAIL)
- **`null` value** — exploitable by sandboxed iframes (FAIL)
- **Same-origin reflection** — server reflects the Origin but it matches the Host header (correctly treated as PASS, not a vulnerability)

### XFO + CSP Frame-Ancestors

When `X-Frame-Options` is absent but CSP contains a `frame-ancestors` directive, SecHedr marks XFO as **COVERED** (shown in orange in the compliance detail) rather than failing it — because `frame-ancestors` provides equivalent protection.

---

## 📋 Policy-Based Compliance

Real-world security policies aren't one-size-fits-all. An HTML page needs strict CSP and `no-store` caching, while a static image needs long cache lifetimes and doesn't need CSP at all. SecHedr lets you define this.

### How It Works

1. Go to the **Policies** tab → create a policy or use the **Default Baseline**
2. Each header section supports **content-type conditions** — different rules for different response types
3. **Activate** the policy → all results are evaluated against it in real-time
4. Policy compliance appears as a column in Raw Results, Testcase Results, and Repeater tabs
5. Click any row → the detail popup shows per-header compliance with expected vs. actual values

### Content-Type Conditions

Each condition matches responses by their `Content-Type` header and applies its own rules:

| Condition | Content-Type Pattern | Cache-Control Rule | CSP Rule |
|-----------|---------------------|-------------------|----------|
| **HTML Pages** | `text/html` | Required: `no-store` | Required: `default-src, script-src`; Prohibited: `unsafe-inline, unsafe-eval` |
| **API Responses** | `application/json` | Required: `no-store, no-cache` | Not applicable |
| **Static Assets** | `image/*, text/css, application/javascript` | Required: `public`; Prohibited: `no-store` | Not applicable |

- Content-type patterns support wildcards (`image/*` matches `image/png`, `image/jpeg`, etc.)
- Responses that don't match any condition get **N/A** — no false failures
- Conditions are independently configurable for Cache-Control and CSP
- HSTS, XFO, XCTO, and ACAO rules apply globally (not content-type dependent)

---

## 🧪 104 Built-in Testcases

SecHedr ships with 104 testcases organized by category. Each testcase sends a specific request variation and analyzes the response headers.

| Category | IDs | What It Tests |
|----------|-----|---------------|
| **Content Type** | HDR-001 → 011 | Headers on HTML, JSON, CSS, JS, images, fonts, downloads, auth, health, webhooks, GraphQL |
| **Status Codes** | STATUS-* | Headers across 27 status codes (2xx, 3xx, 4xx, 5xx) |
| **Redirect Chain** | REDIRECT-001 | Headers at each hop in a redirect chain |
| **Path Variations** | PATH-001 → 006 | Root path, traversal, trailing slash, 404, query params, encoding |
| **HTTP Methods** | METHOD-* | GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT, QUERY |
| **CORS / Origin** | ACAO-001 → 008, CORS-001 → 005 | No origin, approved, unapproved, attacker, null, subdomain, scheme, port, credentials, preflight |
| **User-Agent** | UA-001 → 006 | Desktop, mobile, bot, cURL, empty, absent |
| **Sec-Fetch** | SECFETCH-001 → 004 | Navigate, cors, cross-site iframe, all removed |
| **Referer** | REFERER-001 → 005 | Absent, same-origin, cross-origin, suspicious, empty |
| **Forwarded Headers** | XFP/XFH/XFF-* | X-Forwarded-Proto, X-Forwarded-Host, X-Forwarded-For variations |
| **Auth / Cookies** | COOKIE-001 → 005, AUTH-001 → 003 | No cookie, tampered, expired, unknown, malformed, auth comparison |
| **Edge Cases** | EDGE-001 → 005 | Duplicate headers, exact syntax, wildcards, error-page conflicts |

### Scanning Modes

| Mode | How It Works |
|------|-------------|
| **Passive** | Analyzes every proxied response without sending any extra traffic. Zero noise. |
| **Active** | Sends modified requests — method variations, origin injection, path mutations — to test how the server behaves under different conditions. |

Both modes run independently and can be toggled from the toolbar. Passive is always safe; Active generates additional requests.

Testcases can also be imported from an **Excel workbook** for custom test suites.

---

## 📊 Tabs

### Dashboard
Live metrics that auto-refresh every 5 seconds:

- **Scan Overview** — hosts, endpoints, responses assessed, testcases run, missing headers, errors
- **Header Coverage** — progress bars showing header presence across raw results and testcase results, plus an ACAO Checks bar
- **Security Posture** — affected vs. compliant endpoints, overall compliance percentage
- **Scan Health** — throughput (checks/min), heap usage, elapsed time, last update

### Raw Results
Every captured HTTP response in a sortable, filterable table. Columns include per-header present/missing status, ACAO Checks (PASS/FAIL), and Policy Compliance. Click any row to open a split pane with full request/response headers and policy compliance detail.

**Filters:** host, status code, per-header missing, text search, "Any Missing", "All Missing".

### Host Summary
Aggregated per-domain view — unique endpoints, per-header missing counts, ACAO failure count.

### Repeater Requests
Header analysis for Repeater traffic, kept separate from proxy captures. Same columns and detail popup as Raw Results, with policy compliance.

### Testcase Catalog
Reference list of all 104 testcases — ID, description, category, mode (Passive/Active).

### Testcase Results
Output from the scanning engines. Each row shows the testcase ID, host, path, status, per-header status, ACAO Checks, and policy compliance. Click for full detail.

### Policies
Create, edit, duplicate, and activate compliance policies. The editor provides per-header configuration:
- **HSTS** — min max-age, require includeSubDomains, require preload
- **Cache-Control** — content-type conditions with required/prohibited directives
- **XFO** — allowed values
- **XCTO** — expected value
- **ACAO** — allowed origins, wildcard/null toggles
- **CSP** — content-type conditions with required directives and prohibited sources

### Scope & Export
- **Scope** — Burp-style include/exclude tables with wildcard support (`*.example.com`)
- **Export** — CSV export for raw results, filtered results, and testcase results

---

## 🖱️ UI Controls

| Control | Function |
|---------|----------|
| **Passive Scan** | Toggle passive scanning on/off |
| **Active Scan** | Toggle active scanning on/off |
| **Enabled** | Master switch — pause/resume all capture |
| **Clear** | Wipe all results and testcase data (with confirmation) |
| **Wrap** | Toggle word wrap in request/response viewer |

Click any result row → arrow keys navigate between results while the detail popup is open.

---

## 🏗️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Java 17 |
| Burp API | Montoya API |
| UI | Swing — custom dark theme with blue accents |
| Policy Persistence | Gson (JSON, saved to `~/.burp_security_headers_policies.json`) |
| Testcase Import | Apache POI (Excel) |
| Packaging | Maven Shade (fat JAR) |

---

## 🏛️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Burp Suite                                 │
│                                                                     │
│  ┌──────────────┐    HTTP Traffic    ┌───────────────────────────┐  │
│  │   Proxy /     │──────────────────▶│  HeaderCheckHttpHandler   │  │
│  │   Repeater    │                   │  (Montoya HttpHandler)    │  │
│  └──────────────┘                    └─────────┬─────────────────┘  │
│                                                │                    │
│                                     parse headers, build            │
│                                                │                    │
│                                                ▼                    │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                     HeaderResult                             │   │
│  │  (host, path, status, HSTS, CC, XFO, XCTO, ACAO, CSP)        │   │
│  └──────────────────────┬───────────────────────────────────────┘   │
│                         │                                           │
│            ┌────────────┼──────────────┐                            │
│            ▼            ▼              ▼                            │
│  ┌──────────────┐ ┌───────────┐ ┌──────────────────┐                │
│  │ ResultStore  │ │  Summary  │ │     Policy       │                │ 
│  │ (raw results)│ │  Service  │ │    Evaluator     │                │
│  └──────┬───────┘ └─────┬─────┘ └────────┬─────────┘                │
│         │               │                │                          │
│         │               │     ┌──────────┴──────────┐               │
│         │               │     │   PolicyStore       │               │
│         │               │     │ ┌─────────────────┐ │               │
│         │               │     │ │ PolicyProfile   │ │               │
│         │               │     │ │  └─ PolicyRule  │ │               │
│         │               │     │ │  └─ Conditions  │ │               │
│         │               │     │ └─────────────────┘ │               │
│         │               │     │   ~/.burp_sec...json│               │
│         │               │     └─────────────────────┘               │
│         │               │                                           │
│  ┌──────┴───────────────┴───────────────────────────────────────┐   │
│  │                  SecurityHeadersTab (Swing UI)               │   │
│  │                                                              │   │
│  │  ┌───────────┬────────────┬──────────┬───────────────────┐   │   │
│  │  │ Dashboard │ Raw Results│ Host     │ Repeater          │   │   │
│  │  │           │            │ Summary  │                   │   │   │
│  │  ├───────────┼────────────┼──────────┼───────────────────┤   │   │
│  │  │ Testcase  │ Testcase   │ Policies │ Scope &           │   │   │
│  │  │ Catalog   │ Results    │          │ Export            │   │   │
│  │  └───────────┴────────────┴──────────┴───────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Testcase Engine                           │   │
│  │  ┌───────────────┐  ┌──────────────┐  ┌──────────────────┐   │   │
│  │  │ PassiveEngine │  │ ActiveRunner │  │ TestcaseLibrary  │   │   │
│  │  │ (observe)     │  │ (send reqs)  │  │ (104 testcases)  │   │   │
│  │  └───────────────┘  └──────────────┘  └──────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────────┐  ┌──────────────────┐                         │
│  │ ScopeManager     │  │ CsvExportService │                         │
│  │ (include/exclude)│  │ (results → CSV)  │                         │
│  └──────────────────┘  └──────────────────┘                         │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Capture** — `HeaderCheckHttpHandler` intercepts every HTTP response via Montoya API
2. **Parse** — Extracts the 6 security headers + ACAO behavioral checks into a `HeaderResult`
3. **Store** — `ResultStore` holds raw results; `TestcaseResultStore` holds testcase results
4. **Evaluate** — `PolicyEvaluator` checks results against the active `PolicyProfile` (content-type aware)
5. **Display** — `SecurityHeadersTab` renders everything across 8 tabs with live dashboard updates
6. **Export** — `CsvExportService` exports filtered results; `ScopeManager` controls what gets captured
