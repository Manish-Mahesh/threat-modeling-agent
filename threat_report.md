# Threat Model Report: Web Portal Architecture (Django & Backbone.js)

**Date:** 2025-12-10  
**Version:** 1.0  
**Status:** Draft  

---

## 1. Architecture Extraction

### 1.1 Components
*   **Data Storage:** Database (Top), Database (Bottom)
*   **Server-Side Logic:** Common Server (Application Server), REST API (Django + Piston App), Server Model (Django), Server View (Django), Server Template (Django), Server Router (urls.py), I18n (*.po)
*   **Client-Side Logic:** Client Event Handler, Client Model Collection (Backbone.js), Client View (Backbone.js), Client Router (Backbone.js), Dependencies REQUIRE.JS

### 1.2 Data Flows
1.  **Database (Top) → Server Model (Django)** (TCP/IP)
2.  **Common Server → Database (Bottom)** (Database Protocol)
3.  **Common Server → REST API (Django + Piston App)** (HTTP/REST)
4.  **REST API → Server Model (Django)** (Invocation)
5.  **Server Router → Server View (Django)** (Invocation)
6.  **Server View ↔ Server Model (Django)** (Invocation)
7.  **Server View → Server Template (Django)** (Invocation)
8.  **I18n (*.po) → Server Template (Django)** (Invocation)
9.  **Client Event Handler → Client Model/View** (Asynchronous call)
10. **Client Model ↔ Client View** (Invocation)
11. **Client Router → Client Model/View** (Invocation)
12. **Client View → Server Router** (JSON / *.MU)
13. **Client Router → REST API** (HTTP/AJAX implied)

### 1.3 Trust Boundaries
*   **Client-Side Container:** Web Portal BACKBONE.JS Container (Untrusted User Zone)
*   **Server-Side Container:** Web Portal Django App Container (Trusted Execution Zone)
*   **Internal Logic Boundaries:** Data Access Layer, Business Logic, Flow Logic, Presentation Logic

---

## 2. Component Inventory Table

| Component | Type | Criticality | Notes |
| :--- | :--- | :--- | :--- |
| **REST API (Django + Piston)** | API Service | **Critical** | Uses deprecated framework (Piston); primary entry point for data; handles deserialization. |
| **Database (Bottom)** | Database | **Critical** | Stores business data; target for SQL injection and privilege escalation. |
| **Database (Top)** | Database | **High** | Stores application state/model data; high confidentiality requirement. |
| **Common Server** | App Server | **Critical** | Hosts the application; explicitly linked to Nginx CVEs in threat data. |
| **Server Model (Django)** | MVC Model | **High** | Enforces business rules and interacts directly with databases. |
| **Client View (Backbone.js)** | Front-End | **High** | Renders data in browser; high risk of XSS due to manual DOM manipulation. |
| **I18n (*.po)** | Translation | **Medium** | Handles format strings; potential for localized XSS or format string attacks. |
| **Dependencies REQUIRE.JS** | Dependency Manager | **Medium** | Manages client-side libraries; supply chain risk. |

---

## 3. STRIDE Threat Enumeration

| ID | STRIDE | CWE | Component | Description | Severity | Mitigations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T-001** | Tampering | CWE-502 | REST API (Django + Piston) | **Insecure Deserialization in Piston:** Piston may accept YAML/Pickle, allowing RCE via crafted payloads. | **Critical** | 1. Migrate to Django REST Framework.<br>2. Disable YAML/Pickle serializers.<br>3. Enforce JSON-only input. |
| **T-002** | Tampering | CWE-79 | Client View (Backbone.js) | **DOM-based XSS:** Backbone views may render unsafe model attributes directly to the DOM without encoding. | **High** | 1. Use context-aware templating (Handlebars).<br>2. Sanitize data via DOMPurify.<br>3. Implement strict CSP. |
| **T-003** | Spoofing | CWE-352 | REST API (Django + Piston) | **CSRF via AJAX:** AJAX requests may lack proper CSRF token header handling, allowing state changes. | **High** | 1. Configure Django to read `X-CSRFToken`.<br>2. Ensure Backbone sync injects token.<br>3. Use `SameSite=Strict` cookies. |
| **T-004** | Info Disclosure | CWE-200 | REST API (Django + Piston) | **Mass Assignment/Exposure:** API may return full model objects (including sensitive fields) by default. | **Medium** | 1. Use DTOs/Serializers with field whitelisting.<br>2. Define `exclude` in Piston handlers. |
| **T-005** | Tampering | CWE-134 | I18n (*.po) | **Format String/XSS in Translations:** Malicious .po files can inject scripts or crash the app via format strings. | **Medium** | 1. Enforce code review on .po files.<br>2. Auto-escape translated strings in templates. |
| **T-006** | EoP | CWE-639 | REST API (Django + Piston) | **Insecure Direct Object Reference (IDOR):** Sequential IDs in URLs allow accessing other users' resources. | **High** | 1. Implement object-level permissions.<br>2. Use UUIDs instead of integers. |
| **T-007** | DoS | CWE-829 | Dependencies REQUIRE.JS | **CDN Dependency Failure:** External script loading failure or compromise causes DoS or code injection. | **Medium** | 1. Use Subresource Integrity (SRI).<br>2. Host critical dependencies locally. |
| **T-008** | Tampering | CWE-89 | Server Model (Django) | **ORM Bypass SQL Injection:** Usage of `raw()` or `extra()` with user input allows DB manipulation. | **Critical** | 1. Prohibit `raw()`/`extra()` methods.<br>2. Use parameterized ORM filters.<br>3. Static Analysis (SAST). |
| **T-009** | DoS | CWE-190 | Database (Bottom) | **PostgreSQL Integer Overflow (CVE-2021-32027):** Auth users can write arbitrary bytes to memory via array modification. | **High** | 1. Update PostgreSQL to patched version. |
| **T-010** | EoP | CWE-190 | Database (Bottom) | **PostgreSQL RCE (CVE-2023-5869):** Integer overflow in array modification allows arbitrary code execution. | **High** | 1. Update PostgreSQL to patched version. |
| **T-011** | DoS | CWE-Other | Server Router (urls.py) | **Django i18n DoS (CVE-2022-41323):** Regex DoS via internationalized URL locale parameter. | **High** | 1. Update Django.<br>2. Rate limit locale switching. |
| **T-012** | DoS | CWE-770 | Server View (Django) | **Accept-Language Header DoS (CVE-2023-23969):** Excessive memory usage via large headers. | **High** | 1. Update Django.<br>2. Cap header size in Nginx. |
| **T-013** | DoS | CWE-22 | REST API (Django + Piston) | **Directory Traversal (CVE-2021-31542):** Uploaded files with crafted names can traverse directories. | **High** | 1. Update Django.<br>2. Sanitize filenames on upload. |
| **T-014** | DoS | CWE-Other | Server Router (urls.py) | **ACL Bypass (CVE-2021-44420):** Trailing newlines in URLs bypass upstream Nginx access controls. | **High** | 1. Update Django.<br>2. Strict URL validation in Nginx. |
| **T-015** | DoS | CWE-89 | Server Model (Django) | **JSONField SQL Injection (CVE-2024-42005):** Injection via `values()` on JSONField models. | **High** | 1. Update Django.<br>2. Audit JSONField queries. |
| **T-016** | DoS | CWE-89 | Server Model (Django) | **FilteredRelation SQL Injection (CVE-2025-57833):** Injection via dictionary expansion in `annotate()`. | **High** | 1. Update Django.<br>2. Avoid dynamic kwargs in annotation. |
| **T-017** | EoP | CWE-193 | Common Server (Nginx) | **Nginx Resolver Overflow (CVE-2021-23017):** 1-byte overwrite via forged UDP DNS packets. | **High** | 1. Update Nginx.<br>2. Disable resolver if unused. |
| **T-018** | DoS | CWE-787 | Common Server (Nginx) | **MP4 Module Corruption (CVE-2022-41741):** Memory corruption via crafted MP4 file if module enabled. | **High** | 1. Update Nginx.<br>2. Disable `ngx_http_mp4_module`. |
| **T-019** | EoP | CWE-915 | Database (Bottom) | **PostgreSQL Superuser Escalation (CVE-2022-2625):** Privilege escalation via extension creation. | **High** | 1. Update PostgreSQL.<br>2. Restrict extension creation. |

---

## 4. Architectural Weaknesses

1.  **W-001: Use of Obsolete API Framework (Django-Piston)**
    *   **Description:** The system uses Django-Piston, which is unmaintained (last update ~2011). It lacks modern security controls, standard auth classes, and browsable API protection.
    *   **Impact:** Critical exposure to RCE (via serialization) and high maintenance debt.

2.  **W-002: Dual MVC Complexity (Split-Brain)**
    *   **Description:** Business logic is split between Django (Server) and Backbone.js (Client). Validation often exists only on the client side, leading to API security gaps.
    *   **Impact:** Data integrity issues and validation bypasses if the API is accessed directly (e.g., via `curl`).

3.  **W-003: Potential Lack of Transport Layer Security**
    *   **Description:** Data flows specify "HTTP/REST" and "JSON" without explicit HTTPS enforcement.
    *   **Impact:** Man-in-the-Middle attacks compromising credentials and session tokens.

4.  **W-004: Client-Side Session Management Risks**
    *   **Description:** Backbone apps typically store tokens in LocalStorage (accessible to JS). Combined with the high XSS risk (T-002), this allows easy session hijacking.
    *   **Impact:** Full account takeover.

5.  **W-005: Missing Rate Limiting on API**
    *   **Description:** No API Gateway or throttling middleware is identified.
    *   **Impact:** Susceptibility to Brute Force and DoS attacks.

---

## 5. CVE Discovery

*Only relevant CVEs based on the identified components (PostgreSQL, Django, Nginx) are listed below.*

| CVE ID | Component | CVSS | Summary | Relevance |
| :--- | :--- | :--- | :--- | :--- |
| **CVE-2023-5869** | PostgreSQL | 8.8 | Integer overflow in array modification leading to RCE. | **High** - Auth users can compromise DB server. |
| **CVE-2021-32027** | PostgreSQL | 8.8 | Bounds check missing in array modification (Memory overwrite). | **High** - Data integrity/availability risk. |
| **CVE-2024-42005** | Django | 7.3 | SQL Injection in `QuerySet.values()` for JSONField. | **High** - Critical data exfiltration vector. |
| **CVE-2021-31542** | Django | 7.5 | Directory traversal in MultiPartParser/UploadedFile. | **Medium** - Relevant if API accepts file uploads. |
| **CVE-2022-41323** | Django | 7.5 | DoS via internationalized URL locale parameter. | **High** - Architecture explicitly uses I18n. |
| **CVE-2023-23969** | Django | 7.5 | DoS via excessive memory usage in Accept-Language headers. | **High** - Unauthenticated remote DoS. |
| **CVE-2025-57833** | Django | 7.1 | SQL Injection in `FilteredRelation` via dictionary expansion. | **High** - ORM-based injection vector. |
| **CVE-2021-44420** | Django | 7.3 | Access Control Bypass via trailing newlines in URLs. | **Medium** - Bypasses Nginx-level path rules. |
| **CVE-2021-23017** | Nginx | 7.7 | 1-byte memory overwrite in resolver (UDP packets). | **Medium** - High impact if resolver is configured. |
| **CVE-2022-41741** | Nginx | 7.0 | Memory corruption in `ngx_http_mp4_module`. | **Low** - Only if MP4 streaming is enabled. |
| **CVE-2022-2625** | PostgreSQL | 8.0 | Privilege escalation to superuser via extension creation. | **Low** - Requires complex social engineering. |

---

## 6. Threat ↔ CVE Matrix

| Threat ID | CVE | Relationship |
| :--- | :--- | :--- |
| **T-009** | CVE-2021-32027 | **Direct** (Source of Threat) |
| **T-010** | CVE-2023-5869 | **Direct** (Source of Threat) |
| **T-011** | CVE-2022-41323 | **Direct** (Source of Threat) |
| **T-012** | CVE-2023-23969 | **Direct** (Source of Threat) |
| **T-013** | CVE-2021-31542 | **Direct** (Source of Threat) |
| **T-014** | CVE-2021-44420 | **Direct** (Source of Threat) |
| **T-015** | CVE-2024-42005 | **Direct** (Source of Threat) |
| **T-016** | CVE-2025-57833 | **Direct** (Source of Threat) |
| **T-017** | CVE-2021-23017 | **Direct** (Source of Threat) |
| **T-018** | CVE-2022-41741 | **Direct** (Source of Threat) |
| **T-019** | CVE-2022-2625 | **Direct** (Source of Threat) |
| **T-001** | CVE-2011-4103 | **Related Weakness** (Piston Serialization History) |

---

## 7. Attack Path Simulations

### AP-01: Full System Compromise via Piston Deserialization and Database Pivot
*   **Impact:** Total system compromise (Web Server + Database).
*   **Likelihood:** High
*   **Steps:**
    1.  **Reconnaissance:** Attacker identifies `REST API` endpoints and detects Piston usage.
    2.  **Exploit (T-001):** Attacker sends a POST request with `Content-Type: application/x-yaml` containing a Python payload.
    3.  **Execution:** Piston deserializes the payload, executing shell commands (RCE) on the **Common Server**.
    4.  **Lateral Movement:** Attacker reads `settings.py` to steal database credentials.
    5.  **Pivot (T-010/CVE-2023-5869):** Attacker connects to **Database (Bottom)** and triggers an integer overflow to gain execution on the database host.

### AP-02: Data Exfiltration via Django SQL Injection and Backbone.js XSS Chaining
*   **Impact:** Data theft and Admin Account Takeover.
*   **Likelihood:** Medium
*   **Steps:**
    1.  **Exploit (T-015/CVE-2024-42005):** Attacker targets an endpoint using `QuerySet.values()` on a JSONField and injects SQL via a crafted key.
    2.  **Exfiltration:** Attacker dumps user session table from **Database (Top)**.
    3.  **Persistence (T-002):** Attacker injects a script tag `<script>...` into a profile field (Stored XSS).
    4.  **Execution:** An Admin views the **Client View (Backbone.js)**. The script executes because Backbone blindly renders the model attribute.
    5.  **Takeover:** The script forces the Admin browser to create a new superuser (CSRF/API call).

---

## 8. Component Security Profiles

### 8.1 REST API (Django + Piston App)
*   **Role:** Primary interface between Backbone Client and Server Logic.
*   **Risk Rating:** **Critical**
*   **Top Threats:**
    1.  T-001 Insecure Deserialization (RCE)
    2.  T-015 SQL Injection (CVE-2024-42005)
    3.  T-006 IDOR
*   **Prioritized Mitigations:**
    1.  **Immediate:** Disable YAML/Pickle serializers in Piston config.
    2.  **Short-term:** Patch Django to latest LTS.
    3.  **Long-term:** Replace Piston with Django REST Framework (DRF).

### 8.2 Client View (Backbone.js)
*   **Role:** Renders UI and handles user interaction.
*   **Risk Rating:** **High**
*   **Top Threats:**
    1.  T-002 DOM-based XSS
    2.  W-004 LocalStorage Session Theft
*   **Prioritized Mitigations:**
    1.  Implement strict Content Security Policy (CSP).
    2.  Use a sanitization library (DOMPurify) before rendering any model attribute.
    3.  Switch session tokens to HttpOnly cookies.

### 8.3 Database (Bottom)
*   **Role:** Core data storage.
*   **Risk Rating:** **Critical**
*   **Top Threats:**
    1.  T-010 Remote Code Execution (CVE-2023-5869)
    2.  T-009 Integer Overflow (CVE-2021-32027)
*   **Prioritized Mitigations:**
    1.  **Immediate:** Upgrade PostgreSQL to a patched version (e.g., latest 13.x/14.x/15.x).
    2.  Restrict network access to only the Common Server IP.

---

## 9. NIST 800-53 Rev5 Control Mapping

| Threat Risk | Threat ID | NIST Control | Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **RCE via Serialization** | T-001 | **SI-16** (Memory Protection) | Controls input validation to prevent execution of injected code via serialization. |
| | | **CM-7** (Least Functionality) | Disable unused serialization formats (YAML/Pickle) to reduce attack surface. |
| **XSS** | T-002 | **SI-15** (Information Output Filtering) | Ensure output is encoded/sanitized to prevent script execution in the browser. |
| | | **SC-39** (Process Isolation) | Use CSP to restrict where scripts can load from and what they can execute. |
| **SQL Injection** | T-008, T-015 | **SI-10** (Information Input Validation) | Validate and parameterize all inputs before passing them to the database interpreter. |
| **Vulnerable Components** | T-009...T-019 | **SI-2** (Flaw Remediation) | Install security-relevant software updates (patches) within the specified time period. |

---

## 10. Hardening Plan

### 10.1 Quick Wins (Under 1 Day)
1.  **Disable Piston Serializers:** Modify `settings.py` or Piston config to explicitly disable YAML and Pickle support. Enforce JSON only.
2.  **Patch Management:** Update **Django** and **PostgreSQL** to the latest minor versions to resolve CVE-2024-42005, CVE-2023-5869, and others.
3.  **Nginx Hardening:** Disable `ngx_http_mp4_module` and `resolver` directives if not strictly necessary.

### 10.2 Short-Term (1–4 Weeks)
1.  **Implement CSP:** define a Content Security Policy header to mitigate XSS risks in the Backbone client.
2.  **Sanitization Wrapper:** Create a utility function in Backbone to sanitize all model attributes before they are passed to Views.
3.  **Network Segmentation:** Ensure databases are not accessible from the public internet, only from the Common Server.

### 10.3 Long-Term (1–3 Months)
1.  **Framework Migration:** **Critical Priority.** Migrate from Django-Piston to **Django REST Framework (DRF)**. Piston is too old to be secured effectively.
2.  **Frontend Modernization:** Evaluate moving from Backbone.js to a framework with auto-escaping (React/Vue/Angular) to eliminate the systemic XSS weakness.
3.  **Secrets Management:** Move database credentials out of `settings.py` and into a secrets manager or environment variables.