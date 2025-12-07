# Threat Model Report: Web Portal Architecture

**Date:** 2025-12-07  
**Project:** Web Portal Architecture  
**Description:** A layered system featuring a Backbone.js front-end and a Django/Piston back-end, interacting with external databases and a common server.

---

## 1. Architecture Extraction

### 1.1 Components
*   Primary Database
*   Secondary Database
*   Common Server
*   REST API (Django + Piston App)
*   Backend Model
*   Backend View
*   Backend Template
*   Backend Router (urls.py)
*   I18n (*.po)
*   Frontend Event Handler
*   Frontend Model/Collection
*   Frontend View
*   Frontend Router
*   REQUIRE.JS

### 1.2 Data Flows
1.  Primary Database → Backend Model (TCP/IP)
2.  Secondary Database → Common Server (Unspecified)
3.  Common Server → REST API (Django + Piston App) (HTTP/REST)
4.  REST API (Django + Piston App) → Backend Model (Invocation)
5.  Backend Model → Backend View (Invocation)
6.  Backend View → Backend Model (Invocation)
7.  Backend View → Backend Template (Invocation)
8.  Backend Template → I18n (*.po) (Invocation)
9.  Backend Router (urls.py) → Backend View (Invocation)
10. Backend Router (urls.py) → Frontend Router (JSON/ *.MU)
11. Frontend Router → Backend Router (urls.py) (JSON/ *.MU)
12. Frontend Router → Frontend View (Invocation)
13. Frontend View → Frontend Model/Collection (Invocation)
14. Frontend Model/Collection → Frontend View (Invocation)
15. Frontend Event Handler → Frontend Model/Collection (Asynchronous call)
16. Frontend Event Handler → Frontend View (Asynchronous call)
17. REST API (Django + Piston App) → Frontend Model/Collection (Implied HTTP/JSON)

### 1.3 Trust Boundaries
*   DATA ACCESS LAYER
*   BUSINESS LOGIC
*   FLOW LOGIC
*   PRESENTATION LOGIC
*   FRONT-END
*   Web Portal Django App (Backend Boundary)
*   Web Portal BACKBONE.JS (Frontend Boundary)

---

## 2. Component Inventory

| Component | Type | Criticality | Notes |
| :--- | :--- | :--- | :--- |
| **Primary Database** | Database | **Critical** | Stores core application data. Target for exfiltration. |
| **Secondary Database** | Database | **High** | Connected to Common Server; potential pivot point. |
| **REST API (Django + Piston)** | API | **Critical** | Main entry point; handles serialization/deserialization. High risk due to legacy framework. |
| **Backend Model** | Model | **High** | Enforces business rules and interacts directly with the DB. |
| **Frontend View** | View | **Medium** | Renders data in browser; primary vector for XSS. |
| **Frontend Model/Collection** | Model | **Medium** | Handles client-side state; communicates with API. |
| **REQUIRE.JS** | Dependency Manager | **Medium** | Loads external scripts; integrity risk. |
| **Common Server** | Server | **High** | Infrastructure component hosting services. |
| **I18n (*.po)** | Internationalization | **Low** | Handles translations; minor DoS risk. |

---

## 3. STRIDE Threat Enumeration

| ID | STRIDE | CWE | Component | Description | Severity | Mitigations |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T-001** | Tampering | **CWE-502** | REST API (Django + Piston) | **Insecure Deserialization via Piston:** An attacker sends a malicious payload (Pickle/YAML) which executes arbitrary code upon deserialization by the Django Piston framework. | **Critical** | 1. Migrate to Django REST Framework (DRF).<br>2. Disable Pickle/YAML serializers.<br>3. Enforce strict JSON-only content types. |
| **T-002** | Spoofing | **CWE-79** | Frontend View | **DOM-based XSS in Backbone View:** Attacker injects malicious JS into user input which is rendered unescaped by the Frontend View into the DOM. | **High** | 1. Implement strict Content Security Policy (CSP).<br>2. Escape all data before rendering.<br>3. Avoid raw HTML injection methods. |
| **T-003** | Info Disclosure | **CWE-200** | REST API (Django + Piston) | **Excessive Data Exposure:** API returns full model objects (including sensitive fields like passwords/keys) relying on the client to hide them. | **Medium** | 1. Use Data Transfer Objects (DTOs) or strict serializers.<br>2. Filter data server-side, not client-side. |
| **T-004** | Tampering | **CWE-89** | Backend Model | **SQL Injection in ORM Bypass:** Filter parameters or raw SQL usage in Piston handlers allows attackers to manipulate database queries. | **High** | 1. Use Django ORM methods strictly.<br>2. Validate input types for all URL parameters.<br>3. Avoid `raw()` or `extra()` queries. |
| **T-005** | Elevation of Privilege | **CWE-639** | REST API (Django + Piston) | **Insecure Direct Object Reference (IDOR):** Authenticated users can access/modify other users' resources by iterating sequential IDs in API requests. | **High** | 1. Implement object-level permissions.<br>2. Verify resource ownership before processing requests. |
| **T-006** | Denial of Service | **CWE-400** | I18n (*.po) | **Resource Exhaustion via Translation:** Malformed locale inputs cause recursive lookups or memory exhaustion during template rendering. | **Medium** | 1. Whitelist allowed language codes.<br>2. Ensure translation files are read-only and integrity checked. |
| **T-007** | Tampering | **CWE-494** | REQUIRE.JS | **Dependency Supply Chain Attack:** External dependencies loaded via Require.js are compromised at the source/CDN, executing code in the browser. | **Medium** | 1. Implement Subresource Integrity (SRI).<br>2. Host critical dependencies locally. |
| **T-008** | Info Disclosure | **CWE-319** | Primary Database | **Cleartext Database Traffic:** Communication between Backend Model and Database occurs over unencrypted TCP/IP, allowing network sniffing. | **High** | 1. Enforce TLS/SSL for database connections.<br>2. Implement strict network segmentation (VLANs). |

---

## 4. Architectural Weaknesses

1.  **Use of Deprecated Framework (Django Piston)**
    *   **Description:** The architecture relies on an unmaintained framework (Piston) known for insecure defaults regarding serialization.
    *   **Impact:** Extremely high risk of Remote Code Execution (RCE) and lack of security patches.

2.  **Lack of CSRF Protection for API**
    *   **Description:** Backbone.js interactions with Django often require manual configuration to handle CSRF tokens, which is frequently disabled for convenience in legacy apps.
    *   **Impact:** Attackers can force authenticated users to perform state-changing actions (e.g., account updates) without consent.

3.  **Unencrypted Internal Traffic**
    *   **Description:** Critical data flows (Database → Model) are using unencrypted protocols.
    *   **Impact:** Compromise of a single internal node allows passive capture of all database credentials and user data.

4.  **Implicit Trust in Frontend Validation**
    *   **Description:** Heavy logic in Frontend Models suggests reliance on client-side validation, with the backend potentially assuming incoming data is clean.
    *   **Impact:** Bypass of business logic and integrity checks by sending raw API requests.

---

## 5. CVE Discovery

*Note: While the input list of CVEs was empty, Threat T-001 explicitly referenced a specific CVE associated with the identified technology (Django Piston). It is included here for accuracy.*

| CVE ID | Component | CVSS | Summary | Preconditions | Relevance | Why it applies |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CVE-2011-4103** | Django Piston | 9.8 (Est) | Django Piston allows remote attackers to execute arbitrary code via a crafted `Content-Type` header (e.g., YAML or Pickle) that triggers insecure deserialization. | Piston installed with default configuration allowing non-JSON serializers. | **Critical** | The architecture explicitly names "Django + Piston App". This is the definitive vulnerability for this component. |

---

## 6. Threat ↔ CVE Matrix

| Threat ID | CVE | Relationship |
| :--- | :--- | :--- |
| **T-001** | **CVE-2011-4103** | **Direct:** The threat describes the exact exploitation mechanism of this CVE. |

---

## 7. Attack Path Simulations

### AP-01: Full Backend Compromise via Piston Deserialization RCE
*   **Impact:** Critical (Full System Control)
*   **Likelihood:** Medium (Depends on network exposure of API)
*   **Chain:**
    1.  **Reconnaissance:** Attacker discovers `REST API` and identifies "django-piston" headers or behavior.
    2.  **Exploit Delivery:** Attacker sends a POST request with `Content-Type: application/x-yaml` containing a python payload (Threat **T-001** / **CVE-2011-4103**).
    3.  **Execution:** The API deserializes the payload, executing shellcode.
    4.  **Pivot:** Attacker gains a shell, reads `settings.py` to find DB credentials.
    5.  **Exfiltration:** Attacker connects to `Primary Database` and dumps all tables.

### AP-02: Mass Data Theft via XSS and IDOR Chaining
*   **Impact:** High (Data Breach)
*   **Likelihood:** High (Common web vulnerabilities)
*   **Chain:**
    1.  **Injection:** Attacker inputs malicious script into a profile field rendered by `Frontend View` (Threat **T-002**).
    2.  **Session Hijacking:** Admin views the profile; script executes and sends session token to attacker.
    3.  **Authentication:** Attacker uses the token to authenticate against the `REST API`.
    4.  **Enumeration:** Attacker iterates through User IDs (`/api/users/1`...`1000`) exploiting IDOR (Threat **T-005**).
    5.  **Collection:** API returns excessive data (Threat **T-003**) for every user, which the attacker collects.

---

## 8. Component Security Profiles

### REST API (Django + Piston)
*   **Role:** Main interface between frontend and data.
*   **Risk Rating:** **Critical**
*   **Top Threats:**
    *   T-001: RCE via Insecure Deserialization.
    *   T-005: Insecure Direct Object Reference (IDOR).
    *   T-003: Excessive Data Exposure.
*   **Prioritized Mitigations:**
    1.  **Migrate to Django REST Framework (DRF) immediately.**
    2.  Disable all serializers except JSON in Piston config.
    3.  Implement strict object-level permissions.

### Primary Database
*   **Role:** Long-term storage of business data.
*   **Risk Rating:** **Critical**
*   **Top Threats:**
    *   T-008: Cleartext traffic sniffing.
    *   T-004: SQL Injection via Backend Model.
*   **Prioritized Mitigations:**
    1.  Enable and enforce TLS 1.2+ for all connections.
    2.  Network isolation (ensure only the Backend Model can connect).
    3.  Regular audits of database access logs.

### Frontend View (Backbone.js)
*   **Role:** Renders UI and user data.
*   **Risk Rating:** **High**
*   **Top Threats:**
    *   T-002: Cross-Site Scripting (XSS).
*   **Prioritized Mitigations:**
    1.  Context-aware output encoding for all dynamic data.
    2.  Implement a restrictive Content Security Policy (CSP).

---

## 9. NIST 800-53 Rev5 Control Mapping

| Threat ID | Threat Category | Relevant NIST Controls | Control Description & Mitigation Utility |
| :--- | :--- | :--- | :--- |
| **T-001** | Tampering (RCE) | **SI-2 (Flaw Remediation)** | Identify and correct system flaws. Essential for patching/replacing the vulnerable Piston framework. |
| **T-001** | Tampering (RCE) | **SC-18 (Mobile Code)** | Restrict execution of mobile code (deserialized objects). Prevents the execution of the pickle payload. |
| **T-002** | Spoofing (XSS) | **SI-10 (Information Input Validation)** | Validate/sanitize inputs. Prevents script injection at the entry point. |
| **T-005** | Elevation of Privilege (IDOR) | **AC-3 (Access Enforcement)** | Enforce approved authorizations for logical access. Ensures User A cannot access User B's record via ID manipulation. |
| **T-008** | Info Disclosure (Sniffing) | **SC-8 (Transmission Confidentiality)** | Protect transmitted information. Mandates TLS for the database connection. |

---

## 10. Hardening Plan

### 10.1 Quick Wins (< 1 Day)
*   **Config Change:** explicitely disable `YAML` and `Pickle` serializers in Django Piston settings. Only allow `JSON`.
*   **Network:** verify that the database port is not exposed to the public internet (ACL check).
*   **Sanitization:** Enable Django's standard XSS protection headers (`X-XSS-Protection`, `X-Content-Type-Options`).

### 10.2 Short-Term (1–4 Weeks)
*   **Dependency Management:** Audit `REQUIRE.JS` dependencies and add Subresource Integrity (SRI) hashes to all script tags.
*   **Encryption:** Configure the Database and Django Backend to require SSL/TLS for the database connection.
*   **Authorization:** Audit all API endpoints and implement a permission check decorator ensuring `request.user.id == resource.owner_id`.
*   **CSP:** Deploy a Content Security Policy header in report-only mode to identify necessary scripts, then enforce it.

### 10.3 Long-Term (1–3 Months)
*   **Re-architecture:** **Replace Django Piston with Django REST Framework (DRF).** Piston is deprecated and insecure by design. This is the single most critical task.
*   **Secret Management:** Move hardcoded secrets (if any) to a dedicated secrets manager and inject them as environment variables.
*   **Frontend Modernization:** Consider migrating from Backbone.js to a modern framework (React/Vue) that handles escaping natively, reducing XSS surface area.