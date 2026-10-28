# ConsentMonitor — Windows 11 Native Verification Plan

**Target Platform:** 64-bit Windows 11 (Versions 25H2 and 26H2 on active servicing channels)  
**Document Status:** READY FOR EXECUTION ON WINDOWS 11 TEST HOST  
**Execution State on Linux Build Host:** **DESIGNED — NOT EXECUTED**

---

## 1. Objectives & Prerequisites

This verification plan specifies the exact testing procedures required to validate the Windows-specific components of `ConsentMonitor` on a physical or virtual 64-bit Windows 11 machine. Portable logic has been verified on Linux (93/93 tests passing). The tests in this document validate live Windows OS integration: MSVC exploit mitigation flags, WinHTTP network protocol boundaries, NTFS filesystem ACLs, and the Win32 GUI event loop.

### 1.1 Host Environment Requirements
- **Operating System:** Windows 11 Pro / Enterprise 64-bit, Version 26H2 (Build 26100+) or 25H2. Servicing updates current.
- **Compiler & SDK:** Visual Studio 2022 (MSVC v143) with C++20 standard library and Windows 11 SDK (10.0.26100.0 or later).
- **Network Capture Tool:** Wireshark 4.x or `tshark` with Npcap installed for full-packet wire capture.
- **Local HTTPS Mock Server:** Python 3.11+ with `cryptography` and `aiohttp` or a local OpenSSL-based TLS 1.2 server.
- **Test Accounts:**
  - `ConsentUserA`: Standard (non-administrative) user account.
  - `ConsentUserB`: Secondary standard user account (for ACL boundary isolation tests).

---

## 2. Phase 1: Native Build & Exploit Mitigation Verification

### 2.1 Compilation & Static Configuration
Execute from a Visual Studio 2022 x64 Native Tools Command Prompt:
```cmd
cd C:\path\to\ConsentMonitor
mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release
```

### 2.2 Binary Security Hardening Audit
Validate that the compiled PE binary incorporates all mandated Windows exploit mitigations using `dumpbin`:
```cmd
dumpbin /loadconfig Release\ConsentMonitor.exe | findstr /i "Guard"
dumpbin /headers Release\ConsentMonitor.exe | findstr /i "characteristics"
```
**Acceptance Criteria:**
- **Control Flow Guard (CFG):** CF Guard table present and active (`/guard:cf`).
- **Spectre Mitigation:** Compiled with `/Qspectre`.
- **ASLR / High Entropy:** High-entropy 64-bit ASLR enabled (`/HIGHENTROPYVA`, `/DYNAMICBASE`).
- **Data Execution Prevention:** DEP enabled (`/NXCOMPAT`).
- **Compiler Warnings:** Built cleanly under `/W4 /WX /permissive-` with zero warnings and zero errors.

---

## 3. Phase 2: Live WinHTTP Protocol & Network Egress Verification

### 3.1 Setup: Local Controlled TLS 1.2 Mock Server
Generate a self-signed root CA and leaf certificate restricted to TLS 1.2:
```cmd
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 365 -nodes -subj "/CN=ConsentMonitorTestCA"
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365
```
Install `ca.crt` into the Local Machine Trusted Root Certification Authorities store for test cases validating valid TLS, and remove it for revocation/untrusted checks.

### 3.2 TC-WIN-01: Zero Plaintext Egress & TLS 1.2 Wire Enforcement
- **Procedure:**
  1. Start Wireshark capturing on the loopback adapter (`Npcap Loopback Adapter`).
  2. Filter on `tcp.port == 8443`.
  3. Launch `ConsentMonitor.exe`, enter `https://localhost:8443/telemetry`, and grant consent.
  4. Trigger a diagnostic event and transmit telemetry.
  5. Inspect the captured packet trace.
- **Verification Criteria:**
  - Client Hello specifies TLS 1.2 (`0x0303`) exclusively.
  - No plain HTTP or unencrypted TCP payload exists before, during, or after the handshake.
  - Zero application bytes (event names, JSON keys, OS build strings) appear in plaintext.

### 3.3 TC-WIN-02: Redirect Policy Enforcement (`WINHTTP_OPTION_REDIRECT_POLICY_NEVER`)
- **Procedure:**
  1. Configure mock server on `https://localhost:8443/telemetry` to return `HTTP 301 Moved Permanently` with `Location: https://malicious-third-party.local/sink`.
  2. Transmit diagnostic telemetry from `ConsentMonitor`.
- **Verification Criteria:**
  - WinHTTP does **not** issue a GET or POST request to `https://malicious-third-party.local/sink`.
  - `WinHttpReceiveResponse` receives the 301 status, records status code, and halts.
  - The client logs `result_category="redirect_rejected"` and closes handles.

### 3.4 TC-WIN-03: Certificate Revocation Fail-Closed
- **Procedure:**
  1. Configure mock server certificate with an OCSP responder URL returning a `REVOKED` response (or an untrusted certificate chain).
  2. Initiate telemetry transmission.
- **Verification Criteria:**
  - `WinHttpSendRequest` fails with `ERROR_WINHTTP_SECURE_FAILURE` (12175) or certificate revocation error.
  - `WinHttpWriteData` is **never called**; zero payload bytes are written to the socket.
  - Worker enters `Drained` state and marks egress failure.

### 3.5 TC-WIN-04: Revocation Gate Between Header and Body Authorization
- **Procedure:**
  1. Configure mock server to pause after accepting TCP connection and TLS handshake.
  2. When the UI signals `HeaderAuthorized` / `HeaderSendInitiated`, immediately click "Revoke Consent".
  3. Allow mock server to respond.
- **Verification Criteria:**
  - `TryAuthorizeBody()` fails under `ConsentStateLock`.
  - `WinHttpWriteData` is bypassed; worker skips body transmission.
  - Network worker thread calls `WinHttpCloseHandle` on request and session handles.
  - Status updates to `Revoked` and worker marks `Drained`.

### 3.6 TC-WIN-05: Revocation Gate Before WinHttpReceiveResponse
- **Procedure:**
  1. Mock server accepts headers and body, then delays HTTP response by 5 seconds.
  2. Revoke consent during the delay.
- **Verification Criteria:**
  - `TryAuthorizeResponse()` fails under `ConsentStateLock`.
  - `WinHttpReceiveResponse()` is **skipped**.
  - Worker immediately proceeds to handle cleanup and exits.

---

## 4. Phase 3: NTFS ACL Security Verification

### 4.1 TC-WIN-06: Directory Creation & Canonical SDDL Inspection
- **Procedure:**
  1. Run `ConsentMonitor.exe` under standard user `ConsentUserA`.
  2. Verify `%LOCALAPPDATA%\ConsentMonitor\Logs` is created.
  3. Query the security descriptor with PowerShell:
     ```powershell
     (Get-Acl "$env:LOCALAPPDATA\ConsentMonitor\Logs").Sddl
     ```
- **Verification Criteria:**
  - SDDL matches canonical structure: `O:<UserSID>D:P(A;OICI;GA;;;<UserSID>)(A;OICI;GA;;;SY)`.
  - Owner is identical to `ConsentUserA` SID.
  - DACL protection flag `P` (`SE_DACL_PROTECTED`) is present; inheritance from parent directory is blocked.
  - Only two ACEs exist: `ConsentUserA` (Full Control) and `NT AUTHORITY\SYSTEM` (Full Control).

### 4.2 TC-WIN-07: Live `GetNamedSecurityInfoW` Audit
- **Procedure:**
  1. Call `Win32Security::VerifySecurityDescriptor` on the active directory.
- **Verification Criteria:**
  - Returns `Result<void>::success()`.
  - Tamper test: Use an administrative account to add an ACE granting `Users` read permissions. Re-run `VerifySecurityDescriptor`.
  - Function returns failure: DACL contains 3 ACEs; expected exactly 2.

### 4.3 TC-WIN-08: Cross-User Access Isolation
- **Procedure:**
  1. Switch session to `ConsentUserB` (standard user).
  2. Attempt to list or read `C:\Users\ConsentUserA\AppData\Local\ConsentMonitor\Logs`:
     ```cmd
     dir C:\Users\ConsentUserA\AppData\Local\ConsentMonitor\Logs
     ```
- **Verification Criteria:**
  - Access is denied (`ERROR_ACCESS_DENIED`, Exit Code 5).
  - No directory enumeration or log leakage occurs across standard user boundaries.

---

## 5. Phase 4: Win32 GUI & Lifecycle Verification

### 5.1 TC-WIN-09: Valid HTTPS Endpoint & Consent Initiation
- **Procedure:**
  1. Launch `ConsentMonitor.exe`.
  2. Verify GUI window renders correctly with native Win32 controls (Edit box, Start, Pause, Revoke, Exit buttons).
  3. Enter `https://127.0.0.1:8443/telemetry` and click "Start Monitoring".
- **Verification Criteria:**
  - Status label updates to `Granted: Monitoring active (Gen 1)`.
  - Local logging initializes; active log file created with proper ACL.

### 5.2 TC-WIN-10: Non-HTTPS Scheme & Malformed URL Rejection
- **Procedure:**
  1. Launch `ConsentMonitor.exe`.
  2. Enter `http://insecure-endpoint.com/telemetry` and click "Start Monitoring".
  3. Repeat with `ftp://...`, `file://...`, and empty string.
- **Verification Criteria:**
  - An error dialog (`MessageBoxW`) is displayed: "Invalid endpoint: URL must begin with https://".
  - Consent state remains `Idle` (generation does not increment).
  - No network sockets or log files are created.

### 5.3 TC-WIN-11: Instantaneous Revocation & Worker Drain
- **Procedure:**
  1. While monitoring is active, click "Revoke Consent".
- **Verification Criteria:**
  - UI immediately transitions to `Revoked`.
  - If network worker was transmitting, UI displays *"Consent Revoked: network egress may be in flight; awaiting worker termination"* until thread joins.
  - Once joined, UI updates to *"Consent Revoked: network egress stopped"*.

### 5.4 TC-WIN-12: Clean Shutdown & Resource Reclamation
- **Procedure:**
  1. Click "Exit" or close window (`WM_CLOSE`).
- **Verification Criteria:**
  - Process exits with code 0.
  - Inspect Task Manager / Process Explorer: zero zombie threads, zero leaked file locks, zero orphaned mutexes (`Global\ConsentMonitor_Writer_*`).

---

## 6. Execution Sign-Off Matrix

| Test Case | Description | Primary Verification Tool | Result | Tester Sign-Off |
|---|---|---|---|---|
| **TC-WIN-01** | Zero Plaintext Egress & TLS 1.2 | Wireshark / Npcap | [ ] PASS  [ ] FAIL | ________________ |
| **TC-WIN-02** | Redirect Policy Block | Mock HTTPS (301/302) | [ ] PASS  [ ] FAIL | ________________ |
| **TC-WIN-03** | Certificate Revocation Fail-Closed | Mock OCSP / Revoked Cert | [ ] PASS  [ ] FAIL | ________________ |
| **TC-WIN-04** | Header/Body Interleaved Revoke | Deliberate Latency + UI Revoke | [ ] PASS  [ ] FAIL | ________________ |
| **TC-WIN-05** | Response Authorization Gate | Delayed Server Response | [ ] PASS  [ ] FAIL | ________________ |
| **TC-WIN-06** | SDDL Directory Creation | PowerShell `Get-Acl` | [ ] PASS  [ ] FAIL | ________________ |
| **TC-WIN-07** | Live Security Descriptor Audit | `VerifySecurityDescriptor` | [ ] PASS  [ ] FAIL | ________________ |
| **TC-WIN-08** | Cross-User ACL Access Denial | Secondary User Session | [ ] PASS  [ ] FAIL | ________________ |
| **TC-WIN-09** | Valid HTTPS Consent Flow | Win32 Window UI | [ ] PASS  [ ] FAIL | ________________ |
| **TC-WIN-10** | Non-HTTPS Scheme Rejection | Win32 Window UI | [ ] PASS  [ ] FAIL | ________________ |
| **TC-WIN-11** | Immediate Revocation Feedback | Win32 Window UI | [ ] PASS  [ ] FAIL | ________________ |
| **TC-WIN-12** | Clean Process Teardown | Process Explorer | [ ] PASS  [ ] FAIL | ________________ |
