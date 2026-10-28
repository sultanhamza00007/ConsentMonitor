# ConsentMonitor

Transparent, user-mode, consent-driven Windows application diagnostic monitoring.

## 1. Project Overview & Scope

`ConsentMonitor` is a Windows user-mode application written in modern C++ (C++20). It demonstrates transparent system diagnostic monitoring governed by strict user consent controls.

### Architectural & Safety Guarantees
- **Strictly User-Mode & Visible:** Operates entirely in user mode with a native Win32 GUI. No kernel drivers, keyboard filters, covert hooks, stealth, or persistence.
- **Strictly Allowlisted Diagnostics:** Collects only application start/stop, consent transitions, network egress attempt outcomes, storage errors, and operation durations.
- **Prohibited Data:** Keystrokes, window/document content, clipboard, credentials, usernames, machine names, device identifiers, and user content are never collected.
- **Separation of Disclosures:** Local diagnostic file logging is disclosed separately from network egress consent.
- **Explicit Endpoint Entry:** No default remote endpoint is shipped. The user must manually input, review, and grant consent for the destination HTTPS URL.
- **Direct Connection:** No proxy support. No cookies, authentication tokens, or credentials are ever transmitted.

---

## 2. Platform Support Baseline

- **Supported OS:** 64-bit Windows 11, versions **25H2** and **26H2**, on active servicing channels receiving security updates.
- **Test Matrix:** 26H2 is the primary test platform; 25H2 is tested for compatibility.
- **Exclusions:** Windows 10 (including version 2004) and any out-of-servicing releases are outside the supported baseline.
- **Servicing Verification:** Check Microsoft's current client lifecycle list prior to release:  
  [Windows 11 Supported Versions](https://learn.microsoft.com/en-us/windows/release-health/supported-versions-windows-client).
- **Toolchain:** MSVC (Visual Studio 2022 or Build Tools) with modern Microsoft Windows SDK supporting Windows 11 25H2/26H2 APIs.

---

## 3. Architecture & Core Subsystems

### 3.1 Consent & Generational State Machine
- States: `Idle`, `Granted`, `Paused`, `Revoked`.
- Monotonic `consent_generation` isolates worker lifecycles.
- Re-consent creates a new generation; workers from old generations cannot authorize new work.
- Repeated grant while active is idempotent.
- An unlaunched worker is considered terminal and drained.

### 3.2 Two-Stage Network Authorization & Response Gate
Operates on a dedicated single synchronous WinHTTP worker thread:
1. `HeaderAuthorized`: Checked under `ConsentStateLock` before `WinHttpSendRequest(..., NULL, 0)`.
2. `BodyAuthorized`: Checked under `ConsentStateLock` before `WinHttpWriteData`.
3. `ResponseAuthorized`: Checked under `ConsentStateLock` before `WinHttpReceiveResponse`. If consent is revoked before this check, the response operation is skipped and handles are closed.
4. **Revocation Semantics:** Stop creating telemetry, discard queued unsent events, block new network authorizations. If a network call is already in flight, the UI states: *"Consent Revoked: network egress may be in flight; awaiting worker termination"*, until the worker thread exits and closes its handles.
5. **No Retries / Partial Write:** If `WinHttpSendRequest` fails, `WinHttpWriteData` is never called. If `WinHttpWriteData` fails or short-writes, the incomplete outcome is recorded without retries. The payload buffer remains valid until the synchronous call returns.
6. **TLS & Egress Policy:** TLS 1.2 is configured as the sole allowed protocol (`WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2`). Redirects disabled (`WINHTTP_OPTION_REDIRECT_POLICY_NEVER`). Revocation checking enabled.
7. **Handle Safety:** If handle closure fails or is uncertain, the system enters `Degraded_EgressUnknown` and the UI shows *"Egress state unknown"*, never *"Egress stopped"*.

### 3.3 Storage Quota & SDDL ACL Enforcement
- **Single-Writer Exclusivity:** Protected per-user mutex `Global\ConsentMonitor_Writer_<UserSID>`.
- **Filesystem Security:** `%LOCALAPPDATA%\ConsentMonitor\Logs` created with explicit SDDL:
  `O:<UserSID>D:P(A;OICI;GA;;;<UserSID>)(A;OICI;GA;;;SY)` (Owner: User, Protected DACL, User & SYSTEM Full Control). Verified via `GetNamedSecurityInfoW`.
- **Quota Ceilings:**
  - Active log: 5 MiB ceiling (`5,242,880` bytes).
  - Maximum 3 archives.
  - Hard Ceiling: `20,971,520` bytes (20 MiB).
  - Ordinary Write Cap: `20,905,984` bytes (19.9375 MiB).
  - Lifecycle Reserve: `65,536` bytes (64 KiB).
  - Exact-Fit Admission: 20,904,960 B + 1,024 B event = 20,905,984 B → Admitted.
  - One-Byte-Over Rejection: 20,904,961 B + 1,024 B event = 20,905,985 B → Rejected.
- **Write Failure:** Halts ordinary logging without deliberate truncation. UI reports final event may be incomplete.

### 3.4 Crash-Safe Dynamic Journaling & Recovery
- Monotonic sequence derived from last valid persisted sequence (`seq = last_valid_seq + 1`).
- RFC 8785 canonical JSON with CRC-32/IEEE integrity checksum.
- Ordered rotation: `CLOSE_ACTIVE` → move active to staging → retire `.3` (or `ABSENT`) → shift `.2` to `.3` (or `ABSENT`) → shift `.1` to `.2` (or `ABSENT`) → promote staging to `.1` → create fresh active (`CREATE_NEW` + verified ACL) → `ROTATION_COMPLETE` → clear journal.
- Startup crash recovery handles all 12 recovery states; ambiguous/multiple temporary journals fail closed without file deletion.

---

## 4. Building & Running

### Windows 11 Build (Native Target)
```cmd
mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release
ctest -C Release --output-on-failure
```

### Linux Portable Test Build (Verification of Portable Core Logic)
```bash
make test
```

---

## 5. Verification Status & Test Evidence

### Executed on Linux (93 of 93 Passed across 9 Suites)
Following the Stage 2 security audit and remediation, all portable C++20 core logic suites compile warning-free (`-Wall -Wextra -Wpedantic -Werror`) and pass on the Linux build host:
- `test_canonical_json` (8 tests passed): RFC 8785 sorting, escaping, numeric formatting.
- `test_consent_manager` (19 tests passed): State machine, generational tracking, phase authorization, revocation, unlaunched worker terminal state.
- `test_crc32` (8 tests passed): IEEE 802.3 polynomial, test vectors, buffer sizes.
- `test_event_pipeline` (8 tests passed): FIFO queue, consent gating, discard on revocation, multi-threaded race prevention.
- `test_event_schema` (14 tests passed): Strict field allowlist, canonical JSON serialization, validation.
- `test_journal_engine` (11 tests passed): Monotonic sequence, checksum validation, trailing garbage & injected key rejection.
- `test_rotation_engine` (13 tests passed): Ordered rotation, archive shifting, crash recovery states, identity checks.
- `test_storage_quota` (8 tests passed): Exact-fit admission, one-byte-over rejection, overlap accounting, integer overflow prevention.
- `test_win32_security` (4 tests passed): Canonical SDDL formatting, custom SID formatting, user SID query, non-Windows platform boundary checks.

See [AUDIT_STAGE2.md](AUDIT_STAGE2.md) for full audit findings and remediation details.

### Platform Limitations (Unexecuted - Windows 11 Host Required)
The following tests are **DESIGNED — NOT EXECUTED** due to the absence of a physical or virtual Windows 11 test host:
- **WinHTTP TLS 1.2 Wire Tests (TC-WIN-01 to TC-WIN-05):** Real network packet capture and controlled HTTPS server tests for TLS 1.2 handshake, certificate revocation, redirect rejection, and interleaved authorization revocation.
- **NTFS ACL Verification (TC-WIN-06 to TC-WIN-08):** Live `GetNamedSecurityInfoW` inspection of owner SID and protected DACL with exact ACE count on NTFS. (SDDL string generation is verified on Linux, but NTFS kernel enforcement requires Windows).
- **Win32 GUI Loop (TC-WIN-09 to TC-WIN-12):** Live Win32 message pump, button click event handling, URL scheme validation, and window rendering.

See [WINDOWS_VERIFICATION_PLAN.md](WINDOWS_VERIFICATION_PLAN.md) for the complete native Windows 11 verification suite and execution sign-off matrix.

---

## 6. Legacy Isolation Confirmation

The legacy reference directory `/home/hamza/Documents/Keylogger/` was strictly segregated and preserved untouched. No legacy files were accessed, read, copied, compiled, or referenced.
