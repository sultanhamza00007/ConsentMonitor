# ConsentMonitor — Architecture & Design Specification

**Document Version:** 2.0.0 (Stage 2 Implementation Baseline)  
**Platform:** 64-bit Windows 11, versions 25H2 and 26H2, on active servicing channels.  
**Scope:** Transparent, user-mode, consent-based diagnostic monitoring.

---

## 1. Scope & Safety Boundaries

### 1.1 Allowed Diagnostic Events
Only app-generated diagnostics are collected:
- Application start / stop
- Consent state changes (Granted, Paused, Resumed, Revoked)
- Network egress attempt outcomes (success / failure category)
- Storage errors (rotation failure, disk full, quota exceeded)
- Bounded operation durations (milliseconds)

### 1.2 Allowed Event Fields
| Field | Type | Description |
|-------|------|-------------|
| `utc_time` | string | ISO 8601 UTC timestamp |
| `event_type` | string | Enumerated event category |
| `app_version` | string | Application version |
| `os_build` | string | Supported OS build number |
| `result_category` | string | Bounded result/error category |
| `duration_ms` | uint32 | Operation duration in milliseconds |

### 1.3 Prohibited Data
Keystrokes, window/document contents, clipboard data, credentials, usernames,
device identifiers, arbitrary filesystem paths, and user content are **never**
collected, serialized, logged, or transmitted.

### 1.4 Exclusions
No kernel drivers, keyboard filters, covert hooks, credential access, stealth
mechanisms, or persistence beyond the user-launched application lifetime.

---

## 2. Consent & Generational State Machine

### 2.1 States
```
Idle → Granted → Paused → Granted → Revoked → Granted (new gen) → ...
                    └──────────────→ Revoked
```

- **Idle:** Initial state. No consent has been given.
- **Granted:** User has actively granted consent. Monitoring and (optionally) network egress are authorized.
- **Paused:** Monitoring paused; consent not withdrawn.
- **Revoked:** Consent explicitly withdrawn. All queued events discarded, new network authorizations blocked.

### 2.2 Generation Tracking
- `consent_generation` is a monotonically increasing uint64_t counter.
- `GrantConsent()` from Idle or Revoked increments the generation.
- `GrantConsent()` while already Granted is idempotent (returns current generation).
- `RevokeConsent()` sets `network_cancel_requested` atomically and transitions to Revoked.
- Re-consent (Grant after Revoke) creates a **new generation**; old-generation workers detect the mismatch and abort.
- An unlaunched worker is considered terminal and drained.
- Repeated grant while active is rejected or idempotent.

### 2.3 Revocation Guarantees
On revocation:
1. Immediately stop creating new telemetry events.
2. Discard all queued unsent events.
3. Block all new network authorizations.
4. Set `network_cancel_requested` atomically.
5. A previously authorized network call may still be starting or in flight and may transmit some or all of its buffer.
6. The UI states this explicitly until the worker has returned and closed its handles.
7. No universal cancellation deadline is promised.

---

## 3. Network Dispatch — Two-Stage Authorization with Response Gate

### 3.1 Worker Thread Model
- One dedicated synchronous WinHTTP worker thread.
- The UI thread **never** closes a request handle or waits on network completion.
- `ConsentStateLock` (std::mutex) protects only in-memory state changes.
- The lock is **never** held across WinHTTP calls, socket waits, thread joins, file I/O, or handle closure.

### 3.2 Authorization Points
All authorization points represent **permission granted**, not proof that an API call has started. API outcomes are recorded only after calls return.

| Step | Authorization | Under Lock | API Call |
|------|--------------|------------|----------|
| 1 | `HeaderAuthorized` | Yes | `WinHttpSendRequest(..., NULL, 0)` |
| 2 | `BodyAuthorized` | Yes | `WinHttpWriteData(buffer, len)` |
| 3 | `ResponseAuthorized` | Yes | `WinHttpReceiveResponse` |

### 3.3 Interleaving Rules

**Commit → Revoke → Worker reaches WinHttpSendRequest:**
If header authorization was committed under lock before revocation, the worker may call `WinHttpSendRequest` after `RevokeConsent()` returns. The request was already authorized. The body authorization check will then fail (revoked), so `WinHttpWriteData` is never called.

**Revocation before body commitment:**
`WinHttpWriteData` is skipped. Handles are closed. At the local API level, the evidence is that `WinHttpWriteData` was never called. This does not prove zero network packets were sent at the wire level; it proves the application did not invoke the body-write API.

**Body committed before revocation:**
`WinHttpWriteData` proceeds. It may transmit some or all of its buffer. The actual byte count reported by the API is recorded. Zero automatic retries. No continuation of a partial write.

**Revocation before response authorization:**
If consent is revoked before `ResponseAuthorized` is checked, `WinHttpReceiveResponse` is **skipped**. The worker closes handles and records: "body write completed/attempted; response not awaited (consent revoked)." This means the worker does not wait for a server reply after the user has withdrawn consent.

**Handle closure failure:**
A failed or uncertain `WinHttpCloseHandle` transitions to `Degraded_EgressUnknown`. The worker is **not** marked drained. The UI displays "Egress state unknown" — never "Egress stopped."

### 3.4 Evidence Layers
Tests and status reports must distinguish:
- **Local API evidence:** Which WinHTTP functions were called and what they returned.
- **Packet-capture evidence:** What was observed on the wire (requires pcap/Wireshark on Windows host).
- **Server-observed evidence:** What the HTTPS server logged in its access log.

Server silence does not prove no network packets were sent. Local API non-invocation proves the application did not call the API, but does not address lower-layer behavior.

### 3.5 Payload Buffer Lifetime
The payload buffer remains valid until the synchronous `WinHttpWriteData` call returns. (Not "pinned" — simply held in scope for the call's duration.)

---

## 4. WinHTTP Transport Security

> **Platform requirement:** These settings require Windows 11 WinHTTP and are verified only on a Windows 11 test host.

- **TLS Protocol:** TLS 1.2 configured as the sole allowed protocol (`WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2`). Fail closed if configuration fails.
- **Certificate Validation:** Full chain and hostname validation. All `SECURITY_FLAG_IGNORE_*` flags prohibited. Certificate-revocation checking required; if revocation status cannot be established, fail closed.
- **Redirects:** Disabled before sending: `WINHTTP_OPTION_REDIRECT_POLICY` = `WINHTTP_OPTION_REDIRECT_POLICY_NEVER`.
- **Proxy:** Direct connection only. No proxy configuration.
- **Credentials:** No cookies, authentication tokens, or credentials are ever sent.
- **Endpoint:** User must manually enter and review the HTTPS endpoint URL. No default remote endpoint is configured.

---

## 5. Local Storage, SDDL Security & Quota

### 5.1 Single-Writer Mutex
A per-user global mutex ensures single-writer exclusivity.

### 5.2 Security Descriptors (SDDL)

> **Platform requirement:** NTFS ACL enforcement is verified only on a Windows 11 test host. SDDL string formatting tests on Linux verify string construction, NOT Windows ACL enforcement.

- Owner: Current process User SID (`O:<UserSID>`).
- DACL: Protected (`D:P`).
- ACEs: Exactly two Full Control entries: `(A;OICI;GA;;;<UserSID>)(A;OICI;GA;;;SY)`.
- Verification: `GetNamedSecurityInfoW` post-creation checks the actual ACE set (owner, protected-DACL bit, exact ACE count and masks), not only the protected-DACL bit.
- This is access control, not protection from the owning user.

### 5.3 Quota Boundaries

| Boundary | Value | Purpose |
|----------|-------|---------|
| Active file ceiling | 5,242,880 B (5 MiB) | Trigger rotation |
| Max archives | 3 | Retention limit |
| Hard ceiling | 20,971,520 B (20 MiB) | Absolute maximum |
| Ordinary write cap | 20,905,984 B (≈19.94 MiB) | Normal write limit |
| Lifecycle reserve | 65,536 B (64 KiB) | Journal/rotation headroom |

Aggregate quota includes: active file, all archives, staging files, recovered files, journal file, and temporary journal files.

**Exact-fit admission:** 20,904,960 B + 1,024 B event = 20,905,984 B → Admitted.  
**One-byte-over rejection:** 20,904,961 B + 1,024 B event = 20,905,985 B → Rejected before queueing.

### 5.4 Write Failure Handling
On `ERROR_DISK_FULL` or write failure:
- Halt ordinary logging immediately.
- Preserve existing bytes without deliberate truncation.
- UI reports: "A final event may be incomplete."
- A partial final record may remain on disk.

---

## 6. Rotation Journal State Machine

### 6.1 Journal Record Schema
RFC 8785 JCS canonical JSON containing:
- `schema_version`, `rotation_id`, `journal_seq`, `operation`, `phase`
- `source_path`, `destination_path`, `expected_identity`, `checksum`

Checksum: CRC-32/IEEE over canonical JSON with checksum field omitted. Detects accidental corruption, not forgery.

### 6.2 Sequence Rules
- Derived dynamically: `next_seq = last_valid_persisted_seq + 1`.
- Increments exactly once per successfully persisted `PREPARED`, `COMPLETED`, or `ABSENT` snapshot.
- Each snapshot written to a unique same-directory temp file, flushed and closed before replacement.
- Both temp and journal copies counted against quota during overlap.

### 6.3 Rotation Sequence (Ordered)
1. **CLOSE_ACTIVE:** Flush and close active log handle → PREPARED → COMPLETED
2. **MOVE_TO_STAGING:** Rename `active.log` → `active.log.staging`
3. **RETIRE_ARCHIVE_3:** Delete `archive.3` if present → COMPLETED; or → ABSENT
4. **SHIFT_2_TO_3:** Rename `archive.2` → `archive.3`; or → ABSENT
5. **SHIFT_1_TO_2:** Rename `archive.1` → `archive.2`; or → ABSENT
6. **PROMOTE_STAGING_TO_1:** Rename `active.log.staging` → `archive.1`
7. **CREATE_ACTIVE:** Create fresh `active.log` with `CREATE_NEW` + verified ACL
8. **ROTATION_COMPLETE:** Persist completion, then clear journal

### 6.4 `MOVEFILE_WRITE_THROUGH` Scope
Relied upon only for documented behavior: copy-and-delete with target flush. Not described as a multi-file transaction or universal power-loss guarantee. See: [MoveFileExW documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).

### 6.5 Crash Recovery
On startup: acquire writer lock, validate ACLs, enumerate all known paths, suspend logging until recovery completes.

| Condition | Action |
|-----------|--------|
| No journal, normal layout (active present, no staging/temp) | Resume normally |
| No journal, archive gaps | Preserve gaps, report without renumbering |
| Active journal, no temp | Reconcile recorded operation |
| Active journal + one valid next-seq temp | Promote if phase agrees with disk |
| No active journal + unique valid CLOSE_ACTIVE/PREPARED temp + canonical layout | Promote and proceed |
| PREPARED: source present, dest absent | Perform operation |
| PREPARED: source absent, dest matches identity | Treat as already complete |
| COMPLETED: verify postconditions | Verify and proceed |
| ABSENT: verify source absent | Verify and proceed |
| .3 RETIRE_ARCHIVE_3/PREPARED + absent .3 | Satisfies postcondition |
| Multiple temps / bad checksum / seq mismatch / identity mismatch / unexpected files | **Halt without cleanup.** Preserve evidence. Report operator repair required. |

---

## 7. Test Classification & Platform Requirements

### 7.1 Portable Tests (Executed on Linux)
These tests exercise platform-independent C++20 logic:
- Event schema serialization and field allowlisting
- Consent state machine transitions and generation tracking
- Storage quota calculations and admission boundaries
- CRC-32/IEEE computation
- RFC 8785 canonical JSON serialization
- Journal state machine (sequence, checksum, phases)
- Rotation engine logic with in-memory filesystem
- Event pipeline queue management
- SDDL string construction (formatting only — not ACL enforcement)

### 7.2 Windows-Only Tests (Require Windows 11 Host)
These tests are **DESIGNED but marked UNEXECUTED** when no Windows 11 host is available:
- WinHTTP TLS 1.2 client against controlled HTTPS endpoint
- Certificate chain, hostname, and revocation validation
- Redirect policy enforcement
- NTFS ACL enforcement via `GetNamedSecurityInfoW`
- Win32 GUI window loop and status rendering
- Packet-capture evidence (Wireshark/pcap)
- `MoveFileExW` with `MOVEFILE_WRITE_THROUGH` behavior
- Actual `CreateFileW` with `CREATE_NEW` semantics and security descriptor

---

## 8. Project Layout

```
/home/hamza/pd_project/ConsentMonitor/
├── ARCHITECTURE.md          ← This document
├── README.md                ← Usage guide and build instructions
├── CMakeLists.txt           ← Windows build (MSVC + Windows SDK)
├── Makefile                 ← Linux portable test build (g++ 13.3)
├── include/
│   └── consent_monitor/
│       ├── common.hpp               ← Shared constants and Result<T>
│       ├── crc32.hpp                ← CRC-32/IEEE
│       ├── canonical_json.hpp       ← RFC 8785 JCS serializer
│       ├── event_schema.hpp         ← Event types and serialization
│       ├── consent_manager.hpp      ← Consent state machine
│       ├── storage_quota.hpp        ← Quota calculator
│       ├── journal_types.hpp        ← Journal enums and record struct
│       ├── filesystem_interface.hpp ← Abstract FS + InMemoryFilesystem
│       ├── journal_engine.hpp       ← Journal persistence engine
│       ├── rotation_engine.hpp      ← Rotation sequence + crash recovery
│       ├── event_pipeline.hpp       ← Event queue management
│       ├── winhttp_client.hpp       ← WinHTTP client (Windows-only)
│       └── win32_security.hpp       ← SDDL/ACL (Windows-only)
├── src/
│   ├── crc32.cpp
│   ├── canonical_json.cpp
│   ├── event_schema.cpp
│   ├── consent_manager.cpp
│   ├── storage_quota.cpp
│   ├── journal_engine.cpp
│   ├── rotation_engine.cpp
│   ├── event_pipeline.cpp
│   ├── winhttp_client.cpp           ← Windows-only
│   ├── win32_security.cpp           ← Windows-only
│   ├── win32_window.cpp             ← Windows-only GUI
│   └── main.cpp                     ← Windows-only entry point
└── tests/
    ├── test_framework.hpp           ← Zero-dependency test harness
    ├── test_crc32.cpp
    ├── test_canonical_json.cpp
    ├── test_event_schema.cpp
    ├── test_consent_manager.cpp
    ├── test_storage_quota.cpp
    ├── test_journal_engine.cpp
    ├── test_rotation_engine.cpp
    └── test_event_pipeline.cpp
```

---

## 9. Legacy Isolation

- `/home/hamza/Documents/Keylogger/` is completely segregated.
- No files there are read, copied, executed, modified, or referenced during implementation.
- Legacy code is not used as an implementation source.
