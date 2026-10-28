// ConsentMonitor — test_consent_manager.cpp
// Tests for the consent state machine and network worker phase tracking.
// Copyright 2026 ConsentMonitor Contributors. MIT License.

#include "test_framework.hpp"
#include <consent_monitor/consent_manager.hpp>

#include <string>

using namespace consent_monitor;

int main() {
    cm_test::Suite suite("ConsentManager");

    // 1. Initial state is Idle, generation 0
    suite.add("Initial state is Idle, generation 0", [] {
        ConsentManager cm;
        ASSERT_EQ(cm.GetState(), ConsentState::Idle);
        ASSERT_EQ(cm.GetGeneration(), uint64_t{0});
    });

    // 2. GrantConsent from Idle → Granted, generation 1
    suite.add("GrantConsent from Idle transitions to Granted gen 1", [] {
        ConsentManager cm;
        auto r = cm.GrantConsent();
        ASSERT_TRUE(r.ok);
        ASSERT_EQ(r.value, uint64_t{1});
        ASSERT_EQ(cm.GetState(), ConsentState::Granted);
        ASSERT_EQ(cm.GetGeneration(), uint64_t{1});
    });

    // 3. GrantConsent while Granted → idempotent, returns gen 1
    suite.add("GrantConsent while Granted is idempotent", [] {
        ConsentManager cm;
        cm.GrantConsent();
        auto r = cm.GrantConsent();
        ASSERT_TRUE(r.ok);
        ASSERT_EQ(r.value, uint64_t{1});
        ASSERT_EQ(cm.GetGeneration(), uint64_t{1});
    });

    // 4. RevokeConsent from Granted → Revoked, cancel flag set
    suite.add("RevokeConsent from Granted sets Revoked and cancel flag", [] {
        ConsentManager cm;
        cm.GrantConsent();
        auto r = cm.RevokeConsent();
        ASSERT_TRUE(r.ok);
        ASSERT_EQ(cm.GetState(), ConsentState::Revoked);
        ASSERT_TRUE(cm.IsCancelRequested());
    });

    // 5. GrantConsent after Revoke → new generation 2
    suite.add("GrantConsent after Revoke yields new generation", [] {
        ConsentManager cm;
        cm.GrantConsent();          // gen 1
        cm.RevokeConsent();
        auto r = cm.GrantConsent(); // gen 2
        ASSERT_TRUE(r.ok);
        ASSERT_EQ(r.value, uint64_t{2});
        ASSERT_EQ(cm.GetState(), ConsentState::Granted);
        ASSERT_FALSE(cm.IsCancelRequested());
    });

    // 6. PauseMonitoring from Granted → Paused
    suite.add("PauseMonitoring from Granted transitions to Paused", [] {
        ConsentManager cm;
        cm.GrantConsent();
        auto r = cm.PauseMonitoring();
        ASSERT_TRUE(r.ok);
        ASSERT_EQ(cm.GetState(), ConsentState::Paused);
    });

    // 7. ResumeMonitoring from Paused → Granted
    suite.add("ResumeMonitoring from Paused transitions to Granted", [] {
        ConsentManager cm;
        cm.GrantConsent();
        cm.PauseMonitoring();
        auto r = cm.ResumeMonitoring();
        ASSERT_TRUE(r.ok);
        ASSERT_EQ(cm.GetState(), ConsentState::Granted);
    });

    // 8. RevokeConsent from Paused → Revoked
    suite.add("RevokeConsent from Paused transitions to Revoked", [] {
        ConsentManager cm;
        cm.GrantConsent();
        cm.PauseMonitoring();
        auto r = cm.RevokeConsent();
        ASSERT_TRUE(r.ok);
        ASSERT_EQ(cm.GetState(), ConsentState::Revoked);
        ASSERT_TRUE(cm.IsCancelRequested());
    });

    // 9. Old generation cannot authorize (gen mismatch)
    suite.add("Old generation cannot authorize", [] {
        ConsentManager cm;
        cm.GrantConsent();          // gen 1
        cm.RevokeConsent();
        cm.GrantConsent();          // gen 2
        ASSERT_FALSE(cm.TryAuthorizeHeader(1));  // old gen
    });

    // 10. TryAuthorizeHeader succeeds with correct gen and Granted state
    suite.add("TryAuthorizeHeader succeeds with correct gen", [] {
        ConsentManager cm;
        auto r = cm.GrantConsent();
        ASSERT_TRUE(cm.TryAuthorizeHeader(r.value));
        ASSERT_EQ(cm.GetWorkerPhase(r.value), NetworkWorkerPhase::HeaderAuthorized);
    });

    // 11. TryAuthorizeBody after header authorized, correct gen
    suite.add("TryAuthorizeBody succeeds after header", [] {
        ConsentManager cm;
        auto r = cm.GrantConsent();
        cm.TryAuthorizeHeader(r.value);
        ASSERT_TRUE(cm.TryAuthorizeBody(r.value));
        ASSERT_EQ(cm.GetWorkerPhase(r.value), NetworkWorkerPhase::BodyAuthorized);
    });

    // 12. TryAuthorizeResponse after body authorized, correct gen
    suite.add("TryAuthorizeResponse succeeds after body", [] {
        ConsentManager cm;
        auto r = cm.GrantConsent();
        cm.TryAuthorizeHeader(r.value);
        cm.TryAuthorizeBody(r.value);
        ASSERT_TRUE(cm.TryAuthorizeResponse(r.value));
        ASSERT_EQ(cm.GetWorkerPhase(r.value), NetworkWorkerPhase::ResponseAuthorized);
    });

    // 13. TryAuthorizeResponse fails after revocation (response skipped)
    suite.add("TryAuthorizeResponse fails after revocation", [] {
        ConsentManager cm;
        auto r = cm.GrantConsent();
        cm.TryAuthorizeHeader(r.value);
        cm.RecordPhase(r.value, NetworkWorkerPhase::HeaderSendInitiated);
        cm.TryAuthorizeBody(r.value);
        cm.RecordPhase(r.value, NetworkWorkerPhase::BodyWriteInitiated);
        cm.RevokeConsent();
        ASSERT_FALSE(cm.TryAuthorizeResponse(r.value));
    });

    // 14. Cancel flag blocks authorization
    suite.add("Cancel flag blocks authorization", [] {
        ConsentManager cm;
        auto r = cm.GrantConsent();
        cm.RevokeConsent();  // sets cancel flag
        ASSERT_TRUE(cm.IsCancelRequested());
        // Even if we somehow had the right gen, cancel blocks it
        // (state is now Revoked anyway).
        ASSERT_FALSE(cm.TryAuthorizeHeader(r.value));
    });

    // 15. MarkDrained sets drained flag
    suite.add("MarkDrained sets drained flag", [] {
        ConsentManager cm;
        auto r = cm.GrantConsent();
        cm.TryAuthorizeHeader(r.value);
        cm.RecordPhase(r.value, NetworkWorkerPhase::ClosingHandles);
        cm.MarkDrained(r.value);
        ASSERT_TRUE(cm.IsWorkerDrained(r.value));
        ASSERT_EQ(cm.GetWorkerPhase(r.value), NetworkWorkerPhase::Drained);
    });

    // 16. MarkDegraded enters Degraded_EgressUnknown
    suite.add("MarkDegraded enters Degraded_EgressUnknown", [] {
        ConsentManager cm;
        auto r = cm.GrantConsent();
        cm.TryAuthorizeHeader(r.value);
        cm.MarkDegraded(r.value);
        ASSERT_EQ(cm.GetWorkerPhase(r.value),
                  NetworkWorkerPhase::Degraded_EgressUnknown);
    });

    // 17. Status message reflects current state accurately
    suite.add("Status message reflects current state", [] {
        ConsentManager cm;
        {
            std::string msg = cm.GetStatusMessage();
            ASSERT_TRUE(msg.find("Idle") != std::string::npos);
        }
        cm.GrantConsent();
        {
            std::string msg = cm.GetStatusMessage();
            ASSERT_TRUE(msg.find("Granted") != std::string::npos);
        }
        cm.PauseMonitoring();
        {
            std::string msg = cm.GetStatusMessage();
            ASSERT_TRUE(msg.find("Paused") != std::string::npos);
        }
        cm.RevokeConsent();
        {
            std::string msg = cm.GetStatusMessage();
            ASSERT_TRUE(msg.find("Revoked") != std::string::npos);
        }
        // Check degraded message says "Egress state unknown" not "Egress stopped"
        cm.GrantConsent();  // gen 2
        auto gen = cm.GetGeneration();
        cm.TryAuthorizeHeader(gen);
        cm.MarkDegraded(gen);
        {
            std::string msg = cm.GetStatusMessage();
            ASSERT_TRUE(msg.find("Egress state unknown") != std::string::npos);
            ASSERT_TRUE(msg.find("Egress stopped") == std::string::npos);
        }
    });

    // 18. Multiple grant-revoke-grant cycles increment generation monotonically
    suite.add("Multiple cycles increment generation monotonically", [] {
        ConsentManager cm;
        for (uint64_t i = 1; i <= 5; ++i) {
            auto r = cm.GrantConsent();
            ASSERT_TRUE(r.ok);
            ASSERT_EQ(r.value, i);
            ASSERT_EQ(cm.GetGeneration(), i);
            cm.RevokeConsent();
        }
    });

    // 19. Unlaunched worker is terminal/drained
    suite.add("Unlaunched worker is terminal/drained", [] {
        ConsentManager cm;
        auto r = cm.GrantConsent();
        // Worker was never launched — no TryAuthorize called.
        ASSERT_TRUE(cm.IsWorkerDrained(r.value));
    });

    return suite.run();
}
