// ConsentMonitor — test_event_pipeline.cpp
// Tests for the consent-gated event queue.
// Copyright 2026 ConsentMonitor Contributors. MIT License.

#include "test_framework.hpp"
#include <consent_monitor/consent_manager.hpp>
#include <consent_monitor/event_pipeline.hpp>
#include <consent_monitor/event_schema.hpp>
#include <atomic>
#include <thread>

using namespace consent_monitor;

static EventRecord make_event(EventType type) {
    EventRecord ev;
    ev.utc_time        = "2026-10-24T22:00:00Z";
    ev.event_type      = type;
    ev.app_version     = std::string(kAppVersion);
    ev.os_build        = "26100.1234";
    ev.result_category = "OK";
    ev.duration_ms     = 0;
    return ev;
}

int main() {
    cm_test::Suite suite("EventPipeline");

    // 1. Enqueue succeeds when consent granted
    suite.add("Enqueue succeeds when consent granted", [] {
        ConsentManager cm;
        cm.GrantConsent();
        EventPipeline pipe(cm);

        bool ok = pipe.Enqueue(make_event(EventType::AppStart));
        ASSERT_TRUE(ok);
        ASSERT_EQ(pipe.Size(), size_t{1});
    });

    // 2. Enqueue rejected when consent revoked
    suite.add("Enqueue rejected when consent revoked", [] {
        ConsentManager cm;
        cm.GrantConsent();
        cm.RevokeConsent();
        EventPipeline pipe(cm);

        bool ok = pipe.Enqueue(make_event(EventType::AppStart));
        ASSERT_FALSE(ok);
        ASSERT_EQ(pipe.Size(), size_t{0});
    });

    // 3. Dequeue returns events in FIFO order
    suite.add("Dequeue returns events in FIFO order", [] {
        ConsentManager cm;
        cm.GrantConsent();
        EventPipeline pipe(cm);

        pipe.Enqueue(make_event(EventType::AppStart));
        pipe.Enqueue(make_event(EventType::AppStop));

        auto e1 = pipe.Dequeue();
        ASSERT_TRUE(e1.has_value());
        ASSERT_EQ(static_cast<uint8_t>(e1->event_type),
                  static_cast<uint8_t>(EventType::AppStart));

        auto e2 = pipe.Dequeue();
        ASSERT_TRUE(e2.has_value());
        ASSERT_EQ(static_cast<uint8_t>(e2->event_type),
                  static_cast<uint8_t>(EventType::AppStop));

        auto e3 = pipe.Dequeue();
        ASSERT_FALSE(e3.has_value());
    });

    // 4. DiscardAll empties queue and increments discard counter
    suite.add("DiscardAll empties queue and increments discard counter", [] {
        ConsentManager cm;
        cm.GrantConsent();
        EventPipeline pipe(cm);

        pipe.Enqueue(make_event(EventType::AppStart));
        pipe.Enqueue(make_event(EventType::AppStop));
        ASSERT_EQ(pipe.Size(), size_t{2});

        pipe.DiscardAll();
        ASSERT_EQ(pipe.Size(), size_t{0});
        ASSERT_TRUE(pipe.IsEmpty());
        ASSERT_EQ(pipe.TotalDiscarded(), size_t{2});
    });

    // 5. Size and IsEmpty are correct
    suite.add("Size and IsEmpty are correct", [] {
        ConsentManager cm;
        cm.GrantConsent();
        EventPipeline pipe(cm);

        ASSERT_TRUE(pipe.IsEmpty());
        ASSERT_EQ(pipe.Size(), size_t{0});

        pipe.Enqueue(make_event(EventType::ConsentGranted));
        ASSERT_FALSE(pipe.IsEmpty());
        ASSERT_EQ(pipe.Size(), size_t{1});

        pipe.Dequeue();
        ASSERT_TRUE(pipe.IsEmpty());
        ASSERT_EQ(pipe.Size(), size_t{0});
    });

    // 6. TotalEnqueued and TotalDiscarded track lifetime counts
    suite.add("TotalEnqueued and TotalDiscarded track lifetime counts", [] {
        ConsentManager cm;
        cm.GrantConsent();
        EventPipeline pipe(cm);

        pipe.Enqueue(make_event(EventType::AppStart));
        pipe.Enqueue(make_event(EventType::AppStop));
        pipe.Enqueue(make_event(EventType::ConsentGranted));
        ASSERT_EQ(pipe.TotalEnqueued(), size_t{3});

        pipe.Dequeue();  // consume 1
        ASSERT_EQ(pipe.TotalEnqueued(), size_t{3}); // unchanged

        pipe.DiscardAll(); // discard remaining 2
        ASSERT_EQ(pipe.TotalDiscarded(), size_t{2});

        // Enqueue more
        pipe.Enqueue(make_event(EventType::AppStart));
        ASSERT_EQ(pipe.TotalEnqueued(), size_t{4});

        pipe.DiscardAll();
        ASSERT_EQ(pipe.TotalDiscarded(), size_t{3}); // 2 + 1
    });

    // 7. Enqueue after revoke-then-re-grant works with new state
    suite.add("Enqueue after revoke-then-re-grant works", [] {
        ConsentManager cm;
        cm.GrantConsent();
        EventPipeline pipe(cm);

        pipe.Enqueue(make_event(EventType::AppStart));
        ASSERT_EQ(pipe.Size(), size_t{1});

        cm.RevokeConsent();
        pipe.DiscardAll();  // simulate revocation cleanup

        // Rejected while revoked
        bool ok = pipe.Enqueue(make_event(EventType::AppStart));
        ASSERT_FALSE(ok);

        // Re-grant
        cm.GrantConsent();
        ok = pipe.Enqueue(make_event(EventType::AppStart));
        ASSERT_TRUE(ok);
        ASSERT_EQ(pipe.Size(), size_t{1});
    });

    // 8. Deterministic concurrency: Enqueue and Revoke synchronization
    suite.add("Concurrent enqueue and revocation synchronization", [] {
        ConsentManager cm;
        cm.GrantConsent();
        EventPipeline pipe(cm);

        std::atomic<bool> start_flag{false};
        std::atomic<int> enqueued_count{0};

        // Thread 1: attempts to enqueue 1000 events
        std::thread t1([&] {
            while (!start_flag.load(std::memory_order_acquire)) {}
            for (int i = 0; i < 1000; ++i) {
                if (pipe.Enqueue(make_event(EventType::OperationDuration))) {
                    enqueued_count.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });

        // Thread 2: revokes consent and purges queue
        std::thread t2([&] {
            while (!start_flag.load(std::memory_order_acquire)) {}
            cm.RevokeConsent();
            pipe.DiscardAll();
        });

        start_flag.store(true, std::memory_order_release);
        t1.join();
        t2.join();

        // After both finish, consent is Revoked.
        // Queue must either be empty or only contain events if DiscardAll ran before Enqueue,
        // but now trying to Enqueue must fail.
        ASSERT_FALSE(pipe.Enqueue(make_event(EventType::AppStart)));

        // Now discard any remaining (if any slipped in before revoke)
        pipe.DiscardAll();
        ASSERT_EQ(pipe.Size(), size_t{0});
    });

    return suite.run();
}
