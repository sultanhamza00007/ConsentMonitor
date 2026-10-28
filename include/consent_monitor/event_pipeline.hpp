// ConsentMonitor — event_pipeline.hpp
// Thread-safe event queue that respects consent state.
// Copyright 2026 ConsentMonitor Contributors. MIT License.

#pragma once

#include <consent_monitor/common.hpp>
#include <consent_monitor/event_schema.hpp>

#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>

namespace consent_monitor {

// Forward declaration — avoids circular include.
class ConsentManager;

// ─── EventPipeline ─────────────────────────────────────────────────────────
// Thread-safe FIFO queue for EventRecords. Enqueue is gated on active
// consent; revocation triggers a full discard.

class EventPipeline {
public:
    /// Construct with a reference to the consent manager whose state
    /// determines whether events may be enqueued.
    explicit EventPipeline(ConsentManager& cm);

    /// Enqueue an event if consent is currently active (Granted or Paused).
    /// Returns true on success, false if consent is not active.
    bool Enqueue(EventRecord event);

    /// Dequeue the front event, or std::nullopt if the queue is empty.
    std::optional<EventRecord> Dequeue();

    /// Discard every queued event. Typically called on revocation.
    void DiscardAll();

    /// Current queue depth.
    size_t Size() const;

    /// Whether the queue is empty.
    bool IsEmpty() const;

    /// Lifetime counter of successfully enqueued events.
    size_t TotalEnqueued() const;

    /// Lifetime counter of discarded events.
    size_t TotalDiscarded() const;

private:
    ConsentManager&          consent_mgr_;
    mutable std::mutex       mutex_;
    std::deque<EventRecord>  queue_;
    size_t                   total_enqueued_{0};
    size_t                   total_discarded_{0};
};

} // namespace consent_monitor
