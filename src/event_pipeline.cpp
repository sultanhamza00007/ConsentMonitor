// ConsentMonitor — event_pipeline.cpp
// Thread-safe event queue gated on consent state.

#include <consent_monitor/event_pipeline.hpp>
#include <consent_monitor/consent_manager.hpp>

namespace consent_monitor {

EventPipeline::EventPipeline(ConsentManager& cm) : consent_mgr_(cm) {}

bool EventPipeline::Enqueue(EventRecord event) {
    std::lock_guard lock(mutex_);

    // Check consent state under lock to prevent check-then-act races with revocation
    auto state = consent_mgr_.GetState();
    if (state != ConsentState::Granted && state != ConsentState::Paused)
        return false;

    queue_.push_back(std::move(event));
    ++total_enqueued_;
    return true;
}

std::optional<EventRecord> EventPipeline::Dequeue() {
    std::lock_guard lock(mutex_);
    if (queue_.empty()) return std::nullopt;
    EventRecord rec = std::move(queue_.front());
    queue_.pop_front();
    return rec;
}

void EventPipeline::DiscardAll() {
    std::lock_guard lock(mutex_);
    total_discarded_ += queue_.size();
    queue_.clear();
}

size_t EventPipeline::Size() const {
    std::lock_guard lock(mutex_);
    return queue_.size();
}

bool EventPipeline::IsEmpty() const {
    std::lock_guard lock(mutex_);
    return queue_.empty();
}

size_t EventPipeline::TotalEnqueued() const {
    std::lock_guard lock(mutex_);
    return total_enqueued_;
}

size_t EventPipeline::TotalDiscarded() const {
    std::lock_guard lock(mutex_);
    return total_discarded_;
}

} // namespace consent_monitor
