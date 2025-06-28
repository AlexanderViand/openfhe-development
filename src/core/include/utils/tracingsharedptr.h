#ifndef __TRACINGSHAREDPTR_H__
#define __TRACINGSHAREDPTR_H__

#include "config_core.h"

namespace lbcrypto {

#ifdef ENABLE_TRACER_SUPPORT
    #include <memory>
    #include <type_traits>
    #include <utility>
    #include "cryptocontext-fwd.h"
    #include "utils/tracing.h"

// Helper used to emit trace events. Primary template does nothing.
template <class T, class = void>
struct TraceHelper {
    static void onUpdate(const T*, const char*) {}
};

// Enabled when T has a GetCryptoContext() method
template <class T>
struct TraceHelper<T, std::void_t<decltype(std::declval<const T&>().GetCryptoContext())>> {
    static void onUpdate(const T* obj, const char* name) {
        auto cc = obj->GetCryptoContext();
        cc->getTracer()->TraceDataUpdate(name);
    }
};

/**
 * Wrapper around std::shared_ptr that emits tracing callbacks when constructed
 * or assigned.
 */
template <typename T>
class TracingSharedPtr : public std::shared_ptr<T> {
    using Base = std::shared_ptr<T>;

public:
    using Base::shared_ptr;
    TracingSharedPtr() = default;

    template <class U>
    explicit TracingSharedPtr(U* ptr) : Base(ptr) {
        trace("rawptr-ctor");
    }

    template <class U, class Deleter>
    explicit TracingSharedPtr(U* ptr, Deleter d) : Base(ptr, d) {
        trace("rawptr-ctor");
    }

    template <class U>
    TracingSharedPtr(const std::shared_ptr<U>& other)  // NOLINT(runtime/explicit)
        : Base(other) {
        trace("copy-ctor");
    }

    template <class U>
    TracingSharedPtr(std::shared_ptr<U>&& other)  // NOLINT(runtime/explicit)
        : Base(std::move(other)) {
        trace("move-ctor");
    }

    template <class U>
    TracingSharedPtr(const TracingSharedPtr<U>& other)  // NOLINT(runtime/explicit)
        : Base(other) {
        trace("copy-ctor");
    }

    template <class U>
    TracingSharedPtr(TracingSharedPtr<U>&& other)  // NOLINT(runtime/explicit)
        : Base(std::move(other)) {
        trace("move-ctor");
    }

    TracingSharedPtr(const TracingSharedPtr& other) : Base(other) {
        trace("copy-ctor");
    }

    TracingSharedPtr(TracingSharedPtr&& other) noexcept : Base(std::move(other)) {
        trace("move-ctor");
    }

    TracingSharedPtr& operator=(const TracingSharedPtr& other) {
        Base::operator=(other);
        trace("copy-assign");
        return *this;
    }

    TracingSharedPtr& operator=(TracingSharedPtr&& other) noexcept {
        Base::operator=(std::move(other));
        trace("move-assign");
        return *this;
    }

    template <class U>
    TracingSharedPtr& operator=(const TracingSharedPtr<U>& other) {
        Base::operator=(other);
        trace("copy-assign");
        return *this;
    }

    template <class U>
    TracingSharedPtr& operator=(TracingSharedPtr<U>&& other) {
        Base::operator=(std::move(other));
        trace("move-assign");
        return *this;
    }

    template <class U>
    TracingSharedPtr& operator=(const std::shared_ptr<U>& other) {
        Base::operator=(other);
        trace("assign");
        return *this;
    }

    template <class U>
    TracingSharedPtr& operator=(std::shared_ptr<U>&& other) {
        Base::operator=(std::move(other));
        trace("move-assign2");
        return *this;
    }

private:
    void trace(const char* name) const {
        if (auto obj = this->get()) {
            TraceHelper<T>::onUpdate(obj, name);
        }
    }
};

template <typename T>
using SharedPtr = TracingSharedPtr<T>;

#else

template <typename T>
using SharedPtr = std::shared_ptr<T>;

#endif  // ENABLE_TRACER_SUPPORT

}  // namespace lbcrypto

#endif  // __TRACINGSHAREDPTR_H__
