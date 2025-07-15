//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================
/*
 * SharedPtr wrapper class that provides tracing support for OpenFHE
 */
#ifndef __SHARED_PTR_H__
#define __SHARED_PTR_H__

#include <memory>
#include "config_core.h"

#ifndef ENABLE_TRACER_SUPPORT
namespace lbcrypto {

// If tracing is disabled, we simply make SharedPtr an alias for std::shared_ptr
template <typename T>
using SharedPtr = std::shared_ptr<T>;

// Define the shared_ptr namespace to match std::shared_ptr in case it was used explicitly somewhere
namespace shared_ptr = std;

// Expose the commonly used functions
using std::dynamic_pointer_cast;
using std::make_shared;
using std::static_pointer_cast;

}  // namespace lbcrypto

#else
    // If tracing is enabled, we define a SharedPtr class that wraps std::shared_ptr
    // and provides a tracing mechanism for shared pointer operations.

    #include <functional>

namespace detail {
// Type erasure for tracer callbacks
template <typename T>
struct TracerHolder {
    static std::function<void(const std::string&, const T*, const T*)> tracer;
};

template <typename T>
std::function<void(const std::string&, const T*, const T*)> TracerHolder<T>::tracer = nullptr;
}  // namespace detail

// Generic tracing function that uses the registered tracer
template <typename T>
void TraceSharedPtrOperation(const std::string& operation, const T* source, const T* destination) {
    if (detail::TracerHolder<T>::tracer) {
        detail::TracerHolder<T>::tracer(operation, source, destination);
    }
}

// Function for tracers to register their handlers
template <typename T>
void SetSharedPtrTracer(std::function<void(const std::string&, const T*, const T*)> tracer) {
    detail::TracerHolder<T>::tracer = std::move(tracer);
}

namespace lbcrypto {

namespace shared_ptr {

template <typename T>
class SharedPtr {
    std::shared_ptr<T> m_ptr;

    void traceOperation(const std::string& operation, const T* source = nullptr, const T* destination = nullptr) const {
        TraceSharedPtrOperation(operation, source, destination);
    }

public:
    using element_type = T;
    using weak_type    = std::weak_ptr<T>;
    using deleter_type = void (*)(T*);

    // Constructors
    constexpr SharedPtr() noexcept : m_ptr(nullptr) {
        traceOperation("default_construct");
    }
    constexpr SharedPtr(std::nullptr_t) noexcept : m_ptr(nullptr) {
        traceOperation("nullptr_construct");
    }
    explicit SharedPtr(T* p) : m_ptr(p) {
        traceOperation("raw_ptr_construct", nullptr, p);
    }
    template <typename D>
    SharedPtr(T* p, D d) : m_ptr(p, d) {
        traceOperation("raw_ptr_deleter_construct", nullptr, p);
    }
    template <typename D, typename A>
    SharedPtr(T* p, D d, A a) : m_ptr(p, d, a) {
        traceOperation("raw_ptr_deleter_allocator_construct", nullptr, p);
    }
    template <typename U>
    SharedPtr(const SharedPtr<U>& r, T* p) noexcept : m_ptr(r.m_ptr, p) {
        traceOperation("aliasing_construct", r.get(), p);
    }
    SharedPtr(std::shared_ptr<T> p) : m_ptr(p) {
        traceOperation("shared_ptr_construct", nullptr, p.get());
    }
    SharedPtr(const SharedPtr& other) : m_ptr(other.m_ptr) {
        traceOperation("copy_construct", other.get(), m_ptr.get());
    }
    SharedPtr(SharedPtr&& other) noexcept : m_ptr(std::move(other.m_ptr)) {
        traceOperation("move_construct", other.get(), m_ptr.get());
    }
    template <typename U, typename = typename std::enable_if<std::is_convertible<U*, T*>::value>::type>
    SharedPtr(const SharedPtr<U>& r) noexcept : m_ptr(r.internal()) {
        traceOperation("copy_construct_convertible", r.get(), m_ptr.get());
    }
    template <typename U, typename = typename std::enable_if<std::is_convertible<U*, T*>::value>::type>
    SharedPtr(SharedPtr<U>&& r) noexcept : m_ptr(std::move(r.internal())) {
        traceOperation("move_construct_convertible", r.get(), m_ptr.get());
    }

    // Assignment operators
    SharedPtr& operator=(const SharedPtr& other) {
        T* old_ptr = m_ptr.get();
        m_ptr      = other.m_ptr;
        traceOperation("copy_assign", other.get(), old_ptr);
        return *this;
    }
    SharedPtr& operator=(SharedPtr&& other) noexcept {
        T* old_ptr = m_ptr.get();
        m_ptr      = std::move(other.m_ptr);
        traceOperation("move_assign", other.get(), old_ptr);
        return *this;
    }
    SharedPtr& operator=(std::nullptr_t) noexcept {
        T* old_ptr = m_ptr.get();
        m_ptr      = nullptr;
        traceOperation("nullptr_assign", nullptr, old_ptr);
        return *this;
    }
    SharedPtr& operator=(std::shared_ptr<T> p) {
        T* old_ptr = m_ptr.get();
        m_ptr      = p;
        traceOperation("shared_ptr_assign", p.get(), old_ptr);
        return *this;
    }

    // Dereference operators
    typename std::add_lvalue_reference<T>::type operator*() const noexcept {
        return *m_ptr;
    }
    T* operator->() const noexcept {
        return m_ptr.operator->();
    }
    template <typename U = T, typename = typename std::enable_if<std::is_array<U>::value>::type>
    typename std::add_lvalue_reference<T>::type operator[](std::ptrdiff_t idx) const {
        return m_ptr[idx];
    }

    // Get raw pointer
    T* get() const noexcept {
        return m_ptr.get();
    }

    // Reset
    void reset() noexcept {
        m_ptr.reset();
    }
    void reset(T* p) {
        m_ptr.reset(p);
    }
    template <typename D>
    void reset(T* p, D d) {
        m_ptr.reset(p, d);
    }
    template <typename D, typename A>
    void reset(T* p, D d, A a) {
        m_ptr.reset(p, d, a);
    }
    void reset(std::shared_ptr<T> p) {
        m_ptr = p;
    }

    // Observers
    long use_count() const noexcept {
        return m_ptr.use_count();
    }
    bool unique() const noexcept {
        return m_ptr.unique();
    }
    explicit operator bool() const noexcept {
        return static_cast<bool>(m_ptr);
    }

    // Modifiers
    void swap(SharedPtr& other) noexcept {
        m_ptr.swap(other.m_ptr);
    }

    // Owner-based ordering
    template <typename U>
    bool owner_before(const SharedPtr<U>& other) const noexcept {
        return m_ptr.owner_before(other.m_ptr);
    }
    template <typename U>
    bool owner_before(const std::weak_ptr<U>& other) const noexcept {
        return m_ptr.owner_before(other);
    }

    // Friend declarations for comparison operators and access
    template <typename U>
    friend class SharedPtr;

    template <typename T1, typename U>
    friend bool operator==(const SharedPtr<T1>&, const SharedPtr<U>&) noexcept;
    template <typename T1, typename U>
    friend bool operator!=(const SharedPtr<T1>&, const SharedPtr<U>&) noexcept;
    template <typename T1, typename U>
    friend bool operator<(const SharedPtr<T1>&, const SharedPtr<U>&) noexcept;
    template <typename T1, typename U>
    friend bool operator<=(const SharedPtr<T1>&, const SharedPtr<U>&) noexcept;
    template <typename T1, typename U>
    friend bool operator>(const SharedPtr<T1>&, const SharedPtr<U>&) noexcept;
    template <typename T1, typename U>
    friend bool operator>=(const SharedPtr<T1>&, const SharedPtr<U>&) noexcept;

    // Get the underlying shared_ptr
    const std::shared_ptr<T>& internal() const noexcept {
        return m_ptr;
    }
    std::shared_ptr<T>& internal() noexcept {
        return m_ptr;
    }

    // Serialization support
    template <class Archive>
    void serialize(Archive& ar) {
        ar(m_ptr);
    }
};

// Free function comparisons
template <typename T, typename U>
bool operator==(const SharedPtr<T>& lhs, const SharedPtr<U>& rhs) noexcept {
    return lhs.internal() == rhs.internal();
}

template <typename T>
bool operator==(const SharedPtr<T>& lhs, std::nullptr_t) noexcept {
    return !lhs;
}

template <typename T>
bool operator==(std::nullptr_t, const SharedPtr<T>& rhs) noexcept {
    return !rhs;
}

template <typename T, typename U>
bool operator!=(const SharedPtr<T>& lhs, const SharedPtr<U>& rhs) noexcept {
    return !(lhs == rhs);
}

template <typename T>
bool operator!=(const SharedPtr<T>& lhs, std::nullptr_t) noexcept {
    return static_cast<bool>(lhs);
}

template <typename T>
bool operator!=(std::nullptr_t, const SharedPtr<T>& rhs) noexcept {
    return static_cast<bool>(rhs);
}

template <typename T, typename U>
bool operator<(const SharedPtr<T>& lhs, const SharedPtr<U>& rhs) noexcept {
    return lhs.internal() < rhs.internal();
}

template <typename T>
bool operator<(const SharedPtr<T>& lhs, std::nullptr_t) noexcept {
    return lhs.internal() < nullptr;
}

template <typename T>
bool operator<(std::nullptr_t, const SharedPtr<T>& rhs) noexcept {
    return nullptr < rhs.internal();
}

template <typename T, typename U>
bool operator<=(const SharedPtr<T>& lhs, const SharedPtr<U>& rhs) noexcept {
    return !(rhs < lhs);
}

template <typename T>
bool operator<=(const SharedPtr<T>& lhs, std::nullptr_t) noexcept {
    return !(nullptr < lhs);
}

template <typename T>
bool operator<=(std::nullptr_t, const SharedPtr<T>& rhs) noexcept {
    return !(rhs < nullptr);
}

template <typename T, typename U>
bool operator>(const SharedPtr<T>& lhs, const SharedPtr<U>& rhs) noexcept {
    return rhs < lhs;
}

template <typename T>
bool operator>(const SharedPtr<T>& lhs, std::nullptr_t) noexcept {
    return nullptr < lhs;
}

template <typename T>
bool operator>(std::nullptr_t, const SharedPtr<T>& rhs) noexcept {
    return rhs < nullptr;
}

template <typename T, typename U>
bool operator>=(const SharedPtr<T>& lhs, const SharedPtr<U>& rhs) noexcept {
    return !(lhs < rhs);
}

template <typename T>
bool operator>=(const SharedPtr<T>& lhs, std::nullptr_t) noexcept {
    return !(lhs < nullptr);
}

template <typename T>
bool operator>=(std::nullptr_t, const SharedPtr<T>& rhs) noexcept {
    return !(nullptr < rhs);
}

// Swap
template <typename T>
void swap(SharedPtr<T>& lhs, SharedPtr<T>& rhs) noexcept {
    lhs.swap(rhs);
}

// make_shared equivalent
template <typename T, typename... Args>
SharedPtr<T> make_shared(Args&&... args) {
    return SharedPtr<T>(std::make_shared<T>(std::forward<Args>(args)...));
}

// static_pointer_cast
template <typename T, typename U>
SharedPtr<T> static_pointer_cast(const SharedPtr<U>& r) noexcept {
    return SharedPtr<T>(std::static_pointer_cast<T>(r.internal()));
}

// dynamic_pointer_cast
template <typename T, typename U>
SharedPtr<T> dynamic_pointer_cast(const SharedPtr<U>& r) noexcept {
    return SharedPtr<T>(std::dynamic_pointer_cast<T>(r.internal()));
}

// const_pointer_cast
template <typename T, typename U>
SharedPtr<T> const_pointer_cast(const SharedPtr<U>& r) noexcept {
    return SharedPtr<T>(std::const_pointer_cast<T>(r.internal()));
}

// reinterpret_pointer_cast (C++17)
template <typename T, typename U>
SharedPtr<T> reinterpret_pointer_cast(const SharedPtr<U>& r) noexcept {
    return SharedPtr<T>(std::reinterpret_pointer_cast<T>(r.internal()));
}

}  // namespace shared_ptr

// Expose SharedPtr directly for nicer-looking code
using shared_ptr::SharedPtr;

// Similarly, we epose the commonly used functions directly
// to avoid needing to qualify them with shared_ptr::
using shared_ptr::dynamic_pointer_cast;
using shared_ptr::make_shared;
using shared_ptr::static_pointer_cast;

// Note: the simple using + unqualified name approach does not always work for make_shared
// because of ADL-induced ambiguity between the tracing-enabled make_shared and std::make_shared
// when the former is present, so some uses of make_shared still need to be qualified with shared_ptr::
// (which will resolve to either the tracing-enabled or the std version depending on ENABLE_TRACER_SUPPORT)

}  // namespace lbcrypto
namespace std {
// Hash support for SharedPtr when tracing is enabled
template <typename T>
struct hash<lbcrypto::SharedPtr<T> > {
    size_t operator()(const lbcrypto::SharedPtr<T>& ptr) const noexcept {
        return hash<shared_ptr<T> >()(ptr.internal());
    }
};
}  // namespace std

#endif  // ENABLE_TRACER_SUPPORT

#endif  // __SHARED_PTR_H__