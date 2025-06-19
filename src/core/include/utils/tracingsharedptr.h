#ifndef __TRACINGSHAREDPTR_H__
#define __TRACINGSHAREDPTR_H__

//==============================================================================
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
//==============================================================================

#include "utils/tracing.h"
#include <memory>
#include <utility>

namespace lbcrypto {

#ifdef ENABLE_TRACER_SUPPORT

// Trait to check if a type has GetCryptoContext() const
template <class T, class = void>
struct HasGetCryptoContext : std::false_type {};

template <class T>
struct HasGetCryptoContext<T, std::void_t<decltype(std::declval<const T&>().GetCryptoContext())>> : std::true_type {};

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
    explicit TracingSharedPtr(const std::shared_ptr<U>& other) : Base(other) {
        trace("copy-ctor");
    }

    template <class U>
    explicit TracingSharedPtr(std::shared_ptr<U>&& other) : Base(std::move(other)) {
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
        if constexpr (HasGetCryptoContext<T>::value) {
            T* obj = this->get();
            if (obj) {
                auto cc = obj->GetCryptoContext();
                IF_TRACE(cc->getTracer()->TraceDataUpdate(name));
            }
        }
    }
};

#else

template <typename T>
using TracingSharedPtr = std::shared_ptr<T>;

#endif  // ENABLE_TRACER_SUPPORT

}  // namespace lbcrypto

#endif  // __TRACINGSHAREDPTR_H__
