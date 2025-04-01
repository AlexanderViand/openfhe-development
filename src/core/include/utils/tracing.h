#ifndef __TRACING_H__
#define __TRACING_H__

// FIXME: add CMake flags instead
#define ENABLE_TRACER_SUPPORT

// This is intentionally not using "do {x} while(0)"
// so that it can be used for member definitions, too.
#ifdef ENABLE_TRACER_SUPPORT
    #define IF_TRACE(x) x
#else
    #define IF_TRACE(x)
#endif

#ifdef ENABLE_TRACER_SUPPORT
    #define REGISTER_IF_TRACE(t, x) t->registerOutput(x);
#else
    #define REGISTER_IF_TRACE(t, x) x
#endif

// If tracing is disabled, none of these definitions should be needed
#ifdef ENABLE_TRACER_SUPPORT
    #include "ciphertext-fwd.h"
    #include "encoding/plaintext-fwd.h"
    #include "key/publickey-fwd.h"
    #include "key/privatekey-fwd.h"

namespace lbcrypto {

template <typename Element>
struct TraceThing {
    virtual ~TraceThing() = 0;

    virtual void registerInput(Ciphertext<Element> ciphertext)                               = 0;
    virtual void registerInput(ConstCiphertext<Element> ciphertext)                          = 0;
    virtual void registerInputs(std::initializer_list<Ciphertext<Element>> ciphertexts)      = 0;
    virtual void registerInputs(std::initializer_list<ConstCiphertext<Element>> ciphertexts) = 0;

    virtual void registerInput(Plaintext plaintext)                          = 0;
    virtual void registerInputs(std::initializer_list<Plaintext> plaintexts) = 0;
    // ConstPlaintext is just an alias for Plaintext, so no need for special handling

    virtual Ciphertext<Element> registerOutput(Ciphertext<Element> ciphertext) {
        return ciphertext;
    }
    virtual ConstCiphertext<Element> registerOutput(ConstCiphertext<Element> ciphertext) {
        return ciphertext;
    }
    virtual Plaintext registerOutput(Plaintext plaintext) {
        return plaintext;
    }
};

template <typename Element>
class Tracer {
public:
    virtual ~Tracer() = default;

    virtual std::unique_ptr<TraceThing<Element>> TraceCryptoContextEvalFunc(std::string function_name) = 0;

    virtual std::unique_ptr<TraceThing<Element>> TraceCryptoContextEvalFunc(
        std::string function_name, std::initializer_list<Ciphertext<Element>> ciphertext_inputs) = 0;

    virtual std::unique_ptr<TraceThing<Element>> TraceCryptoContextEvalFunc(
        std::string function_name, std::initializer_list<ConstCiphertext<Element>> ciphertext_inputs) = 0;
};

/// A null trace thing that does nothing when called.
template <typename Element>
class NullTraceThing : public TraceThing<Element> {
public:
    NullTraceThing() = default;

    virtual void registerInput(Ciphertext<Element> ciphertext) override {}
    virtual void registerInput(ConstCiphertext<Element> ciphertext) override {}
    virtual void registerInputs(std::initializer_list<Ciphertext<Element>> ciphertexts) override {}
    virtual void registerInputs(std::initializer_list<ConstCiphertext<Element>> ciphertexts) override {}

    virtual void registerInput(Plaintext plaintext) override {}
    virtual void registerInputs(std::initializer_list<Plaintext> plaintexts) override {}
};

/// A null tracer that does nothing when called.
template <typename Element>
class NullTracer : public Tracer<Element> {
    int level = 0;

public:
    NullTracer() = default;

    virtual std::unique_ptr<TraceThing<Element>> TraceCryptoContextEvalFunc(std::string function_name) override {
        return std::make_unique<NullTraceThing<Element>>();
    }

    virtual std::unique_ptr<TraceThing<Element>> TraceCryptoContextEvalFunc(
        std::string function_name, std::initializer_list<Ciphertext<Element>> ciphertext_inputs) override {
        return std::make_unique<NullTraceThing<Element>>();
    }

    virtual std::unique_ptr<TraceThing<Element>> TraceCryptoContextEvalFunc(
        std::string function_name, std::initializer_list<ConstCiphertext<Element>> ciphertext_inputs) override {
        return std::make_unique<NullTraceThing<Element>>();
    }
};

}  // namespace lbcrypto

#endif

#endif