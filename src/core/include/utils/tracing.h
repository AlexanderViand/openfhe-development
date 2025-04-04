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

/// Used to register inputs and outputs with the tracer.
#ifdef ENABLE_TRACER_SUPPORT
    /// The 1-argument version is a special case for CrytpoContext.h where
    /// where there is a convention that the FunctionTracer is always called t
    #define REGISTER_IF_TRACE_1(x)    t->registerInput(x);
    #define REGISTER_IF_TRACE_2(t, x) t->registerInput(x);
#else
    #define REGISTER_IF_TRACE_1(x)    x
    #define REGISTER_IF_TRACE_2(t, x) x
#endif

// Dispatch variadic macro to the correct version
#define MACRO_HELPER(_1, _2, MACRO, ...) MACRO
#define REGISTER_IF_TRACE(...)           MACRO_HELPER(__VA_ARGS__, REGISTER_IF_TRACE_2, REGISTER_IF_TRACE_1)(__VA_ARGS__)

// If tracing is disabled, none of these definitions should be needed
#ifdef ENABLE_TRACER_SUPPORT
    #include "ciphertext-fwd.h"
    #include "encoding/plaintext-fwd.h"
    #include "key/publickey-fwd.h"
    #include "key/privatekey-fwd.h"

namespace lbcrypto {

// ConstPlaintext is currently an alias for Plaintext, so no registerInput(ConstPlaintext)/etc is needed.
// We throw a compile time error should this change, as the tracing infrastructure will have to be updated
static_assert(std::is_same<ConstPlaintext, Plaintext>::value, "Expected ConstPlaintext to be an alias for Plaintext");

/// Opens a scope for a specific function (e.g., a CryptoContext Eval... Function)
/// and keeps track of the inputs and outputs at the top-level.
/// Any calls to the Tracer that occur while inside this scope should be recorded
/// as occuring inside this scope, allowing the trace to represent nested scopes
/// and different levels of tracing "depth."
template <typename Element>
struct FunctionTracer {
    /// Destructor closes the current trace scope.
    virtual ~FunctionTracer() = 0;

    // Input Registration Functions. These are expected to not modify their inputs,
    // even when they can for technical reasons (lacking const/const on ptr instead of object).

    virtual void registerInput(Ciphertext<Element> ciphertext, std::string name = "")               = 0;
    virtual void registerInput(ConstCiphertext<Element> ciphertext, std::string name = "")          = 0;
    virtual void registerInputs(std::initializer_list<Ciphertext<Element>> ciphertexts,
                                std::initializer_list<std::string> name = "")                       = 0;
    virtual void registerInputs(std::initializer_list<ConstCiphertext<Element>> ciphertexts,
                                std::initializer_list<std::string> name = "")                       = 0;
    virtual void registerInput(Plaintext plaintext, std::string name = "")                          = 0;
    virtual void registerInputs(std::initializer_list<Plaintext> plaintexts, std::string name = "") = 0;
    virtual void registerInput(const PublicKey<Element> publicKey, std::string name = "")           = 0;
    virtual void registerInput(const PrivateKey<Element> privateKey, std::string name = "")         = 0;
    virtual void registerInput(const PlaintextEncodings encoding, std::string name = "")            = 0;
    virtual void registerInput(const std::vector<int64_t>& values, std::string name = "")           = 0;
    virtual void registerInput(size_t value, std::string name = "")                                 = 0;

    /// If there are unknown types that should be traced, they should be registered here.
    virtual void registerInput(void* ptr, std::string name = "") = 0;

    // Output Registration Functions. These are allowed to modify the output (specifically, it's metadata)
    // but must return their input, since they might be called from a functions'  return statement.
    virtual Ciphertext<Element> registerOutput(Ciphertext<Element> ciphertext, std::string name = "") {
        return ciphertext;
    }
    virtual ConstCiphertext<Element> registerOutput(ConstCiphertext<Element> ciphertext, std::string name = "") {
        return ciphertext;
    }
    virtual Plaintext registerOutput(Plaintext plaintext, std::string name = "") {
        return plaintext;
    }
};

template <typename Element>
class Tracer {
public:
    virtual ~Tracer() = default;

    virtual std::unique_ptr<FunctionTracer<Element>> TraceCryptoContextEvalFunc(std::string function_name) = 0;

    virtual std::unique_ptr<FunctionTracer<Element>> TraceCryptoContextEvalFunc(
        std::string function_name, std::initializer_list<Ciphertext<Element>> ciphertext_inputs) = 0;

    virtual std::unique_ptr<FunctionTracer<Element>> TraceCryptoContextEvalFunc(
        std::string function_name, std::initializer_list<ConstCiphertext<Element>> ciphertext_inputs) = 0;
};

/// A null trace thing that does nothing when called.
template <typename Element>
class NullFunctionTracer : public FunctionTracer<Element> {
public:
    NullFunctionTracer() = default;

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

    virtual std::unique_ptr<FunctionTracer<Element>> TraceCryptoContextEvalFunc(std::string function_name) override {
        return std::make_unique<NullFunctionTracer<Element>>();
    }

    virtual std::unique_ptr<FunctionTracer<Element>> TraceCryptoContextEvalFunc(
        std::string function_name, std::initializer_list<Ciphertext<Element>> ciphertext_inputs) override {
        return std::make_unique<NullFunctionTracer<Element>>();
    }

    virtual std::unique_ptr<FunctionTracer<Element>> TraceCryptoContextEvalFunc(
        std::string function_name, std::initializer_list<ConstCiphertext<Element>> ciphertext_inputs) override {
        return std::make_unique<NullFunctionTracer<Element>>();
    }
};

}  // namespace lbcrypto

#endif

#endif