#ifndef __TRACING_H__
#define __TRACING_H__

#include "config_core.h"

#ifdef ENABLE_TRACER
    // This is intentionally not using "do {x} while(0)"
    // so that it can be used for member definitions
    // and situations where an expression is expected
    #define IF_TRACE(...) __VA_ARGS__

    // Used to add additional functional arguments,
    // differs only in that it adds a comma
    #define IF_TRACE_(...) , __VA_ARGS__
#else
    #define IF_TRACE(...)
    #define IF_TRACE_(...)
#endif

/// Used to register inputs and outputs with the tracer,
/// in situations where the registered value needs to be returned.
/// This allows us to avoid adding unnecessary local vars / copies
/// (e.g., return REGISTER_IF_TRACE(some_function_computing_the_result(..)))
#ifdef ENABLE_TRACER
    /// The 1-argument version is a special case for CrytpoContext.h where
    /// where there is a convention that the FunctionTracer is always called t
    #define REGISTER_IF_TRACE_1(x)    t->registerOutput(x)
    #define REGISTER_IF_TRACE_2(t, x) t->registerOutput(x)
#else
    #define REGISTER_IF_TRACE_1(x)    x
    #define REGISTER_IF_TRACE_2(t, x) x
#endif
// Dispatch variadic macro to the correct version
#define MACRO_HELPER(_1, _2, MACRO, ...) MACRO
#define REGISTER_IF_TRACE(...)           MACRO_HELPER(__VA_ARGS__, REGISTER_IF_TRACE_2, REGISTER_IF_TRACE_1)(__VA_ARGS__)

#ifdef ENABLE_TRACER
    #include <cassert>
    #include <complex>
    #include <map>
    #include <string>
    #include <vector>
    #include "constants-defs.h"
    #include "ciphertext-fwd.h"
    #include "encoding/plaintext-fwd.h"
    #include "key/publickey-fwd.h"
    #include "key/privatekey-fwd.h"
    #include "key/evalkey-fwd.h"

namespace lbcrypto {

// There is no keypair-fwd.d so add a fwd decl here
template <typename Element>
class KeyPair;

/// Opens a scope for a specific function (e.g., a CryptoContext Eval... Function)
/// and keeps track of the inputs and outputs at the top-level.
/// Any calls to the Tracer that occur while inside this scope should be recorded
/// as occuring inside this scope, allowing the trace to represent nested scopes
/// and different levels of tracing "depth."
template <typename Element>
struct FunctionTracer {
    /// Destructor should close the current trace scope.
    virtual ~FunctionTracer() = default;

    // Input Registration Functions. These are expected to not modify their inputs,
    // even when they can for technical reasons (lacking const/const on ptr instead of object).
    virtual void registerInput(Ciphertext<Element> ciphertext, std::string name = "", bool isisMutable = false)     = 0;
    virtual void registerInput(ConstCiphertext<Element> ciphertext, std::string name = "",
                               bool isisMutable = false)                                                            = 0;
    virtual void registerInput(Plaintext plaintext, std::string name = "", bool isisMutable = false)                = 0;
    virtual void registerInput(ConstPlaintext plaintext, std::string name = "", bool isisMutable = false)           = 0;
    virtual void registerInput(const PublicKey<Element> publicKey, std::string name = "", bool isisMutable = false) = 0;
    virtual void registerInput(const PrivateKey<Element> privateKey, std::string name = "",
                               bool isisMutable = false)                                                            = 0;
    virtual void registerInput(const EvalKey<Element> evalKey, std::string name = "", bool isisMutable = false)     = 0;
    virtual void registerInput(const PlaintextEncodings encoding, std::string name = "", bool isisMutable = false)  = 0;
    virtual void registerInput(const std::vector<int64_t>& values, std::string name = "", bool isisMutable = false) = 0;
    virtual void registerInput(const std::vector<int32_t>& values, std::string name = "", bool isisMutable = false) = 0;
    virtual void registerInput(const std::vector<uint32_t>& values, std::string name = "",
                               bool isisMutable = false)                                                            = 0;
    virtual void registerInput(const std::vector<double>& values, std::string name = "", bool isisMutable = false)  = 0;
    virtual void registerInput(double value, std::string name = "", bool isisMutable = false)                       = 0;
    virtual void registerInput(std::complex<double> value, std::string name = "", bool isisMutable = false)         = 0;
    virtual void registerInput(const std::vector<std::complex<double>>& values, std::string name = "",
                               bool isisMutable = false)                                                            = 0;
    virtual void registerInput(int32_t value, std::string name = "", bool isisMutable = false) {
        registerInput(static_cast<int64_t>(value), name, isisMutable);
    }
    virtual void registerInput(uint32_t value, std::string name = "", bool isisMutable = false) {
        registerInput(static_cast<int64_t>(value), name, isisMutable);
    }
    virtual void registerInput(int64_t value, std::string name = "", bool isisMutable = false)            = 0;
    virtual void registerInput(size_t value, std::string name = "", bool isisMutable = false)             = 0;
    virtual void registerInput(bool value, std::string name = "", bool isisMutable = false)               = 0;
    virtual void registerInput(const std::string& value, std::string name = "", bool isisMutable = false) = 0;
    virtual void registerInput(const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>& evalKeyMap,
                               std::string name = "", bool isisMutable = false)                           = 0;

    /// If there are unknown types that should be traced, they should be registered here.
    virtual void registerInput(void* ptr, std::string name = "", bool isisMutable = false) = 0;

    /// Convenience functions for registering multiple inputs of the same type at once,
    /// e.g. registerInputs({ciphertext1, ciphertext2}, {"ciphertext1", "ciphertext2"}, true)
    template <typename T>
    void registerInputs(std::initializer_list<T> objects, std::initializer_list<std::string> names = {},
                        bool isMutable = false) {
        if (names.size() == 0) {
            for (auto& obj : objects) {
                registerInput(obj, "", isMutable);
            }
            return;
        }
        assert(objects.size() == names.size() && "objects and names must have the same size");
        auto objIt  = objects.begin();
        auto nameIt = names.begin();
        for (; objIt != objects.end(); ++objIt, ++nameIt) {
            registerInput(*objIt, *nameIt, isMutable);
        }
    }

    // Output Registration Functions. These are allowed to modify the output (specifically, it's metadata)
    // but must return their input, since they might be called from a functions'  return statement.
    virtual Ciphertext<Element> registerOutput(Ciphertext<Element> ciphertext, std::string name = "")           = 0;
    virtual ConstCiphertext<Element> registerOutput(ConstCiphertext<Element> ciphertext, std::string name = "") = 0;
    virtual Plaintext registerOutput(Plaintext plaintext, std::string name = "")                                = 0;
    virtual KeyPair<Element> registerOutput(KeyPair<Element> keyPair, std::string name = "")                    = 0;
    virtual EvalKey<Element> registerOutput(EvalKey<Element> evalKey, std::string name = "")                    = 0;
    virtual std::vector<EvalKey<Element>> registerOutput(std::vector<EvalKey<Element>> evalKeys,
                                                         std::string name = "")                                 = 0;
    virtual std::vector<Ciphertext<Element>> registerOutput(std::vector<Ciphertext<Element>> ciphertexts,
                                                            std::string name = "")                              = 0;
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> registerOutput(
        std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap, std::string name = "")      = 0;
    virtual PublicKey<Element> registerOutput(PublicKey<Element> publicKey, std::string name = "")    = 0;
    virtual PrivateKey<Element> registerOutput(PrivateKey<Element> privateKey, std::string name = "") = 0;
    virtual std::string registerOutput(const std::string& value, std::string name = "")               = 0;
    virtual Element registerOutput(Element element, std::string name = "")                            = 0;
};

template <typename Element>
class Tracer {
public:
    virtual ~Tracer() = default;

    virtual std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(std::string function_name) = 0;

    virtual std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(
        std::string function_name, std::initializer_list<Ciphertext<Element>> ciphertext_inputs) = 0;

    virtual std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(
        std::string function_name, std::initializer_list<ConstCiphertext<Element>> ciphertext_inputs) = 0;
};

/// A null function trace that does nothing when called.
template <typename Element>
class NullFunctionTracer : public FunctionTracer<Element> {
public:
    NullFunctionTracer()                   = default;
    virtual ~NullFunctionTracer() override = default;

    virtual void registerInput(Ciphertext<Element>, std::string, bool isMutable = false) override {}
    virtual void registerInput(ConstCiphertext<Element>, std::string, bool isMutable = false) override {}
    virtual void registerInput(Plaintext, std::string, bool isMutable = false) override {}
    virtual void registerInput(ConstPlaintext, std::string, bool isMutable = false) override {}
    virtual void registerInput(const PublicKey<Element>, std::string, bool isMutable = false) override {}
    virtual void registerInput(const PrivateKey<Element>, std::string, bool isMutable = false) override {}
    virtual void registerInput(const EvalKey<Element>, std::string, bool isMutable = false) override {}
    virtual void registerInput(const PlaintextEncodings, std::string, bool isMutable = false) override {}
    virtual void registerInput(const std::vector<int64_t>&, std::string, bool isMutable = false) override {}
    virtual void registerInput(const std::vector<int32_t>&, std::string, bool isMutable = false) override {}
    virtual void registerInput(const std::vector<uint32_t>&, std::string, bool isMutable = false) override {}
    virtual void registerInput(const std::vector<double>&, std::string, bool isMutable = false) override {}
    virtual void registerInput(double, std::string, bool isMutable = false) override {}
    virtual void registerInput(std::complex<double> value, std::string name = "", bool isMutable = false) override {}
    virtual void registerInput(const std::vector<std::complex<double>>&, std::string, bool isMutable = false) override {
    }
    virtual void registerInput(int64_t, std::string, bool isMutable = false) override {}
    virtual void registerInput(size_t, std::string, bool isMutable = false) override {}
    virtual void registerInput(bool, std::string, bool isMutable = false) override {}
    virtual void registerInput(const std::string&, std::string, bool isMutable = false) override {}
    virtual void registerInput(const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>&, std::string,
                               bool isMutable = false) override {}
    virtual void registerInput(void*, std::string, bool isMutable = false) override {}

    virtual Ciphertext<Element> registerOutput(Ciphertext<Element> ciphertext, std::string) override {
        return ciphertext;
    }
    virtual ConstCiphertext<Element> registerOutput(ConstCiphertext<Element> ciphertext, std::string) override {
        return ciphertext;
    }
    virtual Plaintext registerOutput(Plaintext plaintext, std::string) override {
        return plaintext;
    }
    virtual KeyPair<Element> registerOutput(KeyPair<Element> keyPair, std::string) override {
        return keyPair;
    }
    virtual EvalKey<Element> registerOutput(EvalKey<Element> evalKey, std::string) override {
        return evalKey;
    }
    virtual std::vector<EvalKey<Element>> registerOutput(std::vector<EvalKey<Element>> evalKeys, std::string) override {
        return evalKeys;
    }
    virtual std::vector<Ciphertext<Element>> registerOutput(std::vector<Ciphertext<Element>> ciphertexts,
                                                            std::string) override {
        return ciphertexts;
    }
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> registerOutput(
        std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap, std::string) override {
        return evalKeyMap;
    }
    virtual PublicKey<Element> registerOutput(PublicKey<Element> publicKey, std::string) override {
        return publicKey;
    }
    virtual PrivateKey<Element> registerOutput(PrivateKey<Element> privateKey, std::string) override {
        return privateKey;
    }
    virtual std::string registerOutput(const std::string& value, std::string) override {
        return value;
    }
    virtual Element registerOutput(Element element, std::string) override {
        return element;
    }
};

/// A null tracer that does nothing when called.
template <typename Element>
class NullTracer : public Tracer<Element> {
    int level = 0;

public:
    NullTracer()          = default;
    virtual ~NullTracer() = default;

    virtual std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(std::string function_name) override {
        return std::make_unique<NullFunctionTracer<Element>>();
    }

    virtual std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(
        std::string function_name, std::initializer_list<Ciphertext<Element>> ciphertext_inputs) override {
        return std::make_unique<NullFunctionTracer<Element>>();
    }

    virtual std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(
        std::string function_name, std::initializer_list<ConstCiphertext<Element>> ciphertext_inputs) override {
        return std::make_unique<NullFunctionTracer<Element>>();
    }
};

}  // namespace lbcrypto

#endif

#endif
