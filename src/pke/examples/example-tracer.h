/**
 * @file example-tracer.h
 * @brief Example implementation of a tracer that demonstrates how to build
 *        a custom tracer against the OpenFHE tracing interface.
 *
 * This tracer serves as a reference implementation showing how to:
 * - Implement the Tracer and FunctionTracer interfaces
 * - Track and serialize cryptographic objects (ciphertexts, plaintexts, keys)
 * - Generate unique identifiers for objects using hashing
 * - Format and output trace information with hierarchical structure
 *
 * The ExampleTracer writes function calls, inputs, and outputs to a file or
 * stream with indentation to show the call hierarchy. It can be used as a
 * starting point for building more sophisticated tracers.
 */

#ifndef __EXAMPLE_TRACER_H__
#define __EXAMPLE_TRACER_H__

// Defines ENABLE_TRACER (via config_core.h) so needs to be outside the #ifdef ENABLE_TRACER
#include "tracing.h"

#ifdef ENABLE_TRACER
    #include <fstream>
    #include <memory>
    #include <sstream>
    #include <string>
    #include <unordered_map>
    #include <utility>
    #include <vector>
    #include <cassert>
    #include <type_traits>
    #include <complex>
    #include <iomanip>

    #include "cryptocontext-ser.h"
    #include "ciphertext-ser.h"
    #include "plaintext-ser.h"
    #include "key/key-ser.h"
    #include "scheme/ckksrns/ckksrns-ser.h"
    #include "scheme/bfvrns/bfvrns-ser.h"
    #include "scheme/bgvrns/bgvrns-ser.h"

    #include "utils/hashutil.h"
namespace lbcrypto {

template <typename Element>
class ExampleTracer;

template <typename Element>
class ExampleFunctionTracer : public FunctionTracer<Element> {
private:
    template <typename T>
    std::string getID(T obj, const std::string& type) {
        // Serialize and hash the object for uniqueness detection
        std::stringstream serialStream;
        Serial::Serialize(obj, serialStream, SerType::BINARY);
        const std::string hash = HashUtil::HashString(serialStream.str());

        // Check if we already have a unique ID for this hash
        auto hashIt = m_tracer->m_uniqueID.find(hash);
        if (hashIt != m_tracer->m_uniqueID.end())
            // Object already seen - reuse existing ID
            return hashIt->second;

        // Generate and register a new ID
        size_t& counter            = m_tracer->m_counters[type];
        std::string id             = type + "_" + std::to_string(++counter);
        m_tracer->m_uniqueID[hash] = id;
        return id;
    }

    /// Helper to register objects to either m_inputs or m_outputs (target) for the current function
    template <typename T>
    void registerObject(T obj, const std::string& type, const std::string& name, std::string inOut) {
        std::string id = getID(obj, type);
        std::stringstream ss;
        ss << inOut << " ";
        if (!name.empty())
            ss << name << " = ";
        ss << id << " : " << type;
        print(ss.str());
    }

    template <typename T>
    void registerObjects(const std::vector<T>& objects, const std::string& type, const std::string& name,
                         std::string inOut) {
        std::vector<std::string> ids;
        for (const auto& obj : objects)
            ids.push_back(getID(obj, type));
        std::stringstream ss;
        ss << inOut << " ";
        if (!name.empty())
            ss << name << " = ";
        ss << formatVector(ids, type);
        print(ss.str());
    }

    template <typename T>
    void registerValue(T value, const std::string& type, const std::string& name, std::string inOut) {
        std::stringstream ss;
        ss << inOut << " ";
        if (!name.empty())
            ss << name << " = ";
        ss << value << " : " << type;
        print(ss.str());
    }

    template <typename T>
    void registerValues(const std::vector<T>& values, const std::string& type, const std::string& name,
                        std::string inOut) {
        std::stringstream ss;
        ss << inOut << " ";
        if (!name.empty())
            ss << name << " = ";
        ss << formatVector(values, type);
        print(ss.str());
    }

    /// Helper to format vectors with truncation
    template <typename T>
    std::string formatVector(const std::vector<T>& values, const std::string& elementTypeName) {
        if (values.empty())
            return "[] : " + elementTypeName;

        std::stringstream ss;
        ss << "[" << values[0];
        for (size_t i = 1; i < std::min(values.size(), size_t(16)); ++i)
            ss << ", " << values[i];
        if (values.size() > 16)
            ss << ", ...(" << (values.size() - 16) << " more)";
        ss << "] : vector<" << elementTypeName << ">";
        return ss.str();
    }

public:
    ExampleFunctionTracer(const std::string& func, std::shared_ptr<std::ostream> out, ExampleTracer<Element>* tracer,
                          size_t level)
        : m_func(func), m_out(std::move(out)), m_tracer(tracer), m_level(level) {
        print(m_func + ":");
        m_level += 1;
    }

    ~ExampleFunctionTracer() override {
        m_tracer->EndFunction();
    }

    void registerInput(Ciphertext<Element> ciphertext, std::string name = "", bool isMutable = false) override {
        registerObject(ciphertext, "ciphertext", name, "input");
    }
    void registerInput(ConstCiphertext<Element> ciphertext, std::string name = "", bool isMutable = false) override {
        registerObject(ciphertext, "const_ciphertext", name, "input");
    }
    void registerInput(Plaintext plaintext, std::string name = "", bool isMutable = false) override {
        registerObject(plaintext, "plaintext", name, "input");
    }
    void registerInput(ConstPlaintext plaintext, std::string name = "", bool isMutable = false) override {
        registerObject(plaintext, "plaintext", name, "input");
    }
    void registerInput(const PublicKey<Element> key, std::string name = "", bool isMutable = false) override {
        registerObject(key, "public_key", name, "input");
    }
    void registerInput(const PrivateKey<Element> key, std::string name = "", bool isMutable = false) override {
        registerObject(key, "private_key", name, "input");
    }
    void registerInput(const EvalKey<Element> key, std::string name = "", bool isMutable = false) override {
        registerObject(key, "eval_key", name, "input");
    }
    void registerInput(const PlaintextEncodings encoding, std::string name = "", bool isMutable = false) override {
        std::string encodingStr;
        switch (encoding) {
            case PlaintextEncodings::COEF_PACKED_ENCODING:
                encodingStr = "COEF_PACKED_ENCODING";
                break;
            case PlaintextEncodings::PACKED_ENCODING:
                encodingStr = "PACKED_ENCODING";
                break;
            case PlaintextEncodings::STRING_ENCODING:
                encodingStr = "STRING_ENCODING";
                break;
            case PlaintextEncodings::CKKS_PACKED_ENCODING:
                encodingStr = "CKKS_PACKED_ENCODING";
                break;
            default:
                encodingStr = "UNKNOWN_ENCODING";
                break;
        }
        registerValue(encodingStr, "plaintext_encoding", name, "input");
    }
    void registerInput(const std::vector<int64_t>& values, std::string name = "", bool isMutable = false) override {
        registerValues(values, "int64_t", name, "input");
    }
    void registerInput(const std::vector<int32_t>& values, std::string name = "", bool isMutable = false) override {
        registerValues(values, "int32_t", name, "input");
    }
    void registerInput(const std::vector<uint32_t>& values, std::string name = "", bool isMutable = false) override {
        registerValues(values, "uint32_t", name, "input");
    }
    void registerInput(const std::vector<double>& values, std::string name = "", bool isMutable = false) override {
        registerValues(values, "double", name, "input");
    }
    void registerInput(double value, std::string name = "", bool isMutable = false) override {
        registerValue(value, "double", name, "input");
    }
    void registerInput(std::complex<double> value, std::string name = "", bool isMutable = false) override {
        registerValue(value, "complex<double>", name, "input");
    }
    void registerInput(int64_t value, std::string name = "", bool isMutable = false) override {
        registerValue(value, "int64_t", name, "input");
    }
    void registerInput(size_t value, std::string name = "", bool isMutable = false) override {
        registerValue(value, "size_t", name, "input");
    }
    void registerInput(NativeInteger value, std::string name = "", bool isMutable = false) override {
        registerValue(value.ConvertToInt(), "NativeInteger", name, "input");
    }
    void registerInput(bool value, std::string name = "", bool isMutable = false) override {
        registerValue(value, "bool", name, "input");
    }
    void registerInput(const std::string& value, std::string name = "", bool isMutable = false) override {
        registerValue(value, "string", name, "input");
    }
    void registerInput(const std::map<uint32_t, EvalKey<Element>>& evalKeyMap, std::string name = "",
                       bool isMutable = false) override {
        if (evalKeyMap.empty()) {
            registerValue("{}", "map<uint32_t,EvalKey>", name, "input");
            return;
        }

        std::stringstream ss;
        ss << "input ";
        if (!name.empty())
            ss << name << " = ";
        ss << "{";

        size_t count = 0;
        for (auto it = evalKeyMap.begin(); it != evalKeyMap.end() && count < 16; ++it, ++count) {
            if (count > 0)
                ss << ", ";
            std::string keyId = getID(it->second, "eval_key");
            ss << it->first << ": " << keyId;
        }

        if (evalKeyMap.size() > 16)
            ss << ", ...(" << (evalKeyMap.size() - 16) << " more)";
        ss << "} : map<uint32_t,EvalKey>";
        print(ss.str());
    }
    void registerInput(const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>& evalKeyMap, std::string name = "",
                       bool isMutable = false) override {
        if (!evalKeyMap) {
            registerValue("nullptr", "map<uint32_t,EvalKey>", name, "input");
            return;
        }
        registerInput(*evalKeyMap, name, isMutable);
    }

    void registerInput(const std::shared_ptr<std::vector<Element>>& digits, std::string name = "",
                       bool isMutable = false) override {
        if (!digits || digits->empty()) {
            registerValue(digits ? "[]" : "nullptr", "vector<Element>", name, "input");
            return;
        }
        std::stringstream ss;
        ss << "input ";
        if (!name.empty())
            ss << name << " = ";
        ss << "[" << digits->size() << " elements] : vector<Element>";
        print(ss.str());
    }
    void registerInput(const std::shared_ptr<seriesPowers<Element>>& powers, std::string name = "",
                       bool isMutable = false) override {
        if (!powers) {
            registerValue("nullptr", "seriesPowers", name, "input");
            return;
        }
        std::stringstream ss;
        ss << "input ";
        if (!name.empty()) ss << name << " = ";
        ss << "{k=" << powers->k << ", m=" << powers->m << ", " << powers->powersRe.size() << " powersRe, "
           << powers->powers2Re.size() << " powers2Re";
        if (!powers->powersIm.empty())
            ss << ", " << powers->powersIm.size() << " powersIm, " << powers->powers2Im.size() << " powers2Im";
        ss << "} : seriesPowers";
        print(ss.str());
    }
    void registerInput(void* ptr, std::string name = "", bool isMutable = false) override {
        registerValue(ptr, "void*", name, "input");
    }
    void registerInput(const std::vector<std::complex<double>>& values, std::string name = "",
                       bool isisMutable = false) override {
        registerValues(values, "complex<double>", name, "input");
    }

    Ciphertext<Element> registerOutput(Ciphertext<Element> ciphertext, std::string name = "") override {
        registerObject(ciphertext, "ciphertext", name, "output");
        return ciphertext;
    }
    ConstCiphertext<Element> registerOutput(ConstCiphertext<Element> ciphertext, std::string name = "") override {
        registerObject(ciphertext, "const_ciphertext", name, "output");
        return ciphertext;
    }
    Plaintext registerOutput(Plaintext plaintext, std::string name = "") override {
        registerObject(plaintext, "plaintext", name, "output");
        return plaintext;
    }
    KeyPair<Element> registerOutput(KeyPair<Element> keyPair, std::string name = "") override {
        // For simplicity, we register the public and private keys separately
        if (keyPair.publicKey != nullptr) {
            name = name.empty() ? "" : name + "_public";
            registerObject(keyPair.publicKey, "public_key", name, "output");
        }
        if (keyPair.secretKey != nullptr) {
            name = name.empty() ? "" : name + "_private";
            registerObject(keyPair.secretKey, "private_key", name, "output");
        }
        return keyPair;
    }
    EvalKey<Element> registerOutput(EvalKey<Element> evalKey, std::string name = "") override {
        registerObject(evalKey, "eval_key", name, "output");
        return evalKey;
    }
    std::vector<EvalKey<Element>> registerOutput(std::vector<EvalKey<Element>> evalKeys,
                                                 std::string name = "") override {
        registerObjects(evalKeys, "eval_key", name, "output");
        return evalKeys;
    }
    std::vector<Ciphertext<Element>> registerOutput(std::vector<Ciphertext<Element>> ciphertexts,
                                                    std::string name = "") override {
        registerObjects(ciphertexts, "ciphertext", name, "output");
        return ciphertexts;
    }
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> registerOutput(
        std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap, std::string name = "") override {
        if (!evalKeyMap || evalKeyMap->empty()) {
            registerValue(evalKeyMap ? "{}" : "nullptr", "map<uint32_t,EvalKey>", name, "output");
            return evalKeyMap;
        }

        std::stringstream ss;
        ss << "output ";
        if (!name.empty())
            ss << name << " = ";
        ss << "{";

        size_t count = 0;
        for (auto it = evalKeyMap->begin(); it != evalKeyMap->end() && count < 16; ++it, ++count) {
            if (count > 0)
                ss << ", ";
            std::string keyId = getID(it->second, "eval_key");
            ss << it->first << ": " << keyId;
        }

        if (evalKeyMap->size() > 16)
            ss << ", ...(" << (evalKeyMap->size() - 16) << " more)";
        ss << "} : map<uint32_t,EvalKey>";
        print(ss.str());
        return evalKeyMap;
    }
    std::shared_ptr<std::vector<Element>> registerOutput(std::shared_ptr<std::vector<Element>> digits,
                                                         std::string name = "") override {
        if (!digits || digits->empty()) {
            registerValue(digits ? "[]" : "nullptr", "vector<Element>", name, "output");
            return digits;
        }
        std::stringstream ss;
        ss << "output ";
        if (!name.empty())
            ss << name << " = ";
        ss << "[" << digits->size() << " elements] : vector<Element>";
        print(ss.str());
        return digits;
    }
    std::shared_ptr<seriesPowers<Element>> registerOutput(std::shared_ptr<seriesPowers<Element>> powers,
                                                         std::string name = "") override {
        if (!powers) {
            registerValue("nullptr", "seriesPowers", name, "output");
            return powers;
        }
        std::stringstream ss;
        ss << "output ";
        if (!name.empty())
            ss << name << " = ";
        ss << "{k=" << powers->k << ", m=" << powers->m << ", " << powers->powersRe.size() << " powersRe, "
           << powers->powers2Re.size() << " powers2Re";
        if (!powers->powersIm.empty())
            ss << ", " << powers->powersIm.size() << " powersIm, " << powers->powers2Im.size() << " powers2Im";
        ss << "} : seriesPowers";
        print(ss.str());
        return powers;
    }

    // Output registration for basic types
    double registerOutput(double value, std::string name = "") {
        registerValue(value, "double", name, "output");
        return value;
    }
    std::complex<double> registerOutput(std::complex<double> value, std::string name = "") {
        registerValue(value, "complex<double>", name, "output");
        return value;
    }
    int64_t registerOutput(int64_t value, std::string name = "") {
        registerValue(value, "int64_t", name, "output");
        return value;
    }
    size_t registerOutput(size_t value, std::string name = "") {
        registerValue(value, "size_t", name, "output");
        return value;
    }
    std::vector<int64_t> registerOutput(const std::vector<int64_t>& values, std::string name = "") {
        registerValues(values, "int64_t", name, "output");
        return values;
    }
    PublicKey<Element> registerOutput(PublicKey<Element> publicKey, std::string name = "") override {
        registerObject(publicKey, "public_key", name, "output");
        return publicKey;
    }
    PrivateKey<Element> registerOutput(PrivateKey<Element> privateKey, std::string name = "") override {
        registerObject(privateKey, "private_key", name, "output");
        return privateKey;
    }
    std::string registerOutput(const std::string& value, std::string name = "") override {
        registerValue(value, "string", name, "output");
        return value;
    }
    Element registerOutput(Element element, std::string name = "") override {
        registerObject(element, "element", name, "output");
        return element;
    }

private:
    void print(const std::string& s) const {
        for (size_t i = 0; i < m_level; ++i)
            (*m_out) << '\t';
        (*m_out) << s << std::endl;
    }

    std::string m_func;
    std::shared_ptr<std::ostream> m_out;
    ExampleTracer<Element>* m_tracer;
    size_t m_level;
};

/// Basic Tracing implementation to demonstrate the tracing framework
/// Whenever TraceFunction is called, it will create a ExampleFunctionTracer
/// which will print the function name, inputs, and outputs to the specified output stream.
template <typename Element>
class ExampleTracer : public Tracer<Element> {
public:
    explicit ExampleTracer(const std::string& filename = "openfhe-trace.txt")
        : m_stream(std::make_shared<std::ofstream>(filename, std::ios::out)), m_level(0) {
        *m_stream << "Tracer (" << filename << "):" << std::endl;
    }
    explicit ExampleTracer(std::shared_ptr<std::ostream> stream) : m_stream(std::move(stream)), m_level(0) {}
    ~ExampleTracer() override = default;

    void EndFunction() {
        if (m_level > 0)
            m_level -= 2;
    }

protected:
    virtual std::unique_ptr<FunctionTracer<Element>> createFunctionTracer(std::string function_name) override {
        m_level += 2;
        return std::make_unique<ExampleFunctionTracer<Element>>(function_name, m_stream, this, m_level);
    }

private:
    /// Output stream to write the trace to (e.g., a file)
    std::shared_ptr<std::ostream> m_stream;

    /// Map from hash of the object to a unique ID for that object
    std::unordered_map<std::string, std::string> m_uniqueID;

    /// Map from type name to current counter for ID generation
    std::unordered_map<std::string, size_t> m_counters;

    /// Basic "scoping" support via indentation levels
    uint m_level;

    friend class ExampleFunctionTracer<Element>;
};

}  // namespace lbcrypto

#endif  // ENABLE_TRACER

#endif  // __EXAMPLE_TRACER_H__
