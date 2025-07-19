#ifndef __SIMPLETRACER_H__
#define __SIMPLETRACER_H__

// Defines ENABLE_TRACER_SUPPORT (via config_core.h) so needs to be outside the #ifdef ENABLE_TRACER_SUPPORT
#include "tracing.h"

#ifdef ENABLE_TRACER_SUPPORT
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

    #include "hashutil.h"
namespace lbcrypto {

template <typename Element>
class SimpleTracer;

class TracingID : Metadata {
    std::string m_id = "";

public:
    explicit TracingID(const std::string& id) : m_id(id) {}

    std::string getID() const {
        return m_id;
    }
};

using OStreamPtr = std::shared_ptr<std::ostream>;

template <typename Element>
class SimpleFunctionTracer : public FunctionTracer<Element> {
private:
    /// Helper to register objects with IDs (no type suffix)
    template <typename T>
    void registerObjectHelper(T obj, const std::string& type, const std::string& name,
                              std::vector<std::string>& target) {
        // Serialize and hash the object for uniqueness detection
        std::stringstream serialStream;
        Serial::Serialize(obj, serialStream, SerType::BINARY);
        const std::string hash = HashUtil::HashString(serialStream.str());

        // Check if we already have a unique ID for this hash
        auto hashIt = m_tracer->m_uniqueID.find(hash);
        if (hashIt != m_tracer->m_uniqueID.end()) {
            // Object already seen - reuse existing ID
            target.push_back(name + " " + hashIt->second);
            return;
        }

        // Generate new ID
        std::string id             = generateObjectId(type);
        m_tracer->m_uniqueID[hash] = id;
        target.push_back(name + " " + id);
    }

    /// Helper for initializer lists
    template <typename T>
    void registerObjectsHelper(std::initializer_list<T> objects, std::initializer_list<std::string> names,
                               const std::string& type, std::vector<std::string>& target) {
        if (names.size() == 0) {
            for (auto& obj : objects) {
                registerObjectHelper(obj, type, "", target);
            }
            return;
        }
        assert(objects.size() == names.size() && "objects and names must have the same size");
        auto objIt  = objects.begin();
        auto nameIt = names.begin();
        for (; objIt != objects.end(); ++objIt, ++nameIt) {
            registerObjectHelper(*objIt, type, *nameIt, target);
        }
    }

    std::string generateObjectId(const std::string& type) {
        size_t& counter = m_tracer->m_counters[type];
        return type + "_" + std::to_string(++counter);
    }

    /// Helper to format vectors with truncation
    template <typename T>
    std::string formatVector(const std::vector<T>& values, const std::string& typeName) {
        std::stringstream ss;
        ss << "[";
        for (size_t i = 0; i < values.size(); ++i) {
            if (i > 0)
                ss << ", ";
            formatVectorElement(ss, values[i]);
            if (i >= 10) {  // Limit output to avoid very long traces
                ss << ", ...(" << (values.size() - i - 1) << " more)";
                break;
            }
        }
        ss << "]";
        return ss.str() + " : " + typeName;
    }

    /// Helper to format individual vector elements
    void formatVectorElement(std::stringstream& ss, int64_t value) {
        ss << value;
    }

    void formatVectorElement(std::stringstream& ss, double value) {
        ss << value;
    }

    void formatVectorElement(std::stringstream& ss, const std::complex<double>& value) {
        ss << "(" << value.real();
        if (value.imag() >= 0)
            ss << "+";
        ss << value.imag() << "i)";
    }

public:
    SimpleFunctionTracer(const std::string& func, OStreamPtr out, SimpleTracer<Element>* tracer, size_t level)
        : m_func(func), m_out(std::move(out)), m_tracer(tracer), m_level(level) {}

    ~SimpleFunctionTracer() override {
        for (size_t i = 0; i < m_level; ++i) {
            (*m_out) << '\t';
        }
        (*m_out) << m_func;
        printList(m_inputs, "inputs");
        printList(m_outputs, "outputs");
        (*m_out) << std::endl;
        m_tracer->EndFunction();
    }

    void registerInputs(std::initializer_list<Ciphertext<Element>> ciphertexts,
                        std::initializer_list<std::string> names = {}, bool isMutable = false) override {
        registerObjectsHelper(ciphertexts, names, "ciphertext", m_inputs);
    }

    void registerInputs(std::initializer_list<ConstCiphertext<Element>> ciphertexts,
                        std::initializer_list<std::string> names = {}, bool isMutable = false) override {
        registerObjectsHelper(ciphertexts, names, "const_ciphertext", m_inputs);
    }

    void registerInput(Ciphertext<Element> ciphertext, std::string name = "", bool isMutable = false) override {
        registerObjectHelper(ciphertext, "ciphertext", name, m_inputs);
    }
    void registerInput(ConstCiphertext<Element> ciphertext, std::string name = "", bool isMutable = false) override {
        registerObjectHelper(ciphertext, "const_ciphertext", name, m_inputs);
    }
    void registerInput(Plaintext plaintext, std::string name = "", bool isMutable = false) override {
        registerObjectHelper(plaintext, "plaintext", name, m_inputs);
    }
    void registerInput(ConstPlaintext plaintext, std::string name = "", bool isMutable = false) override {
        registerObjectHelper(plaintext, "plaintext", name, m_inputs);
    }
    void registerInputs(std::initializer_list<Plaintext> plaintexts, std::initializer_list<std::string> names = {},
                        bool isMutable = false) override {
        registerObjectsHelper(plaintexts, names, "plaintext", m_inputs);
    }
    void registerInput(const PublicKey<Element> key, std::string name = "", bool isMutable = false) override {
        registerObjectHelper(key, "public_key", name, m_inputs);
    }
    void registerInput(const PrivateKey<Element> key, std::string name = "", bool isMutable = false) override {
        registerObjectHelper(key, "private_key", name, m_inputs);
    }
    void registerInput(const EvalKey<Element> key, std::string name = "", bool isMutable = false) override {
        registerObjectHelper(key, "eval_key", name, m_inputs);
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
        m_inputs.push_back(name + " " + encodingStr + " : PlaintextEncodings");
    }
    void registerInput(const std::vector<int64_t>& values, std::string name = "", bool isMutable = false) override {
        m_inputs.push_back(name + " " + formatVector(values, "vector<int64_t>"));
    }
    void registerInput(const std::vector<int32_t>& values, std::string name = "", bool isMutable = false) override {
        std::vector<int64_t> converted(values.begin(), values.end());
        m_inputs.push_back(name + " " + formatVector(converted, "vector<int32_t>"));
    }
    void registerInput(const std::vector<uint32_t>& values, std::string name = "", bool isMutable = false) override {
        std::vector<int64_t> converted;
        for (auto val : values) {
            converted.push_back(static_cast<int64_t>(val));
        }
        m_inputs.push_back(name + " " + formatVector(converted, "vector<uint32_t>"));
    }
    void registerInput(const std::vector<double>& values, std::string name = "", bool isMutable = false) override {
        m_inputs.push_back(name + " " + formatVector(values, "vector<double>"));
    }
    void registerInput(double value, std::string name = "", bool isMutable = false) override {
        m_inputs.push_back(name + " " + std::to_string(value) + " : double");
    }
    void registerInput(std::complex<double> value, std::string name = "", bool isMutable = false) override {
        std::stringstream ss;
        ss << "(" << value.real();
        if (value.imag() >= 0)
            ss << "+";
        ss << value.imag() << "i)";
        m_inputs.push_back(name + " " + ss.str() + " : complex<double>");
    }
    void registerInput(int64_t value, std::string name = "", bool isMutable = false) override {
        m_inputs.push_back(name + " " + std::to_string(value) + " : int64_t");
    }
    void registerInput(size_t value, std::string name = "", bool isMutable = false) override {
        m_inputs.push_back(name + " " + std::to_string(value) + " : size_t");
    }
    void registerInput(bool value, std::string name = "", bool isMutable = false) override {
        m_inputs.push_back(name + " " + (value ? "true" : "false") + " : bool");
    }
    void registerInput(const std::string& value, std::string name = "", bool isMutable = false) override {
        m_inputs.push_back(name + " \"" + value + "\" : string");
    }
    void registerInput(const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>& evalKeyMap, std::string name = "",
                       bool isMutable = false) override {
        if (evalKeyMap) {
            m_inputs.push_back(name + " [" + std::to_string(evalKeyMap->size()) + " keys] : map<uint32_t,EvalKey>");
        }
        else {
            m_inputs.push_back(name + " nullptr : map<uint32_t,EvalKey>");
        }
    }
    void registerInput(void* ptr, std::string name = "", bool isMutable = false) override {
        std::stringstream ss;
        ss << std::hex << ptr;
        m_inputs.push_back(name + " 0x" + ss.str() + " : void*");
    }
    void registerInput(const std::vector<std::complex<double>>& values, std::string name = "",
                       bool isisMutable = false) override {
        m_inputs.push_back(name + " " + formatVector(values, "vector<complex<double>>"));
    }

    Ciphertext<Element> registerOutput(Ciphertext<Element> ciphertext, std::string name = "") override {
        registerObjectHelper(ciphertext, "ciphertext", name, m_outputs);
        return ciphertext;
    }
    ConstCiphertext<Element> registerOutput(ConstCiphertext<Element> ciphertext, std::string name = "") override {
        registerObjectHelper(ciphertext, "const_ciphertext", name, m_outputs);
        return ciphertext;
    }
    Plaintext registerOutput(Plaintext plaintext, std::string name = "") override {
        registerObjectHelper(plaintext, "plaintext", name, m_outputs);
        return plaintext;
    }
    KeyPair<Element> registerOutput(KeyPair<Element> keyPair, std::string name = "") override {
        // Register the public and private keys separately
        if (keyPair.publicKey != nullptr) {
            registerObjectHelper(keyPair.publicKey, "public_key", name + "_public", m_outputs);
        }
        if (keyPair.secretKey != nullptr) {
            registerObjectHelper(keyPair.secretKey, "private_key", name + "_private", m_outputs);
        }
        return keyPair;
    }
    EvalKey<Element> registerOutput(EvalKey<Element> evalKey, std::string name = "") override {
        registerObjectHelper(evalKey, "eval_key", name, m_outputs);
        return evalKey;
    }
    std::vector<EvalKey<Element>> registerOutput(std::vector<EvalKey<Element>> evalKeys,
                                                 std::string name = "") override {
        std::stringstream ss;
        ss << name << " [";
        for (size_t i = 0; i < evalKeys.size(); ++i) {
            if (i > 0)
                ss << ", ";
            // Hash each eval key individually
            std::stringstream serialStream;
            Serial::Serialize(evalKeys[i], serialStream, SerType::BINARY);
            const std::string hash = HashUtil::HashString(serialStream.str());

            auto hashIt = m_tracer->m_uniqueID.find(hash);
            if (hashIt != m_tracer->m_uniqueID.end()) {
                ss << hashIt->second;
            }
            else {
                std::string id             = generateObjectId("eval_key");
                m_tracer->m_uniqueID[hash] = id;
                ss << id;
            }
            if (i >= 10) {
                ss << ", ...(" << (evalKeys.size() - i - 1) << " more)";
                break;
            }
        }
        ss << "] : vector<EvalKey>";
        m_outputs.push_back(ss.str());
        return evalKeys;
    }
    std::vector<Ciphertext<Element>> registerOutput(std::vector<Ciphertext<Element>> ciphertexts,
                                                    std::string name = "") override {
        std::stringstream ss;
        ss << name << " [";
        for (size_t i = 0; i < ciphertexts.size(); ++i) {
            if (i > 0)
                ss << ", ";
            // Hash each ciphertext individually
            std::stringstream serialStream;
            Serial::Serialize(ciphertexts[i], serialStream, SerType::BINARY);
            const std::string hash = HashUtil::HashString(serialStream.str());

            auto hashIt = m_tracer->m_uniqueID.find(hash);
            if (hashIt != m_tracer->m_uniqueID.end()) {
                ss << hashIt->second;
            }
            else {
                std::string id             = generateObjectId("ciphertext");
                m_tracer->m_uniqueID[hash] = id;
                ss << id;
            }
            if (i >= 10) {
                ss << ", ...(" << (ciphertexts.size() - i - 1) << " more)";
                break;
            }
        }
        ss << "] : vector<Ciphertext>";
        m_outputs.push_back(ss.str());
        return ciphertexts;
    }
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> registerOutput(
        std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap, std::string name = "") override {
        std::stringstream ss;
        ss << name << " {";
        if (evalKeyMap && evalKeyMap->size() > 0) {
            size_t count = 0;
            for (const auto& pair : *evalKeyMap) {
                if (count > 0)
                    ss << ", ";
                ss << pair.first << ": ";

                // Hash the eval key
                std::stringstream serialStream;
                Serial::Serialize(pair.second, serialStream, SerType::BINARY);
                const std::string hash = HashUtil::HashString(serialStream.str());

                auto hashIt = m_tracer->m_uniqueID.find(hash);
                if (hashIt != m_tracer->m_uniqueID.end()) {
                    ss << hashIt->second;
                }
                else {
                    std::string id             = generateObjectId("eval_key");
                    m_tracer->m_uniqueID[hash] = id;
                    ss << id;
                }

                if (++count >= 10) {
                    ss << ", ...(" << (evalKeyMap->size() - count) << " more)";
                    break;
                }
            }
        }
        ss << "} : map<uint32_t, EvalKey>";
        m_outputs.push_back(ss.str());
        return evalKeyMap;
    }

    // Output registration for basic types
    double registerOutput(double value, std::string name = "") {
        m_outputs.push_back(name + " " + std::to_string(value) + " : double");
        return value;
    }
    std::complex<double> registerOutput(std::complex<double> value, std::string name = "") {
        std::stringstream ss;
        ss << "(" << value.real();
        if (value.imag() >= 0)
            ss << "+";
        ss << value.imag() << "i)";
        m_outputs.push_back(name + " " + ss.str() + " : complex<double>");
        return value;
    }
    int64_t registerOutput(int64_t value, std::string name = "") {
        m_outputs.push_back(name + " " + std::to_string(value) + " : int64_t");
        return value;
    }
    size_t registerOutput(size_t value, std::string name = "") {
        m_outputs.push_back(name + " " + std::to_string(value) + " : size_t");
        return value;
    }
    std::vector<int64_t> registerOutput(const std::vector<int64_t>& values, std::string name = "") {
        m_outputs.push_back(name + " " + formatVector(values, "vector<int64_t>"));
        return values;
    }
    PublicKey<Element> registerOutput(PublicKey<Element> publicKey, std::string name = "") override {
        registerObjectHelper(publicKey, "public_key", name, m_outputs);
        return publicKey;
    }
    PrivateKey<Element> registerOutput(PrivateKey<Element> privateKey, std::string name = "") override {
        registerObjectHelper(privateKey, "private_key", name, m_outputs);
        return privateKey;
    }
    std::string registerOutput(const std::string& value, std::string name = "") override {
        m_outputs.push_back(name + " \"" + value + "\" : string");
        return value;
    }

private:
    void printList(const std::vector<std::string>& list, const std::string& label) const {
        if (list.empty()) {
            return;
        }
        (*m_out) << ' ' << label << "=[";
        for (size_t i = 0; i < list.size(); ++i) {
            if (i > 0) {
                (*m_out) << ", ";
            }
            (*m_out) << list[i];
        }
        (*m_out) << ']';
    }

    std::string m_func;
    OStreamPtr m_out;
    SimpleTracer<Element>* m_tracer;
    std::vector<std::string> m_inputs;
    std::vector<std::string> m_outputs;
    size_t m_level;
};

/// Basic Tracing implementation to demonstrate the tracing framework
/// Whenever TraceFunction is called, it will create a SimpleFunctionTracer
/// which will print the function name, inputs, and outputs to the specified output stream.
template <typename Element>
class SimpleTracer : public Tracer<Element> {
public:
    explicit SimpleTracer(const std::string& filename = "openfhe-trace.txt")
        : m_stream(std::make_shared<std::ofstream>(filename, std::ios::out)), m_level(0) {}
    explicit SimpleTracer(OStreamPtr stream) : m_stream(std::move(stream)), m_level(0) {}
    ~SimpleTracer() override = default;

    std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(std::string func) override {
        size_t level = m_level++;
        return std::make_unique<SimpleFunctionTracer<Element>>(func, m_stream, this, level);
    }
    std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(
        std::string func, std::initializer_list<Ciphertext<Element>> ciphertexts) override {
        size_t level = m_level++;
        auto tracer  = std::make_unique<SimpleFunctionTracer<Element>>(func, m_stream, this, level);
        tracer->registerInputs(ciphertexts);
        return tracer;
    }
    std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(
        std::string func, std::initializer_list<ConstCiphertext<Element>> ciphertexts) override {
        size_t level = m_level++;
        auto tracer  = std::make_unique<SimpleFunctionTracer<Element>>(func, m_stream, this, level);
        tracer->registerInputs(ciphertexts);
        return tracer;
    }

    virtual std::unique_ptr<DataTracer<Element>> TraceDataUpdate(std::string function_name) override {
        return std::make_unique<NullDataTracer<Element>>();
    }

    void EndFunction() {
        if (m_level > 0)
            --m_level;
    }

private:
    /// Output stream to write the trace to (e.g., a file)
    OStreamPtr m_stream;

    /// Map from hash of the object to a unique ID for that object
    std::unordered_map<std::string, std::string> m_uniqueID;

    /// Map from type name to current counter for ID generation
    std::unordered_map<std::string, size_t> m_counters;

    /// Basic "scoping" support via indentation levels
    uint m_level;

    friend class SimpleFunctionTracer<Element>;
};

}  // namespace lbcrypto

#endif  // ENABLE_TRACER_SUPPORT

#endif  // __SIMPLETRACER_H__
