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

    #include "cryptocontext-ser.h"
    #include "ciphertext-ser.h"
    #include "plaintext-ser.h"
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
    /// SFINAE helper to detect if a type has metadata support
    template <typename T>
    static auto hasMetadata(int) -> decltype(std::declval<T>()->FindMetadataByKey(""), std::true_type{});

    template <typename T>
    static std::false_type hasMetadata(...);

    /// Helper to find the right id for an object and register it
    template <typename T>
    void registerInputHelper(T obj, const std::string& type, const std::string& name, bool isMutable) {
        // Serialize and hash the object for uniqueness detection
        std::stringstream serialStream;
        Serial::Serialize(obj, serialStream, SerType::BINARY);
        const std::string hash = HashUtil::HashString(serialStream.str());

        // Check if we already have a unique ID for this hash
        auto hashIt = m_tracer->m_uniqueID.find(hash);
        if (hashIt != m_tracer->m_uniqueID.end()) {
            // Object already seen - reuse existing ID
            const std::string& existingId = hashIt->second;
            m_inputs.push_back(name + " " + existingId + " : " + type);
            return;
        }

        // New object - generate unique ID based on metadata support
        std::string baseId;
        if constexpr (decltype(hasMetadata<T>(0))::value) {
            // Object has metadata support
            baseId = getOrCreateMetadataId(obj, type);
        }
        else {
            // Object without metadata - generate ID based on type only
            baseId = generateBaseIdFromType(type);
        }

        std::string uniqueId = generateUniqueId(baseId);

        // Store the mapping from hash to unique ID
        m_tracer->m_uniqueID[hash] = uniqueId;

        // Add to inputs
        m_inputs.push_back(name + " " + uniqueId + " : " + type);
    }

    template <typename T>
    std::string getOrCreateMetadataId(T obj, const std::string& type) {
        // Check if object has existing tracing_id metadata
        auto metadataIterator = obj->FindMetadataByKey("tracing_id");
        if (obj->MetadataFound(metadataIterator)) {
            return std::dynamic_pointer_cast<TracingID>(obj->GetMetadata(metadataIterator))->getID();
        }

        // No metadata ID - generate one based on type
        size_t& typeCounter = m_tracer->m_counters[type];
        return type + "_" + std::to_string(++typeCounter);
    }

    std::string generateUniqueId(const std::string& baseId) {
        size_t& idCounter = m_tracer->m_counters[baseId];
        return baseId + "_" + std::to_string(++idCounter);
    }

    std::string generateBaseIdFromType(const std::string& type) {
        size_t& typeCounter = m_tracer->m_counters[type];
        return type + "_" + std::to_string(++typeCounter);
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
        if (names.size() == 0) {
            for (auto& ct : ciphertexts) {
                registerInput(ct, "");
            }
            return;
        }
        assert(ciphertexts.size() == names.size() && "ciphertexts and names must have the same size");
        auto ctIt   = ciphertexts.begin();
        auto nameIt = names.begin();
        for (; ctIt != ciphertexts.end(); ++ctIt, ++nameIt) {
            registerInput(*ctIt, *nameIt, isMutable);
        }
    }

    void registerInputs(std::initializer_list<ConstCiphertext<Element>> ciphertexts,
                        std::initializer_list<std::string> names = {}, bool isMutable = false) override {
        if (names.size() == 0) {
            for (auto& ct : ciphertexts) {
                registerInput(ct, "");
            }
            return;
        }
        assert(ciphertexts.size() == names.size() && "ciphertexts and names must have the same size");
        auto ctIt   = ciphertexts.begin();
        auto nameIt = names.begin();
        for (; ctIt != ciphertexts.end(); ++ctIt, ++nameIt) {
            registerInput(*ctIt, *nameIt, isMutable);
        }
    }
    void registerInput(Ciphertext<Element> ciphertext, std::string name = "", bool isMutable = false) override {
        registerInputHelper(ciphertext, "ciphertext", name, isMutable);
    }
    void registerInput(ConstCiphertext<Element> ciphertext, std::string name = "", bool isMutable = false) override {
        registerInputHelper(ciphertext, "const_ciphertext", name, isMutable);
    }
    void registerInput(Plaintext plaintext, std::string name = "", bool isMutable = false) override {
        registerInputHelper(plaintext, "plaintext", name, isMutable);
    }
    void registerInput(ConstPlaintext plaintext, std::string name = "", bool isMutable = false) override {
        registerInputHelper(plaintext, "plaintext", name, isMutable);
    }
    void registerInputs(std::initializer_list<Plaintext> plaintexts, std::initializer_list<std::string> names = {},
                        bool isMutable = false) override {
        if (names.size() == 0) {
            for (auto& pt : plaintexts) {
                registerInputHelper(pt, "plaintext", "", isMutable);
            }
            return;
        }
        assert(plaintexts.size() == names.size() && "plaintexts and names must have the same size");
        auto ptIt   = plaintexts.begin();
        auto nameIt = names.begin();
        for (; ptIt != plaintexts.end(); ++ptIt, ++nameIt) {
            registerInputHelper(*ptIt, "plaintext", *nameIt, isMutable);
        }
    }
    void registerInput(const PublicKey<Element> key, std::string name = "", bool isMutable = false) override {}
    void registerInput(const PrivateKey<Element> key, std::string name = "", bool isMutable = false) override {}
    void registerInput(const PlaintextEncodings encoding, std::string name = "", bool isMutable = false) override {}
    void registerInput(const std::vector<int64_t>& values, std::string name = "", bool isMutable = false) override {}
    void registerInput(double value, std::string name = "", bool isMutable = false) override {}
    void registerInput(std::complex<double> value, std::string name = "", bool isMutable = false) override {}
    void registerInput(int64_t value, std::string name = "", bool isMutable = false) override {}
    void registerInput(size_t value, std::string name = "", bool isMutable = false) override {}
    void registerInput(void* ptr, std::string name = "", bool isMutable = false) override {}

    Ciphertext<Element> registerOutput(Ciphertext<Element> ciphertext, std::string name = "") override {
        return ciphertext;
    }
    ConstCiphertext<Element> registerOutput(ConstCiphertext<Element> ciphertext, std::string name = "") override {
        return ciphertext;
    }
    Plaintext registerOutput(Plaintext plaintext, std::string name = "") override {
        return plaintext;
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

    /// Map from (non-unique) Metadata ID to (last-seen) hash of the object
    /// Specifically, the hash should be SHA256 of the binary serialization of the object
    std::unordered_map<std::string, std::string> m_lastSeen;

    /// Map from hash of the object to a unique ID for that object
    /// Specifically, the hash should be SHA256 of the binary serialization of the object
    std::unordered_map<std::string, std::string> m_uniqueID;

    /// Map from (non-unique) Metadata ID to current counter
    std::unordered_map<std::string, size_t> m_counters;

    /// Basic "scoping" support via indentation levels
    uint m_level;

    friend class SimpleFunctionTracer<Element>;
};

}  // namespace lbcrypto

#endif  // ENABLE_TRACER_SUPPORT

#endif  // __SIMPLETRACER_H__
