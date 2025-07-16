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

    #include "cryptocontext-ser.h"
    #include "ciphertext-ser.h"
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
        assert(false && "IMPLEMENT ME!");
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
        assert(false && "IMPLEMENT ME!");
    }
    void registerInput(Ciphertext<Element> ciphertext, std::string name = "", bool isMutable = false) override {
        std::string id   = "";
        std::string type = "ciphertext";
        auto obj         = ciphertext;
        // Check if it has tracing_id metatdata:
        std::string metadataID = "";
        auto metadataIterator  = ciphertext->FindMetadataByKey("tracing_id");
        if (ciphertext->MetadataFound(metadataIterator)) {
            metadataID = std::dynamic_pointer_cast<TracingID>(ciphertext->GetMetadata(metadataIterator))->getID();
        }
        // Serialize and hash
        std::stringstream s;
        Serial::Serialize(ciphertext, s, SerType::BINARY);
        auto hash = HashUtil::HashString(s.str());

        // Check if a unique ID already exists:
        auto it = m_tracer->m_uniqueID.find(hash);
        if (it != m_tracer->m_uniqueID.end()) {
            // Use the existing ID
            id = it->second;
        }
        else {
            // No unique ID yet, so check if we have a metadata ID

            // FOR NOW: just give it a new tracing id if not
            if (metadataID == "") {
                // TODO: Move this somewhere else
                // check if there is a  counter for "type"
                auto typeIt = m_tracer->m_counters.find(type);
                if (typeIt == m_tracer->m_counters.end()) {
                    // No counter for this type, initialize it
                    m_tracer->m_counters[type] = 0;
                }
                size_t count = ++m_tracer->m_counters[type];
                metadataID   = type + "_" + std::to_string(count);
                // obj->SetMetadataByKey("tracing_id", std::make_shared<TracingID>());
                //TODO: set metadataid!
            }

            if (metadataID == "") {
                assert(false && "TODO: nicer error message!");
            }

            // See if we already have a counter for this ID
            auto idIt = m_tracer->m_counters.find(metadataID);
            if (idIt == m_tracer->m_counters.end()) {
                // No counter for this ID, initialize it
                m_tracer->m_counters[metadataID] = 0;
            }
            size_t count = ++m_tracer->m_counters[metadataID];
            id           = metadataID + "_" + std::to_string(count);
        }
        // Finally, we are ready to push this back:

        m_inputs.push_back(name + " " + id + " : " + type);
    }
    void registerInput(ConstCiphertext<Element> ciphertext, std::string name = "", bool isMutable = false) override {
        std::string id   = "";
        std::string type = "ciphertext";
        auto obj         = ciphertext;
        // Check if it has tracing_id metatdata:
        std::string metadataID = "";
        auto metadataIterator  = ciphertext->FindMetadataByKey("tracing_id");
        if (ciphertext->MetadataFound(metadataIterator)) {
            metadataID = std::dynamic_pointer_cast<TracingID>(ciphertext->GetMetadata(metadataIterator))->getID();
        }
        // Serialize and hash
        std::stringstream s;
        Serial::Serialize(ciphertext, s, SerType::BINARY);
        auto hash = HashUtil::HashString(s.str());

        // Check if a unique ID already exists:
        auto it = m_tracer->m_uniqueID.find(hash);
        if (it != m_tracer->m_uniqueID.end()) {
            // Use the existing ID
            id = it->second;
        }
        else {
            // No unique ID yet, so check if we have a metadata ID

            // FOR NOW: just give it a new tracing id if not
            if (metadataID == "") {
                // TODO: Move this somewhere else
                // check if there is a  counter for "type"
                auto typeIt = m_tracer->m_counters.find(type);
                if (typeIt == m_tracer->m_counters.end()) {
                    // No counter for this type, initialize it
                    m_tracer->m_counters[type] = 0;
                }
                size_t count = ++m_tracer->m_counters[type];
                metadataID   = type + "_" + std::to_string(count);
                // obj->SetMetadataByKey("tracing_id", std::make_shared<TracingID>(id));
                // TODO: set metadata thing!
            }

            if (metadataID == "") {
                assert(false && "TODO: nicer error message!");
            }

            // See if we already have a counter for this ID
            auto idIt = m_tracer->m_counters.find(metadataID);
            if (idIt == m_tracer->m_counters.end()) {
                // No counter for this ID, initialize it
                m_tracer->m_counters[metadataID] = 0;
            }
            size_t count = ++m_tracer->m_counters[metadataID];
            id           = metadataID + "_" + std::to_string(count);
        }
        // Finally, we are ready to push this back:

        m_inputs.push_back(name + " " + id + " : " + type);
    }
    void registerInput(Plaintext plaintext, std::string name = "", bool isMutable = false) override {}
    void registerInput(ConstPlaintext plaintext, std::string name = "", bool isMutable = false) override {}
    void registerInputs(std::initializer_list<Plaintext> plaintexts, std::initializer_list<std::string> names = {},
                        bool isMutable = false) override {}
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
        : m_stream(std::make_shared<std::ofstream>(filename, std::ios::app)), m_level(0) {}
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
