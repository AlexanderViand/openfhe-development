#ifndef __HERACLESTRACER_H__
#define __HERACLESTRACER_H__

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
    #include <mutex>
    #include <unordered_set>
    #ifdef WITH_OPENMP
        #include <omp.h>
    #endif
    #include <type_traits>
    #include <complex>
    #include <iomanip>
    #include <mutex>
    #include <algorithm>

    #include "cryptocontext-ser.h"
    #include "ciphertext-ser.h"
    #include "plaintext-ser.h"
    #include "key/key-ser.h"
    #include "scheme/ckksrns/ckksrns-ser.h"
    #include "scheme/bfvrns/bfvrns-ser.h"
    #include "scheme/bgvrns/bgvrns-ser.h"
    #include "hashutil.h"

    #include <heracles/heracles_proto.h>
    #include <heracles/heracles_data_formats.h>
    #include <heracles/data/io.h>

namespace lbcrypto {

template <typename Element>
class HeraclesTracer;

template <typename Element>
class HeraClesFunctionTracer : public FunctionTracer<Element> {
private:
    /// Helper to extract SSA ID from objects for HERACLES tracing (same approach as SimpleTracer)
    template <typename T>
    std::string getObjectId(T obj, const std::string& type) {
        // Serialize and hash the object for uniqueness detection
        std::stringstream serialStream;
        Serial::Serialize(obj, serialStream, SerType::BINARY);
        const std::string hash = HashUtil::HashString(serialStream.str());

        // Check if we already have a unique ID for this hash
        auto hashIt = m_tracer->m_uniqueID.find(hash);
        if (hashIt != m_tracer->m_uniqueID.end()) {
            // Object already seen - reuse existing ID
            return hashIt->second;
        }

        // Generate new ID using counter
        size_t& counter            = m_tracer->m_counters[type];
        std::string id             = type + "_" + std::to_string(++counter);
        m_tracer->m_uniqueID[hash] = id;
        return id;
    }

    /// Helper to store DCRTPoly data for test vector generation
    void storeDataIfNeeded(ConstCiphertext<Element> ciphertext, const std::string& objectId) {
        if (ciphertext && ciphertext->GetElements().size() > 0) {
            m_tracer->storeData(objectId, ciphertext->GetElements());
        }
    }

    void storeDataIfNeeded(ConstPlaintext plaintext, const std::string& objectId) {
        // Plaintexts don't have DCRTPoly elements in the same way, so we skip data storage for now
        // In a full implementation, we might need to handle this differently
    }

    /// Helper to create HERACLES OperandObject for ciphertexts/plaintexts
    void setHERACLESOperandObject(heracles::fhe_trace::OperandObject* opObj, const std::string& objectId,
                                  size_t numRNS = 0, size_t order = 1) {
        opObj->set_symbol_name(objectId);
        opObj->set_num_rns(numRNS);
        opObj->set_order(order);
    }

    /// Helper to add ciphertext input to HERACLES instruction
    void addCiphertextInput(ConstCiphertext<Element> ciphertext, const std::string& name) {
        if (ciphertext && ciphertext->GetElements().size() > 0) {
            std::string objectId = getObjectId(ciphertext, "ciphertext");
            size_t numRNS        = ciphertext->GetElements()[0].GetNumOfElements();
            size_t order         = ciphertext->GetElements().size();

            auto* srcOp = m_currentInstruction.mutable_args()->add_srcs();
            setHERACLESOperandObject(srcOp, objectId, numRNS, order);

            // Store data for test vector generation
            storeDataIfNeeded(ciphertext, objectId);

            // Store for later reference
            m_inputObjectIds.push_back(objectId);
        }
    }

    /// Helper to add plaintext input to HERACLES instruction
    void addPlaintextInput(ConstPlaintext plaintext, const std::string& name) {
        if (plaintext) {
            std::string objectId = getObjectId(plaintext, "plaintext");

            auto* srcOp = m_currentInstruction.mutable_args()->add_srcs();
            setHERACLESOperandObject(srcOp, objectId, 0, 1);

            // Store data for test vector generation
            storeDataIfNeeded(plaintext, objectId);

            m_inputObjectIds.push_back(objectId);
        }
    }

    /// Helper to add parameter to HERACLES instruction
    template <typename T>
    void addParameter(const std::string& name, const T& value, const std::string& type) {
        heracles::fhe_trace::Parameter param;
        std::stringstream ss;
        ss << value;
        param.set_value(ss.str());

        // Set parameter type based on type string
        std::string upperType = type;
        std::transform(upperType.begin(), upperType.end(), upperType.begin(), ::toupper);

        if (upperType == "DOUBLE") {
            param.set_type(heracles::fhe_trace::ValueType::DOUBLE);
        }
        else if (upperType == "FLOAT") {
            param.set_type(heracles::fhe_trace::ValueType::FLOAT);
        }
        else if (upperType == "INT32") {
            param.set_type(heracles::fhe_trace::ValueType::INT32);
        }
        else if (upperType == "INT64") {
            param.set_type(heracles::fhe_trace::ValueType::INT64);
        }
        else if (upperType == "UINT32") {
            param.set_type(heracles::fhe_trace::ValueType::UINT32);
        }
        else if (upperType == "UINT64") {
            param.set_type(heracles::fhe_trace::ValueType::UINT64);
        }
        else {
            param.set_type(heracles::fhe_trace::ValueType::STRING);
        }

        (*m_currentInstruction.mutable_args()->mutable_params())[name] = param;
    }

public:
    HeraClesFunctionTracer(const std::string& func, HeraclesTracer<Element>* tracer)
        : m_func(func), m_tracer(tracer), m_hasOutput(false) {
        // Initialize the instruction with the function name
        std::string opname_lower = func;
        std::transform(opname_lower.begin(), opname_lower.end(), opname_lower.begin(), ::tolower);
        m_currentInstruction.set_op(opname_lower);
        m_currentInstruction.set_plaintext_index(0);  // Default for OpenFHE
    }

    ~HeraClesFunctionTracer() override {
        // Only add the instruction if we had outputs (i.e., this was a meaningful operation)
        if (m_hasOutput && !m_inputObjectIds.empty()) {
            m_tracer->addInstruction(m_currentInstruction);
        }
    }

    // Input registration methods
    void registerInput(Ciphertext<Element> ciphertext, std::string name = "", bool isMutable = false) override {
        addCiphertextInput(ciphertext, name);
    }

    void registerInput(ConstCiphertext<Element> ciphertext, std::string name = "", bool isMutable = false) override {
        addCiphertextInput(ciphertext, name);
    }

    void registerInputs(std::initializer_list<Ciphertext<Element>> ciphertexts,
                        std::initializer_list<std::string> names = {}, bool isMutable = false) override {
        auto nameIt = names.begin();
        for (auto& ct : ciphertexts) {
            std::string name = (nameIt != names.end()) ? *nameIt++ : "";
            addCiphertextInput(ct, name);
        }
    }

    void registerInputs(std::initializer_list<ConstCiphertext<Element>> ciphertexts,
                        std::initializer_list<std::string> names = {}, bool isMutable = false) override {
        auto nameIt = names.begin();
        for (auto& ct : ciphertexts) {
            std::string name = (nameIt != names.end()) ? *nameIt++ : "";
            addCiphertextInput(ct, name);
        }
    }

    void registerInput(Plaintext plaintext, std::string name = "", bool isMutable = false) override {
        addPlaintextInput(plaintext, name);
    }

    void registerInput(ConstPlaintext plaintext, std::string name = "", bool isMutable = false) override {
        addPlaintextInput(plaintext, name);
    }

    void registerInputs(std::initializer_list<Plaintext> plaintexts, std::initializer_list<std::string> names = {},
                        bool isMutable = false) override {
        auto nameIt = names.begin();
        for (auto& pt : plaintexts) {
            std::string name = (nameIt != names.end()) ? *nameIt++ : "";
            addPlaintextInput(pt, name);
        }
    }

    void registerInput(const PublicKey<Element> publicKey, std::string name = "", bool isMutable = false) override {
        // For keys, we generally don't trace them in HERACLES format, but we could add as parameters
        addParameter(name.empty() ? "public_key" : name, "public_key", "string");
    }

    void registerInput(const PrivateKey<Element> privateKey, std::string name = "", bool isMutable = false) override {
        addParameter(name.empty() ? "private_key" : name, "private_key", "string");
    }

    void registerInput(const EvalKey<Element> evalKey, std::string name = "", bool isMutable = false) override {
        addParameter(name.empty() ? "eval_key" : name, "eval_key", "string");
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
        addParameter(name.empty() ? "encoding" : name, encodingStr, "string");
    }

    void registerInput(const std::vector<int64_t>& values, std::string name = "", bool isMutable = false) override {
        addParameter(name.empty() ? "int64_vector" : name, values.size(), "uint64");
    }

    void registerInput(const std::vector<int32_t>& values, std::string name = "", bool isMutable = false) override {
        addParameter(name.empty() ? "int32_vector" : name, values.size(), "uint32");
    }

    void registerInput(const std::vector<uint32_t>& values, std::string name = "", bool isMutable = false) override {
        addParameter(name.empty() ? "uint32_vector" : name, values.size(), "uint32");
    }

    void registerInput(const std::vector<double>& values, std::string name = "", bool isMutable = false) override {
        addParameter(name.empty() ? "double_vector" : name, values.size(), "uint64");
    }

    void registerInput(double value, std::string name = "", bool isMutable = false) override {
        addParameter(name.empty() ? "double" : name, value, "double");
    }

    void registerInput(std::complex<double> value, std::string name = "", bool isMutable = false) override {
        addParameter(name.empty() ? "complex_real" : name + "_real", value.real(), "double");
        addParameter(name.empty() ? "complex_imag" : name + "_imag", value.imag(), "double");
    }

    void registerInput(const std::vector<std::complex<double>>& values, std::string name = "",
                       bool isMutable = false) override {
        addParameter(name.empty() ? "complex_vector" : name, values.size(), "uint64");
    }

    void registerInput(int64_t value, std::string name = "", bool isMutable = false) override {
        addParameter(name.empty() ? "int64" : name, value, "int64");
    }

    void registerInput(size_t value, std::string name = "", bool isMutable = false) override {
        addParameter(name.empty() ? "size_t" : name, value, "uint64");
    }

    void registerInput(bool value, std::string name = "", bool isMutable = false) override {
        addParameter(name.empty() ? "bool" : name, value ? "true" : "false", "string");
    }

    void registerInput(const std::string& value, std::string name = "", bool isMutable = false) override {
        addParameter(name.empty() ? "string" : name, value, "string");
    }

    void registerInput(const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>& evalKeyMap, std::string name = "",
                       bool isMutable = false) override {
        size_t mapSize = evalKeyMap ? evalKeyMap->size() : 0;
        addParameter(name.empty() ? "eval_key_map_size" : name + "_size", mapSize, "uint64");
    }

    void registerInput(void* ptr, std::string name = "", bool isMutable = false) override {
        std::stringstream ss;
        ss << std::hex << ptr;
        addParameter(name.empty() ? "void_ptr" : name, ss.str(), "string");
    }

    // Output registration methods
    Ciphertext<Element> registerOutput(Ciphertext<Element> ciphertext, std::string name = "") override {
        if (ciphertext && ciphertext->GetElements().size() > 0) {
            std::string objectId = getObjectId(ciphertext, "ciphertext");
            size_t numRNS        = ciphertext->GetElements()[0].GetNumOfElements();
            size_t order         = ciphertext->GetElements().size();

            auto* destOp = m_currentInstruction.mutable_args()->add_dests();
            setHERACLESOperandObject(destOp, objectId, numRNS, order);

            // Store data for test vector generation
            storeDataIfNeeded(ciphertext, objectId);

            m_hasOutput = true;
        }
        return ciphertext;
    }

    ConstCiphertext<Element> registerOutput(ConstCiphertext<Element> ciphertext, std::string name = "") override {
        if (ciphertext && ciphertext->GetElements().size() > 0) {
            std::string objectId = getObjectId(ciphertext, "ciphertext");
            size_t numRNS        = ciphertext->GetElements()[0].GetNumOfElements();
            size_t order         = ciphertext->GetElements().size();

            auto* destOp = m_currentInstruction.mutable_args()->add_dests();
            setHERACLESOperandObject(destOp, objectId, numRNS, order);

            // Store data for test vector generation
            storeDataIfNeeded(ciphertext, objectId);

            m_hasOutput = true;
        }
        return ciphertext;
    }

    Plaintext registerOutput(Plaintext plaintext, std::string name = "") override {
        if (plaintext) {
            std::string objectId = getObjectId(plaintext, "plaintext");
            auto* destOp         = m_currentInstruction.mutable_args()->add_dests();
            setHERACLESOperandObject(destOp, objectId, 0, 1);

            // Store data for test vector generation
            storeDataIfNeeded(plaintext, objectId);

            m_hasOutput = true;
        }
        return plaintext;
    }

    KeyPair<Element> registerOutput(KeyPair<Element> keyPair, std::string name = "") override {
        // For key pairs, we don't typically trace them in HERACLES format
        m_hasOutput = true;  // Mark as having output but don't add to destinations
        return keyPair;
    }

    EvalKey<Element> registerOutput(EvalKey<Element> evalKey, std::string name = "") override {
        m_hasOutput = true;
        return evalKey;
    }

    std::vector<EvalKey<Element>> registerOutput(std::vector<EvalKey<Element>> evalKeys,
                                                 std::string name = "") override {
        m_hasOutput = true;
        return evalKeys;
    }

    std::vector<Ciphertext<Element>> registerOutput(std::vector<Ciphertext<Element>> ciphertexts,
                                                    std::string name = "") override {
        for (auto& ct : ciphertexts) {
            registerOutput(ct, name);
        }
        return ciphertexts;
    }

    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> registerOutput(
        std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap, std::string name = "") override {
        m_hasOutput = true;
        return evalKeyMap;
    }

    PublicKey<Element> registerOutput(PublicKey<Element> publicKey, std::string name = "") override {
        m_hasOutput = true;
        return publicKey;
    }

    PrivateKey<Element> registerOutput(PrivateKey<Element> privateKey, std::string name = "") override {
        m_hasOutput = true;
        return privateKey;
    }

    std::string registerOutput(const std::string& value, std::string name = "") override {
        m_hasOutput = true;
        return value;
    }

    Element registerOutput(Element element, std::string name = "") override {
        m_hasOutput = true;
        return element;
    }

private:
    std::string m_func;
    HeraclesTracer<Element>* m_tracer;
    heracles::fhe_trace::Instruction m_currentInstruction;
    std::vector<std::string> m_inputObjectIds;
    bool m_hasOutput;
};

/// HERACLES Protobuf Tracing implementation
/// Generates protobuf traces compatible with the HERACLES project
template <typename Element>
class HeraclesTracer : public Tracer<Element> {
public:
    explicit HeraclesTracer(const std::string& filename = "openfhe-heracles-trace") : m_filename(filename) {
        // Default to CKKS scheme (can be changed via setContext)
    }

    explicit HeraclesTracer(const std::string& filename, const CryptoContext<Element>& cc) : m_filename(filename) {
        setContext(cc);
    }

    ~HeraclesTracer() override {
        // Save the trace when the tracer is destroyed
        if (!m_instructions.empty()) {
            saveTrace();
        }
    }

    std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(std::string func) override {
        return std::make_unique<HeraClesFunctionTracer<Element>>(func, this);
    }

    std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(
        std::string func, std::initializer_list<Ciphertext<Element>> ciphertexts) override {
        auto tracer = std::make_unique<HeraClesFunctionTracer<Element>>(func, this);
        tracer->registerInputs(ciphertexts);
        return tracer;
    }

    std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(
        std::string func, std::initializer_list<ConstCiphertext<Element>> ciphertexts) override {
        auto tracer = std::make_unique<HeraClesFunctionTracer<Element>>(func, this);
        tracer->registerInputs(ciphertexts);
        return tracer;
    }

    std::unique_ptr<DataTracer<Element>> TraceDataUpdate(std::string function_name) override {
        return std::make_unique<NullDataTracer<Element>>();
    }

    /// Set the crypto context information for the trace
    void setContext(const CryptoContext<Element>& cc) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Store the crypto context for data trace generation
        m_cryptoContext = cc;

        // Store context information directly
        auto scheme = cc->getSchemeId();
        if (scheme == lbcrypto::SCHEME::CKKSRNS_SCHEME) {
            m_scheme = heracles::common::SCHEME_CKKS;
        }
        else if (scheme == lbcrypto::SCHEME::BFVRNS_SCHEME) {
            m_scheme = heracles::common::SCHEME_BFV;
        }
        else if (scheme == lbcrypto::SCHEME::BGVRNS_SCHEME) {
            m_scheme = heracles::common::SCHEME_BGV;
        }
        else {
            m_scheme = heracles::common::SCHEME_CKKS;  // Default fallback
        }

        m_ringDimension = cc->GetRingDimension();

        // For RNS-based schemes, get additional parameters
        auto cc_rns = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        if (cc_rns) {
            m_keyRnsNum = cc_rns->GetParamsQP()->GetParams().size();
            m_dnum      = cc_rns->GetNumPartQ();
            m_alpha     = cc_rns->GetNumPerPartQ();
        }

        m_qSize = cc->GetElementParams()->GetParams().size();

        // Clear cached objects since context changed
        m_cachedFHETrace.reset();
        m_cachedContext.reset();
        m_cachedTestVector.reset();
    }

    /// Generate all traces once and cache them
    void generateTracesIfNeeded() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_cachedFHETrace) {
            return;  // Already generated
        }

        std::cout << "Generating traces for the first time..." << std::endl;

        // Generate FHE trace directly
        m_cachedFHETrace = std::make_unique<heracles::fhe_trace::Trace>();
        m_cachedFHETrace->set_scheme(m_scheme);
        m_cachedFHETrace->set_n(m_ringDimension);
        m_cachedFHETrace->set_key_rns_num(m_keyRnsNum);
        m_cachedFHETrace->set_dnum(m_dnum);
        m_cachedFHETrace->set_alpha(m_alpha);
        m_cachedFHETrace->set_q_size(m_qSize);

        *(m_cachedFHETrace->mutable_instructions()) = {m_instructions.begin(), m_instructions.end()};

        // Generate context and test vector if we have a crypto context
        if (m_cryptoContext) {
            std::cout << "Generating context..." << std::endl;
            m_cachedContext = std::make_unique<heracles::data::FHEContext>(extractFHEContext(m_cryptoContext));

            std::cout << "Generating test vector..." << std::endl;
            m_cachedTestVector = std::make_unique<heracles::data::TestVector>(generateTestVector(*m_cachedFHETrace));
        }

        std::cout << "Traces generated and cached!" << std::endl;
    }

    /// Get the FHE trace (generates and caches if needed)
    heracles::fhe_trace::Trace getTrace() const {
        generateTracesIfNeeded();
        return *m_cachedFHETrace;
    }

    /// Get the FHE context (generates and caches if needed)
    heracles::data::FHEContext getFHEContext() const {
        if (!m_cryptoContext) {
            throw std::runtime_error("CryptoContext not set. Call setContext() first.");
        }
        generateTracesIfNeeded();
        return *m_cachedContext;
    }

    /// Get the test vector (generates and caches if needed)
    heracles::data::TestVector getTestVector() const {
        if (!m_cryptoContext) {
            throw std::runtime_error("CryptoContext not set. Call setContext() first.");
        }
        generateTracesIfNeeded();
        return *m_cachedTestVector;
    }

    /// Save trace to file in binary format
    void saveTrace(const std::string& filename = "") {
        auto trace = getTrace();
        heracles::fhe_trace::store_trace(getFilename(filename, ".bin"), trace);
    }

    /// Save trace to file in JSON format
    void saveTraceJson(const std::string& filename = "") {
        auto actualFilename = getFilename(filename, ".json");
        std::cout << "Saving FHE trace to JSON: " << actualFilename << std::endl;
        auto trace = getTrace();
        heracles::fhe_trace::store_json_trace(actualFilename, trace);
    }

    /// Save data trace to file (context + test vectors)
    void saveDataTrace(const std::string& filename = "") {
        if (!m_cryptoContext) {
            std::cout << "No crypto context available, skipping data trace" << std::endl;
            return;
        }

        auto actualFilename = getFilename(filename, "_data.bin");
        std::cout << "Saving data trace..." << std::endl;

        auto context    = getFHEContext();
        auto testVector = getTestVector();

        // Save as binary data trace
        heracles::data::store_data_trace(actualFilename, context, testVector);

        // Save context and test vector as JSON for debugging
        std::string contextJsonFilename    = actualFilename.substr(0, actualFilename.rfind('.')) + "_context.json";
        std::string testVectorJsonFilename = actualFilename.substr(0, actualFilename.rfind('.')) + "_testvector.json";

        heracles::data::store_hec_context_json(contextJsonFilename, context);
        heracles::data::store_testvector_json(testVectorJsonFilename, testVector);
    }

    /// Store DCRTPoly data for test vector generation
    void storeData(const std::string& objectId, const std::vector<Element>& dcrtpolys) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Simply collect objects in the pool during tracing
        // Conversion to protobuf happens only at the very end in generateTestVector()
        if (!dcrtpolys.empty()) {
            m_dataObjectPool[objectId] = dcrtpolys;
        }
    }

private:
    /// Helper to get actual filename with default extension
    std::string getFilename(const std::string& filename, const std::string& defaultExtension) const {
        return filename.empty() ? (m_filename + defaultExtension) : filename;
    }

    /// Extract FHE context from OpenFHE CryptoContext
    heracles::data::FHEContext extractFHEContext(const CryptoContext<Element>& cc) const {
        heracles::data::FHEContext context;

        auto poly_degree = cc->GetRingDimension();
        auto cc_rns      = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        auto key_rns     = cc_rns->GetParamsQP()->GetParams();

        context.set_n(poly_degree);
        context.set_key_rns_num(key_rns.size());
        context.set_alpha(cc_rns->GetNumPerPartQ());
        context.set_digit_size(cc_rns->GetNumPartQ());
        context.set_q_size(cc->GetElementParams()->GetParams().size());

        for (const auto& parms : key_rns) {
            auto q_i = parms->GetModulus();
            context.add_q_i(q_i.ConvertToInt());

            auto psi_i = RootOfUnity<NativeInteger>(poly_degree * 2, parms->GetModulus());
            context.add_psi(psi_i.ConvertToInt());
        }

        auto scheme = cc->getSchemeId();
        switch (scheme) {
            case SCHEME::CKKSRNS_SCHEME: {
                context.set_scheme(heracles::common::SCHEME_CKKS);
                // Add CKKS-specific information
                extractCKKSInfo(context.mutable_ckks_info(), cc);
            } break;
            case SCHEME::BGVRNS_SCHEME: {
                context.set_scheme(heracles::common::SCHEME_BGV);
                // BGV not fully supported yet
            } break;
            case SCHEME::BFVRNS_SCHEME: {
                context.set_scheme(heracles::common::SCHEME_BFV);
                // BFV not fully supported yet
            } break;
            default:
                context.set_scheme(heracles::common::SCHEME_CKKS);  // Default fallback
        }

        return context;
    }

    /// Extract CKKS-specific information
    bool extractCKKSInfo(heracles::data::CKKSSpecific* ckks_info, const CryptoContext<Element>& cc) const {
        // Simplified CKKS info extraction
        // In a full implementation, this would extract keys, scaling factors, etc.
        auto cc_rns = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());

        // Extract scaling factors
        size_t sizeQ = cc->GetElementParams()->GetParams().size();
        for (size_t i = 0; i < sizeQ; ++i) {
            ckks_info->add_scaling_factor_real(cc_rns->GetScalingFactorReal(i));
            if (i < sizeQ - 1) {
                ckks_info->add_scaling_factor_real_big(cc_rns->GetScalingFactorRealBig(i));
            }
        }

        return true;
    }

    /// Generate test vector from stored data
    heracles::data::TestVector generateTestVector(const heracles::fhe_trace::Trace& trace) const {
        std::cout << "Generating test vector" << std::endl;

        heracles::data::TestVector testVector;

        // Extract symbols from trace instructions
        std::unordered_set<std::string> usedSymbols;

        for (const auto& instruction : trace.instructions()) {
            // Add destination symbols
            for (const auto& dest : instruction.args().dests()) {
                usedSymbols.insert(dest.symbol_name());
            }
            // Add source symbols
            for (const auto& src : instruction.args().srcs()) {
                usedSymbols.insert(src.symbol_name());
            }
        }

        // For each used symbol, add its data to the test vector if available
        for (const auto& symbolId : usedSymbols) {
            if (m_dataObjectPool.find(symbolId) != m_dataObjectPool.end()) {
                auto& dcrtpolys  = m_dataObjectPool.at(symbolId);
                auto& symbolData = (*testVector.mutable_sym_data_map())[symbolId];

                std::cout << "Converting DCRTPoly data for symbol: " << symbolId << std::endl;

                // Convert DCRTPoly to protobuf format (expensive conversion only happens once at the very end!)
                convertDCRTPolyToProtobuf(symbolData.mutable_dcrtpoly(), dcrtpolys);
            }
        }

        return testVector;
    }

    /// Convert DCRTPoly to protobuf format - FAST PARALLEL VERSION (based on old tracing_integration_test)
    bool convertDCRTPolyToProtobuf(heracles::data::DCRTPoly* proto_dcrtpoly,
                                   const std::vector<Element>& dcrtpolys) const {
        for (const auto& dcrtpoly : dcrtpolys) {
            auto poly_pb      = proto_dcrtpoly->add_polys();
            const auto& elems = dcrtpoly.GetAllElements();

            poly_pb->set_in_openfhe_evaluation((dcrtpoly.GetFormat() == Format::EVALUATION));

            for (size_t l = 0; l < dcrtpoly.GetNumOfElements(); ++l) {
                size_t poly_degree = elems[l].GetLength();
                auto elem_vals     = elems[l].GetValues();
                auto rns_poly_pb   = poly_pb->add_rns_polys();

                // OPTIMIZATION: Use parallel conversion like the old system
                std::vector<uint32_t> v_coeffs(poly_degree);
    #pragma omp parallel for
                for (size_t j = 0; j < poly_degree; ++j) {
                    v_coeffs[j] = elem_vals[j].ConvertToInt();
                }

                *rns_poly_pb->mutable_coeffs() = {v_coeffs.begin(), v_coeffs.end()};
                rns_poly_pb->set_modulus(elems[l].GetModulus().ConvertToInt());
            }

            proto_dcrtpoly->set_in_ntt_form((dcrtpolys[0].GetFormat() == Format::EVALUATION));
        }
        return true;
    }

public:  /// Add an instruction to the trace
    void addInstruction(const heracles::fhe_trace::Instruction& instruction) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_instructions.push_back(instruction);
    }

    /// Reset the trace (clear all instructions and data pool)
    void reset() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_instructions.clear();
        m_dataObjectPool.clear();  // Clear collected objects

        // Clear cached objects to force regeneration
        m_cachedFHETrace.reset();
        m_cachedContext.reset();
        m_cachedTestVector.reset();
    }

private:
    std::string m_filename;
    std::vector<heracles::fhe_trace::Instruction> m_instructions;
    mutable std::mutex m_mutex;

    // Context information (previously stored in m_trace)
    heracles::common::Scheme m_scheme = heracles::common::SCHEME_CKKS;
    uint32_t m_ringDimension          = 0;
    uint32_t m_keyRnsNum              = 0;
    uint32_t m_dnum                   = 0;
    uint32_t m_alpha                  = 0;
    uint32_t m_qSize                  = 0;

    // ID management (same approach as SimpleTracer)
    std::unordered_map<std::string, std::string> m_uniqueID;  // hash -> human-readable ID
    std::unordered_map<std::string, size_t> m_counters;       // type -> counter

    // Data trace support
    CryptoContext<Element> m_cryptoContext;  // Stored crypto context
    std::unordered_map<std::string, std::vector<Element>>
        m_dataObjectPool;  // objectId -> DCRTPoly data (collected during tracing)

    // Cached traces (generated once, reused multiple times)
    mutable std::unique_ptr<heracles::fhe_trace::Trace> m_cachedFHETrace;
    mutable std::unique_ptr<heracles::data::FHEContext> m_cachedContext;
    mutable std::unique_ptr<heracles::data::TestVector> m_cachedTestVector;

    friend class HeraClesFunctionTracer<Element>;
};

}  // namespace lbcrypto

#endif  // ENABLE_TRACER_SUPPORT

#endif  // __HERACLESTRACER_H__
