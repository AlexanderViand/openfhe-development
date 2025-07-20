#ifndef __HERACLESTRACER_H__
#define __HERACLESTRACER_H__

// Defines ENABLE_TRACER_SUPPORT (via config_core.h) so needs to be outside the #ifdef ENABLE_TRACER_SUPPORT
#include "tracing.h"

#ifdef ENABLE_TRACER_SUPPORT

    #ifdef WITH_OPENMP
        #include <omp.h>
    #endif
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
class HeraclesFunctionTracer : public FunctionTracer<Element> {
public:
    HeraclesFunctionTracer(const std::string& func, HeraclesTracer<Element>* tracer) : m_tracer(tracer) {
        m_currentInstruction = heracles::fhe_trace::Instruction();

        // FIXME: we should differentiate between high-level ops and low-level ops
        // and use eval_op name for higher level ops that created several lower-level ops
        // but that also requires adding a bit of scoping logic in HeraclesTracer
        m_currentInstruction.set_evalop_name(func);  // Store the original function name
        auto lowercase_name = std::transform(func.begin(), func.end(), func.begin(), ::tolower);
        m_currentInstruction.set_op(lowercase_name);

        auto cc = m_tracer->getCryptoContext();
        if (cc.getSchemeId() != CKKSRNS_SCHEME) {
            // FIXME: set this based on the plaintext algebra being used
            m_currentInstruction.set_plaintext_index(0);
        }
    }

    ~HeraclesFunctionTracer() override {
        // This is where we could re-order (and in the case of params, rename)
        // inputs/outputs incase we need to deviate from the standard OpenFHE order
        auto dests = m_currentInstruction.mutable_args()->add_dests();
        for (auto d : m_destinations) {
            dests->add_destinations()->CopyFrom(d);
        }
        auto srcs = m_currentInstruction.mutable_args()->add_sources();
        for (auto s : m_sources) {
            srcs->add_sources()->CopyFrom(s);
        }
        auto params = m_currentInstruction.mutable_args()->mutable_parameters();
        for (const auto& param : m_parameters) {
            params->add_parameters()->CopyFrom(param);
        }
    }

    // Input registration methods

    /// For HERACLES, type doesn't really matter, nor does mutability
    void registerInput(std::vector<Element> elements, std::string name) {
        // FIXME: implement!
    }

    void registerInput(Element element, std::string name) {
        registerInput(std::vector<Element>(1, element), name);
    }

    void registerInput(Ciphertext<Element> ciphertext, std::string name, bool isMutable) override {
        name = name.empty() ? "ct" : name;
        registerInput(ciphertext->GetElements(), name);
    }

    void registerInput(ConstCiphertext<Element> ciphertext, std::string name, bool isMutable) override {
        name = name.empty() ? "ct" : name;
        registerInput(ciphertext->GetElements(), name);
    }

    // TODO: move this logic up to Tracer as an overridable default, since it doesn't really rely on anything tracer-specific
    void registerInputs(std::initializer_list<Ciphertext<Element>> ciphertexts,
                        std::initializer_list<std::string> names = {}, bool isMutable) override {
        if (names.empty()) {
            for (auto& ct : ciphertexts)
                registerInput(ct, "ct", isMutable);
            return;
        }

        assert(ciphertexts.size() == names.size() || names.size() == 0);
        auto nameIt = names.begin();
        auto ctxtIt = ciphertexts.begin();
        for (; nameIt != names.end() && ctxtIt != ciphertexts.end(); ++ctxtIt, ++nameIt) {
            registerInput(*ctxtIt, *nameIt, isMutable);
        }
    }

    // Same as non-const
    void registerInputs(std::initializer_list<ConstCiphertext<Element>> ciphertexts,
                        std::initializer_list<std::string> names = {}, bool isMutable) override {
        if (names.empty()) {
            for (auto& ct : ciphertexts)
                registerInput(ct, "ct", isMutable);
            return;
        }

        assert(ciphertexts.size() == names.size() || names.size() == 0);
        auto nameIt = names.begin();
        auto ctxtIt = ciphertexts.begin();
        for (; nameIt != names.end() && ctxtIt != ciphertexts.end(); ++ctxtIt, ++nameIt) {
            registerInput(*ctxtIt, *nameIt, isMutable);
        }
    }

    void registerInput(Plaintext plaintext, std::string name, bool isMutable) override {
        name = name.empty() ? "pt" : name;
        registerInput(plaintext->GetElement<Element>(), name);
    }

    void registerInput(ConstPlaintext plaintext, std::string name, bool isMutable) override {
        name = name.empty() ? "pt" : name;
        registerInput(plaintext->GetElement<Element>(), name);
    }

    // Nearly the same as ctxt version
    void registerInputs(std::initializer_list<Plaintext> plaintexts, std::initializer_list<std::string> names = {},
                        bool isMutable) override {
        if (names.empty()) {
            for (auto& pt : plaintexts)
                registerInput(pt, "pt", isMutable);
            return;
        }

        assert(plaintexts.size() == names.size());
        auto nameIt = names.begin();
        auto ptIt   = plaintexts.begin();
        for (; nameIt != names.end() && ptIt != plaintexts.end(); ++ptIt, ++nameIt) {
            registerInput(*ptIt, *nameIt, isMutable);
        }
    }

    void registerInput(const PublicKey<Element> publicKey, std::string name, bool isMutable) override {
        name = name.empty() ? "pk" : name;
        registerInput(publicKey->GetPublicElements(), name, isMutable);
    }

    void registerInput(const PrivateKey<Element> privateKey, std::string name, bool isMutable) override {
        name = name.empty() ? "sk" : name;
        registerInput(privateKey->GetPrivateElement(), name, isMutable);
    }

    void registerInput(const EvalKey<Element> evalKey, std::string name, bool isMutable) override {
        name = name.empty() ? "ek" : name;
        registerInput(evalKey->GetElement<Element>(), name, isMutable);
    }

    void registerInput(const PlaintextEncodings encoding, std::string name, bool isMutable) override {
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

    void registerInput(const std::vector<int64_t>& values, std::string name, bool isMutable) override {
        addParameter(name.empty() ? "int64_vector" : name, values.size(), "uint64");
    }

    void registerInput(const std::vector<int32_t>& values, std::string name, bool isMutable) override {
        addParameter(name.empty() ? "int32_vector" : name, values.size(), "uint32");
    }

    void registerInput(const std::vector<uint32_t>& values, std::string name, bool isMutable) override {
        addParameter(name.empty() ? "uint32_vector" : name, values.size(), "uint32");
    }

    void registerInput(const std::vector<double>& values, std::string name, bool isMutable) override {
        addParameter(name.empty() ? "double_vector" : name, values.size(), "uint64");
    }

    void registerInput(double value, std::string name, bool isMutable) override {
        addParameter(name.empty() ? "double" : name, value, "double");
    }

    void registerInput(std::complex<double> value, std::string name, bool isMutable) override {
        addParameter(name.empty() ? "complex_real" : name + "_real", value.real(), "double");
        addParameter(name.empty() ? "complex_imag" : name + "_imag", value.imag(), "double");
    }

    void registerInput(const std::vector<std::complex<double>>& values, std::string name, bool isMutable) override {
        addParameter(name.empty() ? "complex_vector" : name, values.size(), "uint64");
    }

    void registerInput(int64_t value, std::string name, bool isMutable) override {
        addParameter(name.empty() ? "int64" : name, value, "int64");
    }

    void registerInput(size_t value, std::string name, bool isMutable) override {
        addParameter(name.empty() ? "size_t" : name, value, "uint64");
    }

    void registerInput(bool value, std::string name, bool isMutable) override {
        addParameter(name.empty() ? "bool" : name, value ? "true" : "false", "string");
    }

    void registerInput(const std::string& value, std::string name, bool isMutable) override {
        addParameter(name.empty() ? "string" : name, value, "string");
    }

    void registerInput(const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>& evalKeyMap, std::string name,
                       bool isMutable) override {
        size_t mapSize = evalKeyMap ? evalKeyMap->size() : 0;
        addParameter(name.empty() ? "eval_key_map_size" : name + "_size", mapSize, "uint64");
    }

    void registerInput(void* ptr, std::string name, bool isMutable) override {
        throw std::runtime_error("HERACLES tracing does not support registering non-typed inputs.");
    }

    // Output registration methods
    Ciphertext<Element> registerOutput(Ciphertext<Element> ciphertext, std::string name) override {
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

    ConstCiphertext<Element> registerOutput(ConstCiphertext<Element> ciphertext, std::string name) override {
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

    Plaintext registerOutput(Plaintext plaintext, std::string name) override {
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

    KeyPair<Element> registerOutput(KeyPair<Element> keyPair, std::string name) override {
        // For key pairs, we don't typically trace them in HERACLES format
        m_hasOutput = true;  // Mark as having output but don't add to destinations
        return keyPair;
    }

    EvalKey<Element> registerOutput(EvalKey<Element> evalKey, std::string name) override {
        m_hasOutput = true;
        return evalKey;
    }

    std::vector<EvalKey<Element>> registerOutput(std::vector<EvalKey<Element>> evalKeys, std::string name) override {
        m_hasOutput = true;
        return evalKeys;
    }

    std::vector<Ciphertext<Element>> registerOutput(std::vector<Ciphertext<Element>> ciphertexts,
                                                    std::string name) override {
        for (auto& ct : ciphertexts) {
            registerOutput(ct, name);
        }
        return ciphertexts;
    }

    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> registerOutput(
        std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap, std::string name) override {
        m_hasOutput = true;
        return evalKeyMap;
    }

    PublicKey<Element> registerOutput(PublicKey<Element> publicKey, std::string name) override {
        m_hasOutput = true;
        return publicKey;
    }

    PrivateKey<Element> registerOutput(PrivateKey<Element> privateKey, std::string name) override {
        m_hasOutput = true;
        return privateKey;
    }

    std::string registerOutput(const std::string& value, std::string name) override {
        m_hasOutput = true;
        return value;
    }

    Element registerOutput(Element element, std::string name) override {
        return element;
    }

private:
    HeraclesTracer<Element>* m_tracer;
    heracles::fhe_trace::Instruction m_currentInstruction;

    // We record the args and params in case some ops require reordering them
    std::vector<heracles::fhe_trace::OperandObject> m_sources;
    std::vector<heracles::fhe_trace::OperandObject> m_destinations;
    std::vector<heracles::fhe_trace::Parameter> m_parameters;

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
            if (ciphertext && ciphertext->GetElements().size() > 0) {
                m_tracer->storeData(objectId, ciphertext->GetElements());
            }

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
            if (plaintext && plaintext->GetElements().size() > 0) {
                m_tracer->storeData(objectId, plaintext->GetElements());
            }

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
};

/// HERACLES Protobuf Tracing implementation
/// Generates protobuf traces compatible with the HERACLES project
template <typename Element>
class HeraclesTracer : public Tracer<Element> {
public:
    HeraclesTracer(const std::string& filename = "openfhe-heracles-trace", const CryptoContext<Element>& cc)
        : m_filename(filename), m_context(cc) {}

    ~HeraclesTracer() override = default;

    std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(std::string func) override {
        return std::make_unique<HeraclesFunctionTracer<Element>>(func, this);
    }

    std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(
        std::string func, std::initializer_list<Ciphertext<Element>> ciphertexts) override {
        auto tracer = std::make_unique<HeraclesFunctionTracer<Element>>(func, this);
        tracer->registerInputs(ciphertexts);
        return tracer;
    }

    std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(
        std::string func, std::initializer_list<ConstCiphertext<Element>> ciphertexts) override {
        auto tracer = std::make_unique<HeraclesFunctionTracer<Element>>(func, this);
        tracer->registerInputs(ciphertexts);
        return tracer;
    }

    std::unique_ptr<DataTracer<Element>> TraceDataUpdate(std::string function_name) override {
        return std::make_unique<NullDataTracer<Element>>();
    }

    CryptoContext<Element> getCryptoContext() {
        return m_context;
    }

    void addInstruction(const heracles::fhe_trace::Instruction& instruction) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_FHETrace)
            _initializeTrace();
        m_FHETrace->add_instructions()->CopyFrom(instruction);
    }

    /// Check if a certain data element already exists
    bool hasData(const std::string& objectID) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_TestVector)
            _initializeTestVector();
        return m_TestVector->sym_data_map().find(objectID) != m_TestVector->sym_data_map().end();
    }

    /// Store data for test vector
    void storeData(const std::string& objectId, const heracles::data::Data& data) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_TestVector)
            _initializeTestVector();

        *m_TestVector.mutable_sym_data_map()[objectId] = data;
    }

    /// Save trace to file in binary format
    void saveBinaryTrace() {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (!m_FHETrace)
            _initializeTrace();
        heracles::fhe_trace::store_trace(m_filename + ".bin", *m_FHETrace);

        if (!m_FHEContext)
            _initializeContext();
        heracles::data::store_fhe_context(m_filename + "_context.bin", *m_FHEContext);

        if (!m_TestVector)
            _initializeTestVector();
        heracles::data::store_testvector(m_filename + "_testvector.bin", *m_TestVector);

        heracles::data::store_data_trace(m_filename + "_data.bin", *m_FHEContext, *m_TestVector);
    }

    /// Save trace to file in JSON format
    void saveJsonTrace() {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (!m_FHETrace)
            m_FHETrace = _initializeTrace();
        heracles::fhe_trace::store_json_trace(m_filename + ".json", *m_FHETrace);

        if (!m_FHEContext)
            m_FHEContext = _initializeContext();
        heracles::data::store_fhe_context_json(m_filename + "_context.json", *m_FHEContext);

        if (!m_TestVector)
            m_TestVector = _initializeTestVector();
        heracles::data::store_testvector_json(m_filename + "_testvector.json", *m_TestVector);

        // Note: the combined data trace object is not available in *.json
    }

private:
    mutable std::mutex m_mutex;

    // ID management (same approach as SimpleTracer)
    std::unordered_map<std::string, std::string> m_uniqueID;  // hash -> human-readable ID
    std::unordered_map<std::string, size_t> m_counters;       // type -> counter

    CryptoContext<Element> m_cryptoContext;                        // Stored crypto context
    std::vector<heracles::fhe_trace::Instruction> m_instructions;  // Collected instructions
    std::unordered_map<std::string, std::vector<Element>> m_data;  // Collected data (by objectID)

    std::string m_filename;            // Filename basis to use. Will be extended with _data and *.bin/*.json
    CryptoContext<Element> m_context;  // CryptoContext for the current trace

    // Generated traces (nullptr until tracing is finished)
    std::unique_ptr<heracles::fhe_trace::Trace> m_FHETrace   = nullptr;
    std::unique_ptr<heracles::data::FHEContext> m_FHEContext = nullptr;
    std::unique_ptr<heracles::data::TestVector> m_TestVector = nullptr;

    void _initializeTrace() {
        m_FHETrace = std::make_unique<heracles::fhe_trace::Trace>();

        if (!m_FHEContext)
            m_FHEContext = _initializeContext();

        m_FHETrace->set_scheme(m_FHEContext->scheme());
        m_FHETrace->set_n(m_FHEContext->n());
        m_FHETrace->set_key_rns_num(m_FHEContext->key_rns_num());
        m_FHETrace->set_q_size(m_FHEContext->q_size());
        m_FHETrace->set_dnum(m_FHEContext->digit_size());
        m_FHETrace->set_alpha(m_FHEContext->alpha());
    }

    void _initializeContext() {
        m_FHEContext = std::make_unique<heracles::data::FHEContext>();

        auto cc_rns = std::dynamic_pointer_cast<CryptoParametersRNS>(m_context->GetCryptoParameters());
        if (!cc_rns)
            throw std::runtime_error("HERACLES requires RNS parameters.");
        auto key_rns = cc_rns->GetParamsQP()->GetParams();

        auto scheme = m_context->getSchemeId();
        switch (scheme) {
            case SCHEME::CKKSRNS_SCHEME: {
                m_FHEContext->set_scheme(heracles::common::SCHEME_CKKS);
                // Add CKKS-specific information
                m_FHEContext->set_has_ckks_info(true);
                auto ckks_info = m_FHEContext->mutable_ckks_info();
                size_t sizeQ   = m_context->GetElementParams()->GetParams().size();
                for (size_t i = 0; i < sizeQ; ++i) {
                    ckks_info->add_scaling_factor_real(cc_rns->GetScalingFactorReal(i));
                    if (i < sizeQ - 1)
                        ckks_info->add_scaling_factor_real_big(cc_rns->GetScalingFactorRealBig(i));
                }
            } break;
            case SCHEME::BGVRNS_SCHEME: {
                m_FHEContext->set_scheme(heracles::common::SCHEME_BGV);
                // BGV not fully supported yet
            } break;
            case SCHEME::BFVRNS_SCHEME: {
                m_FHEContext->set_scheme(heracles::common::SCHEME_BFV);
                // BFV not fully supported yet
            } break;
            default:
                throw std::runtime_error("Unsupported scheme for HERACLES tracing");
        }

        // TODO: check in old tracing code what these should be set to!
        m_FHEContext->set_n(m_context->GetRingDimension());
        m_FHEContext->set_key_rns_num(key_rns.size());
        m_FHEContext->set_alpha(cc_rns->GetNumPerPartQ());
        m_FHEContext->set_digit_size(cc_rns->GetNumPartQ());
        for (const auto& parms : key_rns) {
            auto q_i = parms->GetModulus();
            m_FHEContext->add_q_i(q_i.ConvertToInt());

            auto psi_i = RootOfUnity<NativeInteger>(poly_degree * 2, parms->GetModulus());
            m_FHEContext->add_psi(psi_i.ConvertToInt());
        }
        m_FHEContext->set_q_size(cc->GetElementParams()->GetParams().size());
        m_FHEContext->set_alpha(cc_rns->GetNumPerPartQ());
    }

    void _initializeTestVector() {
        // Nothing to do here since it's just a data map
        m_TestVector = std::make_unique<heracles::data::TestVector>();
    }
};

}  // namespace lbcrypto

#endif  // ENABLE_TRACER_SUPPORT

#endif  // __HERACLESTRACER_H__
