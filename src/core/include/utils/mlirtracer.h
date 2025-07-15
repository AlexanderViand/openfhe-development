#ifndef __MLIRTRACER_H__
#define __MLIRTRACER_H__

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

namespace lbcrypto {

template <typename Element>
class MlirTracer;

template <typename Element>
class MlirFunctionTracer : public FunctionTracer<Element> {
public:
    MlirFunctionTracer(const std::string& func, std::shared_ptr<std::ostream> out, MlirTracer<Element>* tracer)
        : m_func(func), m_out(std::move(out)), m_tracer(tracer) {}

    ~MlirFunctionTracer() override {
        std::string op = m_tracer->ConvertFuncToOp(m_func);
        if (!m_outputs.empty()) {
            (*m_out) << m_outputs[0] << " = ";
        }
        (*m_out) << "openfhe." << op;
        if (!m_inputs.empty()) {
            (*m_out) << " ";
            for (size_t i = 0; i < m_inputs.size(); ++i) {
                if (i > 0)
                    (*m_out) << ", ";
                (*m_out) << m_inputs[i];
            }
        }
        (*m_out) << " : (";
        for (size_t i = 0; i < m_inputTypes.size(); ++i) {
            if (i > 0)
                (*m_out) << ", ";
            (*m_out) << m_inputTypes[i];
        }
        (*m_out) << ")";
        if (!m_outputTypes.empty()) {
            (*m_out) << " -> " << m_outputTypes[0];
        }
        (*m_out) << std::endl;
    }

    void registerInput(Ciphertext<Element> ciphertext, std::string name = "") override {
        addInput(ciphertext.get(), "ciphertext");
    }
    void registerInput(ConstCiphertext<Element> ciphertext, std::string name = "") override {
        addInput(ciphertext.get(), "ciphertext");
    }
    void registerInputs(std::initializer_list<Ciphertext<Element>> ciphertexts,
                        std::initializer_list<std::string> names = {}) override {
        for (auto& ct : ciphertexts)
            registerInput(ct);
    }
    void registerInputs(std::initializer_list<ConstCiphertext<Element>> ciphertexts,
                        std::initializer_list<std::string> names = {}) override {
        for (auto& ct : ciphertexts)
            registerInput(ct);
    }
    void registerInput(Plaintext plaintext, std::string name = "") override {
        addInput(plaintext.get(), "plaintext");
    }
    void registerInput(ConstPlaintext plaintext, std::string name = "") override {
        addInput(plaintext.get(), "plaintext");
    }
    void registerInputs(std::initializer_list<Plaintext> plaintexts,
                        std::initializer_list<std::string> names = {}) override {
        for (auto& pt : plaintexts)
            registerInput(pt);
    }
    void registerInput(const PublicKey<Element> key, std::string name = "") override {
        addInput(key.get(), "publickey");
    }
    void registerInput(const PrivateKey<Element> key, std::string name = "") override {
        addInput(key.get(), "privatekey");
    }
    void registerInput(const PlaintextEncodings encoding, std::string name = "") override {
        (void)encoding;
    }
    void registerInput(const std::vector<int64_t>& values, std::string name = "") override {
        (void)values;
    }
    void registerInput(double value, std::string name = "") override {
        std::ostringstream ss;
        ss << value;
        m_inputs.push_back(ss.str());
        m_inputTypes.push_back("f64");
    }
    void registerInput(std::complex<double> value, std::string name = "") override {
        std::ostringstream ss;
        ss << "complex<" << value.real() << "," << value.imag() << ">";
        m_inputs.push_back(ss.str());
        m_inputTypes.push_back("!openfhe.complex");
    }
    void registerInput(int64_t value, std::string name = "") override {
        std::ostringstream ss;
        ss << value;
        m_inputs.push_back(ss.str());
        m_inputTypes.push_back("i64");
    }
    void registerInput(size_t value, std::string name = "") override {
        std::ostringstream ss;
        ss << value;
        m_inputs.push_back(ss.str());
        m_inputTypes.push_back("i64");
    }
    void registerInput(void* ptr, std::string name = "") override {
        addInput(ptr, "ptr");
    }

    Ciphertext<Element> registerOutput(Ciphertext<Element> ciphertext, std::string name = "") override {
        addOutput(ciphertext.get(), "ciphertext");
        return ciphertext;
    }
    ConstCiphertext<Element> registerOutput(ConstCiphertext<Element> ciphertext, std::string name = "") override {
        addOutput(ciphertext.get(), "ciphertext");
        return ciphertext;
    }
    Plaintext registerOutput(Plaintext plaintext, std::string name = "") override {
        addOutput(plaintext.get(), "plaintext");
        return plaintext;
    }

private:
    void addInput(const void* ptr, const std::string& type) {
        std::string id = m_tracer->GetId(ptr, type);
        m_inputs.push_back("%" + id);
        m_inputTypes.push_back(m_tracer->GetType(type));
    }
    void addOutput(const void* ptr, const std::string& type) {
        std::string id = m_tracer->GetId(ptr, type);
        m_outputs.push_back("%" + id);
        m_outputTypes.push_back(m_tracer->GetType(type));
    }

    std::string m_func;
    std::shared_ptr<std::ostream> m_out;
    MlirTracer<Element>* m_tracer;
    std::vector<std::string> m_inputs;
    std::vector<std::string> m_inputTypes;
    std::vector<std::string> m_outputs;
    std::vector<std::string> m_outputTypes;
};

template <typename Element>
class MlirTracer : public Tracer<Element> {
public:
    explicit MlirTracer(const std::string& filename = "trace.mlir")
        : m_stream(std::make_shared<std::ofstream>(filename, std::ios::app)) {}
    explicit MlirTracer(std::shared_ptr<std::ostream> stream) : m_stream(std::move(stream)) {}
    ~MlirTracer() override = default;

    std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(std::string func) override {
        return std::make_unique<MlirFunctionTracer<Element>>(func, m_stream, this);
    }
    std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(
        std::string func, std::initializer_list<Ciphertext<Element>> ciphertexts) override {
        auto tracer = std::make_unique<MlirFunctionTracer<Element>>(func, m_stream, this);
        tracer->registerInputs(ciphertexts);
        return tracer;
    }
    std::unique_ptr<FunctionTracer<Element>> StartFunctionTrace(
        std::string func, std::initializer_list<ConstCiphertext<Element>> ciphertexts) override {
        auto tracer = std::make_unique<MlirFunctionTracer<Element>>(func, m_stream, this);
        tracer->registerInputs(ciphertexts);
        return tracer;
    }

    virtual std::unique_ptr<DataTracer<Element>> TraceDataUpdate(std::string function_name) override {
        return std::make_unique<NullDataTracer<Element>>();
    }

    std::string GetId(const void* ptr, const std::string& type) {
        auto it = m_idMap.find(ptr);
        if (it != m_idMap.end())
            return it->second;

        std::string prefix;
        if (type.find("ciphertext") != std::string::npos)
            prefix = "ct";
        else if (type.find("plaintext") != std::string::npos)
            prefix = "pt";
        else if (type.find("publickey") != std::string::npos)
            prefix = "pk";
        else if (type.find("privatekey") != std::string::npos)
            prefix = "sk";
        else if (type.find("context") != std::string::npos)
            prefix = "cc";
        else if (type.find("params") != std::string::npos)
            prefix = "params";
        else
            prefix = "obj";

        size_t id         = ++m_counters[prefix];
        std::string value = prefix + std::to_string(id);
        m_idMap[ptr]      = value;
        return value;
    }

    std::string GetType(const std::string& type) {
        if (type.find("ciphertext") != std::string::npos)
            return "!lwe.ct";
        if (type.find("plaintext") != std::string::npos)
            return "!lwe.pt";
        if (type.find("publickey") != std::string::npos)
            return "!openfhe.pk";
        if (type.find("privatekey") != std::string::npos)
            return "!openfhe.sk";
        if (type.find("context") != std::string::npos)
            return "!openfhe.cc";
        if (type.find("params") != std::string::npos)
            return "!openfhe.params";
        return "!openfhe.obj";
    }

    std::string ConvertFuncToOp(const std::string& func) {
        auto it = m_funcMap.find(func);
        if (it != m_funcMap.end())
            return it->second;
        std::string result;
        for (size_t i = 0; i < func.size(); ++i) {
            char c = func[i];
            if (isupper(c)) {
                if (i > 0)
                    result += "_";
                result += static_cast<char>(tolower(c));
            }
            else {
                result += c;
            }
        }
        return result;
    }

private:
    std::shared_ptr<std::ostream> m_stream;
    std::unordered_map<const void*, std::string> m_idMap;
    std::unordered_map<std::string, size_t> m_counters;
    std::unordered_map<std::string, std::string> m_funcMap = {{"Encrypt", "encrypt"},
                                                              {"Decrypt", "decrypt"},
                                                              {"EvalAdd", "add"},
                                                              {"EvalSub", "sub"},
                                                              {"EvalMult", "mul"},
                                                              {"EvalNegate", "negate"},
                                                              {"EvalRotate", "rot"},
                                                              {"EvalAtIndex", "rot"},
                                                              {"EvalAutomorphism", "automorph"},
                                                              {"EvalMultNoRelin", "mul_no_relin"},
                                                              {"Relinearize", "relin"},
                                                              {"ModReduce", "mod_reduce"},
                                                              {"LevelReduce", "level_reduce"},
                                                              {"Bootstrap", "bootstrap"},
                                                              {"MakePackedPlaintext", "make_packed_plaintext"}};
};

}  // namespace lbcrypto

#endif  // ENABLE_TRACER_SUPPORT

#endif  // __MLIRTRACER_H__
