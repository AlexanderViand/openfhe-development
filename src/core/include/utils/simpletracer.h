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

namespace lbcrypto {

template <typename Element>
class SimpleTracer;

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

    void registerInput(Ciphertext<Element> ciphertext, std::string name = "") override {
        addInput(name.empty() ? "ciphertext" : name, ciphertext.get());
    }
    void registerInput(ConstCiphertext<Element> ciphertext, std::string name = "") override {
        addInput(name.empty() ? "constciphertext" : name, ciphertext.get());
    }
    void registerInputs(std::initializer_list<Ciphertext<Element>> ciphertexts,
                        std::initializer_list<std::string> names = {}) override {
        auto n = names.begin();
        for (auto& ct : ciphertexts) {
            std::string nm = n == names.end() ? "ciphertext" : *n;
            if (n != names.end())
                ++n;
            registerInput(ct, nm);
        }
    }
    void registerInputs(std::initializer_list<ConstCiphertext<Element>> ciphertexts,
                        std::initializer_list<std::string> names = {}) override {
        auto n = names.begin();
        for (auto& ct : ciphertexts) {
            std::string nm = n == names.end() ? "constciphertext" : *n;
            if (n != names.end())
                ++n;
            registerInput(ct, nm);
        }
    }
    void registerInput(Plaintext plaintext, std::string name = "") override {
        addInput(name.empty() ? "plaintext" : name, plaintext.get());
    }
    void registerInput(ConstPlaintext plaintext, std::string name = "") override {
        addInput(name.empty() ? "plaintext" : name, plaintext.get());
    }
    void registerInputs(std::initializer_list<Plaintext> plaintexts,
                        std::initializer_list<std::string> names = {}) override {
        auto n = names.begin();
        for (auto& pt : plaintexts) {
            std::string nm = n == names.end() ? "plaintext" : *n;
            if (n != names.end())
                ++n;
            registerInput(pt, nm);
        }
    }
    void registerInput(const PublicKey<Element> key, std::string name = "") override {
        addInput(name.empty() ? "publickey" : name, key.get());
    }
    void registerInput(const PrivateKey<Element> key, std::string name = "") override {
        addInput(name.empty() ? "privatekey" : name, key.get());
    }
    void registerInput(const PlaintextEncodings encoding, std::string name = "") override {
        std::ostringstream ss;
        ss << (name.empty() ? "encoding" : name) << "=" << int(encoding);
        m_inputs.push_back(ss.str());
    }
    void registerInput(const std::vector<int64_t>& values, std::string name = "") override {
        std::ostringstream ss;
        ss << (name.empty() ? "vec" : name) << "=[";
        for (size_t i = 0; i < values.size(); ++i) {
            if (i)
                ss << ",";
            ss << values[i];
        }
        ss << "]";
        m_inputs.push_back(ss.str());
    }
    void registerInput(double value, std::string name = "") override {
        std::ostringstream ss;
        ss << (name.empty() ? "double" : name) << "=" << value;
        m_inputs.push_back(ss.str());
    }
    void registerInput(std::complex<double> value, std::string name = "") override {
        std::ostringstream ss;
        ss << (name.empty() ? "complex" : name) << "=" << value.real() << "+" << value.imag() << "i";
        m_inputs.push_back(ss.str());
    }
    void registerInput(int64_t value, std::string name = "") override {
        std::ostringstream ss;
        ss << (name.empty() ? "int" : name) << "=" << value;
        m_inputs.push_back(ss.str());
    }
    void registerInput(size_t value, std::string name = "") override {
        std::ostringstream ss;
        ss << (name.empty() ? "size" : name) << "=" << value;
        m_inputs.push_back(ss.str());
    }
    void registerInput(void* ptr, std::string name = "") override {
        addInput(name.empty() ? "ptr" : name, ptr);
    }

    Ciphertext<Element> registerOutput(Ciphertext<Element> ciphertext, std::string name = "") override {
        addOutput(name.empty() ? "ciphertext" : name, ciphertext.get());
        return ciphertext;
    }
    ConstCiphertext<Element> registerOutput(ConstCiphertext<Element> ciphertext, std::string name = "") override {
        addOutput(name.empty() ? "constciphertext" : name, ciphertext.get());
        return ciphertext;
    }
    Plaintext registerOutput(Plaintext plaintext, std::string name = "") override {
        addOutput(name.empty() ? "plaintext" : name, plaintext.get());
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

    void addInput(const std::string& name, const void* ptr) {
        std::ostringstream ss;
        ss << name << "@" << m_tracer->GetId(ptr, name);
        m_inputs.push_back(ss.str());
    }
    void addOutput(const std::string& name, const void* ptr) {
        std::ostringstream ss;
        ss << name << "@" << m_tracer->GetId(ptr, name);
        m_outputs.push_back(ss.str());
    }

    std::string m_func;
    OStreamPtr m_out;
    SimpleTracer<Element>* m_tracer;
    std::vector<std::string> m_inputs;
    std::vector<std::string> m_outputs;
    size_t m_level;
};

template <typename Element>
class SimpleTracer : public Tracer<Element> {
public:
    explicit SimpleTracer(const std::string& filename = "trace.log")
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

    std::string GetId(const void* ptr, const std::string& type) {
        auto it = m_idMap.find(ptr);
        if (it != m_idMap.end()) {
            return it->second;
        }

        std::string prefix = typePrefix(type);
        size_t id          = ++m_counters[prefix];
        std::string value  = prefix + std::to_string(id);
        m_idMap[ptr]       = value;
        return value;
    }

    static std::string typePrefix(const std::string& type) {
        if (type.find("ciphertext") != std::string::npos)
            return "ct";
        if (type.find("plaintext") != std::string::npos)
            return "pt";
        if (type.find("publickey") != std::string::npos)
            return "pk";
        if (type.find("privatekey") != std::string::npos)
            return "sk";
        return "obj";
    }

private:
    OStreamPtr m_stream;
    std::unordered_map<const void*, std::string> m_idMap;
    std::unordered_map<std::string, size_t> m_counters;
    size_t m_level;
};

}  // namespace lbcrypto

#endif  // ENABLE_TRACER_SUPPORT

#endif  // __SIMPLETRACER_H__
