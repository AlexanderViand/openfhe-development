//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#ifndef LBCRYPTO_CRYPTO_CKKSRNS_SCHEME_H
#define LBCRYPTO_CRYPTO_CKKSRNS_SCHEME_H

#include "schemerns/rns-scheme.h"

#include "scheme/ckksrns/ckksrns-advancedshe.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/ckksrns-leveledshe.h"
#include "scheme/ckksrns/ckksrns-multiparty.h"
#include "scheme/ckksrns/ckksrns-parametergeneration.h"
#include "scheme/ckksrns/ckksrns-pke.h"
#include "scheme/ckksrns/ckksrns-pre.h"
#include "scheme/ckksrns/ckksrns-schemeswitching.h"

#include <memory>
#include <string>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class SchemeCKKSRNS : public SchemeRNS {
public:
    SchemeCKKSRNS() {
        this->m_ParamsGen = std::make_shared<ParameterGenerationCKKSRNS>();
    }

    virtual ~SchemeCKKSRNS() = default;

    bool operator==(const SchemeBase<DCRTPoly>& sch) const override {
        return (typeid(sch) == typeid(SchemeCKKSRNS));
    }

    Plaintext MakeAuxPlaintextForLinearTransform(
        const CryptoContextImpl<DCRTPoly>& cc,
        const std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>>& params,
        const std::vector<std::complex<double>>& value, size_t noiseScaleDeg,
        uint32_t level, uint32_t slots) const {
        auto fhe = std::dynamic_pointer_cast<FHECKKSRNS>(this->m_FHE);
        if (!fhe) {
            OPENFHE_THROW("CKKS FHE features are not enabled");
        }
        return fhe->MakeAuxPlaintextForLinearTransform(cc, params, value,
                                                       noiseScaleDeg, level,
                                                       slots);
    }

    std::vector<ReadOnlyPlaintext> EvalLinearTransformPrecomputeSparse(
        const CryptoContextImpl<DCRTPoly>& cc,
        const std::vector<std::vector<std::complex<double>>>& diagonals,
        const std::vector<int32_t>& diagonalIndices, uint32_t dim1,
        double scale = 1., uint32_t L = 0) const {
        auto fhe = std::dynamic_pointer_cast<FHECKKSRNS>(this->m_FHE);
        if (!fhe) {
            OPENFHE_THROW("CKKS FHE features are not enabled");
        }
        return fhe->EvalLinearTransformPrecomputeSparse(
            cc, diagonals, diagonalIndices, dim1, scale, L);
    }

    Ciphertext<DCRTPoly> EvalLinearTransformSparse(
        const std::vector<ReadOnlyPlaintext>& precomputed,
        ConstCiphertext<DCRTPoly>& ciphertext,
        const std::vector<int32_t>& diagonalIndices, uint32_t dim1) const {
        auto fhe = std::dynamic_pointer_cast<FHECKKSRNS>(this->m_FHE);
        if (!fhe) {
            OPENFHE_THROW("CKKS FHE features are not enabled");
        }
        return fhe->EvalLinearTransformSparse(precomputed, ciphertext,
                                              diagonalIndices, dim1);
    }

    void Enable(PKESchemeFeature feature) override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::base_class<SchemeRNS>(this));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        ar(cereal::base_class<SchemeRNS>(this));
    }

    std::string SerializedObjectName() const override {
        return "SchemeCKKSRNS";
    }
};

}  // namespace lbcrypto

#endif
