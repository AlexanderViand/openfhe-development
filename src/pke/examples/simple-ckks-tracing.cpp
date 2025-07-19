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

/*
  Simple CKKS example with tracing enabled.
  This example demonstrates that OpenFHE will automatically perform relinearization (relin)
  and rescale operations after ciphertext-ciphertext multiplications, even if these are not
  explicitly called in the code.
*/

#include "openfhe.h"
#include "utils/simpletracer.h"

using namespace lbcrypto;

int main() {
    // Step 1: Setup CryptoContext
    uint32_t multDepth = 2; // At least 2 to see multiple rescale/relin
    uint32_t scaleModSize = 50;
    uint32_t batchSize = 8;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    // Enable tracing
    IF_TRACE(auto tracer = std::make_shared<SimpleTracer<DCRTPoly>>("simple-ckks-tracing-trace.txt"));
    IF_TRACE(cc->setTracer(std::move(tracer)));

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    // Step 2: Key Generation
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Step 3: Encoding and encryption of inputs
    std::vector<double> x1 = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
    std::vector<double> x2 = {2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0};

    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2);

    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

    // Step 4: Homomorphic computation
    // This multiplication will trigger both relin and rescale automatically.
    auto cMul = cc->EvalMult(c1, c2);
    // A second multiplication will trigger another relin and rescale.
    auto cMul2 = cc->EvalMult(cMul, c2);
    // (No explicit call to EvalRelinearize or EvalRescale!)

    // Step 5: Decryption and output
    Plaintext result;
    std::cout.precision(8);

    cc->Decrypt(keys.secretKey, cMul2, &result);
    result->SetLength(batchSize);
    std::cout << "(x1 * x2) * x2 = " << result << std::endl;
    std::cout << "Estimated precision in bits: " << result->GetLogPrecision() << std::endl;

    std::cout << "\nNOTE: Relinearization and rescale were performed automatically after EvalMult.\n"
                 "Check the trace file 'simple-ckks-tracing-trace.txt' for details.\n" << std::endl;

    return 0;
} 