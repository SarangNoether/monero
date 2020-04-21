// Copyright (c) 2014-2020, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <stdlib.h>
#include "ringct/triptych.h"
#include "ringct/rctTypes.h"

using namespace rct;

template<size_t a_N_proofs, size_t a_n, size_t a_m>
class test_triptych
{
    public:
        static const size_t loop_count = 1000;
        static const size_t N_proofs = a_N_proofs;
        static const size_t n = a_n;
        static const size_t m = a_m;

        bool init()
        {
            const size_t N = pow(n,m); // anonymity set size
            p.reserve(N_proofs);
            p.resize(0);
            proofs.reserve(N_proofs);
            proofs.resize(0);

            // Build key vectors
            M_sign = keyV(N);
            M_amount = keyV(N);
            M_lock = keyV(N);
            r_sign = keyV(N_proofs);
            r_amount = keyV(N_proofs);
            r_lock = keyV(N_proofs);
            messages = keyV(N_proofs);
            C_offsets_amount = keyV(N_proofs);
            C_offsets_lock = keyV(N_proofs);

            // Random keys
            key temp;
            for (size_t k = 0; k < N; k++)
            {
                skpkGen(temp,M_sign[k]);
                skpkGen(temp,M_amount[k]);
                skpkGen(temp,M_lock[k]);
            }

            // Signing keys, messages, and commitment offsets
            key s1,s2;
            for (size_t i = 0; i < N_proofs; i++)
            {
                messages[i] = skGen();

                skpkGen(r_sign[i],M_sign[i]);

                skpkGen(s1,M_amount[i]);
                skpkGen(s2,C_offsets_amount[i]);
                sc_sub(r_amount[i].bytes,s1.bytes,s2.bytes);

                skpkGen(s1,M_lock[i]);
                skpkGen(s2,C_offsets_lock[i]);
                sc_sub(r_lock[i].bytes,s1.bytes,s2.bytes);
            }

            // Build proofs
            for (size_t i = 0; i < N_proofs; i++)
            {
                p.push_back(triptych_prove(M_sign,M_amount,M_lock,C_offsets_amount[i],C_offsets_lock[i],i,r_sign[i],r_amount[i],r_lock[i],n,m,messages[i]));
            }
            for (TriptychProof &proof: p)
            {
                proofs.push_back(&proof);
            }

            return true;
        }

        bool test()
        {
            return triptych_verify(M_sign,M_amount,M_lock,C_offsets_amount,C_offsets_lock,proofs,n,m,messages);
        }

    private:
        keyV M_sign;
        keyV M_amount;
        keyV M_lock;
        keyV r_sign;
        keyV r_amount;
        keyV r_lock;
        keyV C_offsets_amount;
        keyV C_offsets_lock;
        keyV messages;
        std::vector<TriptychProof> p;
        std::vector<TriptychProof *> proofs;
};
