// Copyright (c) 2017-2020, The Monero Project
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
#include "gtest/gtest.h"
#include "ringct/rctOps.h"
#include "ringct/arcturus.h"

using namespace rct;

// Test random proofs
//
// Values are random scalars without range checks
TEST(arcturus, random)
{
    const size_t m_max = 6;
    const size_t n = 2; // size base: N = n**2,...,n**m_max
    const size_t T = 2; // number of outputs
    const size_t w = 2; // number of signing indices

    // Ring sizes: N = n**m
    for (size_t m = 2; m <= m_max; m++)
    {
        const size_t N = pow(n,m); // anonymity set size
        ArcturusProof proof;

        // Key vectors
        keyV M = keyV(N); // M[l[u]] = Com(0,r[u])
        keyV r = keyV(w);

        keyV P = keyV(N); // P[l[u]] = Com(a[u],s[u])
        keyV a = keyV(w);
        keyV s = keyV(w);

        std::vector<size_t> l; // signing indices
        l.reserve(w);
        l.resize(w);

        keyV Q = keyV(T); // Q[j] = Com(b[j],t[j])
        keyV b = keyV(T);
        keyV t = keyV(T);

        // Random keys
        key temp;
        for (size_t k = 0; k < N; k++)
        {
            skpkGen(temp,M[k]);
            skpkGen(temp,P[k]);
        }

        // Signing and commitment keys (assumes fixed signing indices 0,1,...,w for this test)
        // TODO: random signing indices
        key a_sum = zero();
        for (size_t u = 0; u < w; u++)
        {
            skpkGen(r[u],M[u]); // M[u] = Com(0,r[u])
            
            a[u] = skGen(); // P[u] = Com(a[u],s[u])
            s[u] = skGen();
            addKeys2(P[u],s[u],a[u],H);

            sc_add(a_sum.bytes,a_sum.bytes,a[u].bytes);

            l[u] = u;
        }

        // Outputs
        key b_sum = zero();
        for (size_t j = 0; j < T-1; j++)
        {
            b[j] = skGen(); // Q[j] = Com(b[j],t[j])A
            t[j] = skGen();
            addKeys2(Q[j],t[j],b[j],H);

            sc_add(b_sum.bytes,b_sum.bytes,b[j].bytes);
        }
        // Value balance for Q[T-1]
        sc_sub(b[T-1].bytes,a_sum.bytes,b_sum.bytes);
        t[T-1] = skGen();
        addKeys2(Q[T-1],t[T-1],b[T-1],H);

        key message = skGen(); // random message

        // Build proof
        proof = arcturus_prove(M,P,Q,l,r,s,t,a,b,n,m,message);

        // Verify proof
        ASSERT_TRUE(arcturus_verify(M,P,Q,proof,n,m,message));
    }
}
