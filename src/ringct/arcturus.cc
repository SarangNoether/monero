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
#include <boost/thread/mutex.hpp>
#include <boost/thread/lock_guard.hpp>
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "rctOps.h"
#include "rctTypes.h"
#include "multiexp.h"
#include "arcturus.h"
#include "cryptonote_config.h"
#include "misc_log_ex.h"

namespace rct
{
    // Maximum tensor entries: m*n*w = 64*2*16 = 2048
    static const size_t max_mnw = 2048;

    // Global data
    static std::shared_ptr<pippenger_cached_data> cache;
    static ge_p3 Hi_p3[max_mnw];
    static ge_p3 H_p3;
    static ge_p3 G_p3;
    static key U;
    static ge_p3 U_p3;
    static boost::mutex init_mutex;

    // Useful scalar and group constants
    static const key ZERO = zero();
    static const key ONE = identity();
    static const key IDENTITY = identity(); // group identity
    static const key TWO = { {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };
    static const key MINUS_ONE = { {0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10} };

    // Initialize transcript
    static void transcript_init(key &transcript)
    {
        std::string salt(config::HASH_KEY_ARCTURUS_TRANSCRIPT);
        hash_to_scalar(transcript,salt.data(),salt.size());
    }

    // Update transcript: transcript, message, M, P, Q, J, A, B, C, D
    static void transcript_update_mu(key &transcript, const key &message, const keyV &M, const keyV &P, const keyV &Q, const keyV &J, const key &A, const key &B, const key &C, const key &D)
    {
        CHECK_AND_ASSERT_THROW_MES(M.size() == P.size(), "Transcript challenge inputs have incorrect size!");

        std::string hash;
        hash.reserve((2 + 2*M.size() + Q.size() + J.size() + 4)*sizeof(key));
        hash = std::string((const char*) transcript.bytes, sizeof(transcript));
        hash += std::string((const char*) message.bytes, sizeof(message));
        for (size_t k = 0; k < M.size(); k++)
        {
            hash += std::string((const char*) M[k].bytes, sizeof(M[k]));
            hash += std::string((const char*) P[k].bytes, sizeof(P[k]));
        }
        for (size_t j = 0; j < Q.size(); j++)
        {
            hash += std::string((const char*) Q[j].bytes, sizeof(Q[j]));
        }
        for (size_t u = 0; u < J.size(); u++)
        {
            hash += std::string((const char*) J[u].bytes, sizeof(J[u]));
        }
        hash += std::string((const char*) A.bytes, sizeof(A));
        hash += std::string((const char*) B.bytes, sizeof(B));
        hash += std::string((const char*) C.bytes, sizeof(C));
        hash += std::string((const char*) D.bytes, sizeof(D));
        CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");
        hash_to_scalar(transcript,hash.data(),hash.size());

        CHECK_AND_ASSERT_THROW_MES(!(transcript == ZERO), "Transcript challenge must be nonzero!");
    }

    // Update transcript: transcript, X, Y, Z
    static void transcript_update_x(key &transcript, const keyV &X, const keyV &Y, const keyV &Z)
    {
        CHECK_AND_ASSERT_THROW_MES(X.size() == Y.size(), "Transcript challenge inputs have incorrect size!");
        CHECK_AND_ASSERT_THROW_MES(X.size() == Z.size(), "Transcript challenge inputs have incorrect size!");

        std::string hash;
        hash.reserve((1 + 3*X.size())*sizeof(key));
        hash = std::string((const char*) transcript.bytes, sizeof(transcript));
        for (size_t j = 0; j < X.size(); j++)
        {
            hash += std::string((const char*) X[j].bytes, sizeof(X[j]));
            hash += std::string((const char*) Y[j].bytes, sizeof(Y[j]));
            hash += std::string((const char*) Z[j].bytes, sizeof(Z[j]));
        }
        CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");
        hash_to_scalar(transcript,hash.data(),hash.size());

        CHECK_AND_ASSERT_THROW_MES(!(transcript == ZERO), "Transcript challenge must be nonzero!");
    }

    // Helper function for scalar inversion
    static key sm(key y, int n, const key &x)
    {
        while (n--)
            sc_mul(y.bytes, y.bytes, y.bytes);
        sc_mul(y.bytes, y.bytes, x.bytes);
        return y;
    }

    // Invert a nonzero scalar
    static key invert(const key &x)
    {
        CHECK_AND_ASSERT_THROW_MES(!(x == ZERO), "Cannot invert zero!");

        key _1, _10, _100, _11, _101, _111, _1001, _1011, _1111;

        _1 = x;
        sc_mul(_10.bytes, _1.bytes, _1.bytes);
        sc_mul(_100.bytes, _10.bytes, _10.bytes);
        sc_mul(_11.bytes, _10.bytes, _1.bytes);
        sc_mul(_101.bytes, _10.bytes, _11.bytes);
        sc_mul(_111.bytes, _10.bytes, _101.bytes);
        sc_mul(_1001.bytes, _10.bytes, _111.bytes);
        sc_mul(_1011.bytes, _10.bytes, _1001.bytes);
        sc_mul(_1111.bytes, _100.bytes, _1011.bytes);

        key inv;
        sc_mul(inv.bytes, _1111.bytes, _1.bytes);

        inv = sm(inv, 123 + 3, _101);
        inv = sm(inv, 2 + 2, _11);
        inv = sm(inv, 1 + 4, _1111);
        inv = sm(inv, 1 + 4, _1111);
        inv = sm(inv, 4, _1001);
        inv = sm(inv, 2, _11);
        inv = sm(inv, 1 + 4, _1111);
        inv = sm(inv, 1 + 3, _101);
        inv = sm(inv, 3 + 3, _101);
        inv = sm(inv, 3, _111);
        inv = sm(inv, 1 + 4, _1111);
        inv = sm(inv, 2 + 3, _111);
        inv = sm(inv, 2 + 2, _11);
        inv = sm(inv, 1 + 4, _1011);
        inv = sm(inv, 2 + 4, _1011);
        inv = sm(inv, 6 + 4, _1001);
        inv = sm(inv, 2 + 2, _11);
        inv = sm(inv, 3 + 2, _11);
        inv = sm(inv, 3 + 2, _11);
        inv = sm(inv, 1 + 4, _1001);
        inv = sm(inv, 1 + 3, _111);
        inv = sm(inv, 2 + 4, _1111);
        inv = sm(inv, 1 + 4, _1011);
        inv = sm(inv, 3, _101);
        inv = sm(inv, 2 + 4, _1111);
        inv = sm(inv, 3, _101);
        inv = sm(inv, 1 + 2, _11);

        // Confirm inversion
        key temp;
        sc_mul(temp.bytes,x.bytes,inv.bytes);
        CHECK_AND_ASSERT_THROW_MES(temp == ONE, "Scalar inversion failed!");

        return inv;
    }

    // Invert a tensor
    static keyT invert(keyT x)
    {
        keyT scratch = keyTInit(x[0][0].size(),x[0].size(),x.size());
        key acc = identity();
        for (size_t k = 0; k < x.size(); k++)
        {
            for (size_t j = 0; j < x[0].size(); j++)
            {
                for (size_t i = 0; i < x[0][0].size(); i++)
                {
                    copy(scratch[k][j][i],acc);
                    if (k == 0 && j == 0 && i == 0)
                    {
                        acc = x[0][0][0];
                    }
                    else
                    {
                        sc_mul(acc.bytes,acc.bytes,x[k][j][i].bytes);
                    }
                }
            }
        }

        acc = invert(acc);

        key temp;
        for (size_t k = x.size(); k-- > 0; )
        {
            for (size_t j = x[0].size(); j-- > 0; )
            {
                for (size_t i = x[0][0].size(); i-- > 0; )
                {
                    sc_mul(temp.bytes, acc.bytes, x[k][j][i].bytes);
                    sc_mul(x[k][j][i].bytes, acc.bytes, scratch[k][j][i].bytes);
                    acc = temp;
                }
            }
        }

        return x;
    }

    // Make generators, but only once
    static void init_gens()
    {
        boost::lock_guard<boost::mutex> lock(init_mutex);
        static const std::string H_salt(config::HASH_KEY_ARCTURUS_H);

        static bool init_done = false;
        if (init_done) return;

        // Build Hi generators
        std::vector<MultiexpData> data;
        data.reserve(max_mnw);
        for (size_t i = 0; i < max_mnw; i++)
        {
            std::string hash = H_salt + tools::get_varint_data(i);
            hash_to_p3(Hi_p3[i], hash2rct(crypto::cn_fast_hash(hash.data(),hash.size())));
            data.push_back({ZERO,Hi_p3[i]});
        }
        CHECK_AND_ASSERT_THROW_MES(data.size() == max_mnw, "Bad generator vector size!");
        cache = pippenger_init_cache(data,0,0);

        // Build U
        // U = keccak("arcturus U")
        static const std::string U_salt(config::HASH_KEY_ARCTURUS_U);
        hash_to_p3(U_p3, hash2rct(crypto::cn_fast_hash(U_salt.data(),U_salt.size())));
        ge_p3_tobytes(U.bytes, &U_p3);

        // Build G,H
        ge_frombytes_vartime(&G_p3, G.bytes);
        ge_frombytes_vartime(&H_p3, H.bytes);

        init_done = true;
    }

    // Data for iterated Gray codes
    static size_t gray_counter; // about to be generated
    static std::vector<int> gray_g;
    static std::vector<int> gray_u;
    static size_t gray_index;
    static int gray_old;
    static int gray_new;
    static int gray_N;
    static int gray_K;

    // Prepare for a new Gray iteration cycle
    static void gray_init()
    {
        gray_counter = 0;
        gray_g.resize(0);
        gray_u.resize(0);
        for (int i = 0; i < gray_K+1; i++)
        {
            gray_g.push_back(0);
            gray_u.push_back(1);
        }
        gray_index = 0;
        gray_old = 0;
        gray_new = 0;
    }

    // Generate change data for the next Gray code
    static void gray_next()
    {
        // Zero data is done
        if (gray_counter == 0)
        {
            gray_counter++;
            return;
        }

        size_t i = 0;
        int k = gray_g[0] + gray_u[0];
        while (k >= gray_N || k < 0)
        {
            gray_u[i] = -gray_u[i];
            i++;
            k = gray_g[i] + gray_u[i];
        }
        gray_index = i;
        gray_old = gray_g[i];
        gray_new = k;
        gray_g[i] = k;
        gray_counter++;
    }

    // Commit: vH + rG
    static key com(const key &v, const key &r)
    {
        key temp;
        addKeys2(temp,r,v,H);
        return temp;
    }

    // Commit to a scalar tensor
    static void com_tensor(std::vector<MultiexpData> &data, const keyT &T, const key &r)
    {
        const size_t w = T.size();
        const size_t m = T[0].size();
        const size_t n = T[0][0].size();
        CHECK_AND_ASSERT_THROW_MES(m*n*w <= max_mnw, "Bad matrix commitment parameters!");
        CHECK_AND_ASSERT_THROW_MES(data.size() >= m*n*w + 1, "Bad matrix commitment result vector size!");

        for (size_t j = 0; j < m; j++)
        {
            for (size_t i = 0; i < n; i++)
            {
                for (size_t u = 0; u < w; u++)
                {
                    data[(j*n + i)*w + u] = {T[u][j][i], Hi_p3[(j*n + i)*w + u]};
                }
            }
        }
        data[m*n*w] = {r, H_p3}; // mask
    }

    // Kronecker delta
    static key delta(const size_t x, const size_t y)
    {
        if (x == y)
            return ONE;
        else
            return ZERO;
    }

    // Compute a convolution with a degree-one polynomial
    static keyV convolve(const keyV &x, const keyV &y, const size_t m)
    {
        CHECK_AND_ASSERT_THROW_MES(x.size() >= m, "Bad convolution parameters!");
        CHECK_AND_ASSERT_THROW_MES(y.size() == 2, "Bad convolution parameters!");

        key temp;
        keyV r;
        r.reserve(m+1);
        r.resize(m+1);

        for (size_t i = 0; i < m+1; i++)
        {
            r[i] = ZERO;
        }

        for (size_t i = 0; i < m; i++)
        {
            for (size_t j = 0; j < 2; j++)
            {
                sc_mul(temp.bytes,x[i].bytes,y[j].bytes);
                sc_add(r[i+j].bytes,r[i+j].bytes,temp.bytes);
            }
        }

        return r;
    }

    // Generate an Arcturus proof
    ArcturusProof arcturus_prove(const keyV &M, const keyV &P, const keyV &Q, const std::vector<size_t> &l, const keyV &r, const keyV &s, const keyV &t, const keyV &val_a, const keyV &val_b, const size_t n, const size_t m, const key &message)
    {
        key temp,temp2; // for ephemeral use as needed

        CHECK_AND_ASSERT_THROW_MES(n > 1, "Must have n > 1!");
        CHECK_AND_ASSERT_THROW_MES(m > 1, "Must have m > 1!");

        const size_t N = pow(n,m); // anonymity set size
        const size_t w = l.size(); // number of signing indices
        const size_t T = Q.size(); // number of new outputs

        CHECK_AND_ASSERT_THROW_MES(m*n*w <= max_mnw, "Size parameters are too large!");
        CHECK_AND_ASSERT_THROW_MES(M.size() == N, "Signing vector is wrong size!");
        CHECK_AND_ASSERT_THROW_MES(P.size() == N, "Commitment vector is wrong size!");
        CHECK_AND_ASSERT_THROW_MES(r.size() == w, "Signing mask vector is wrong size!");
        CHECK_AND_ASSERT_THROW_MES(s.size() == w, "Commitment mask vector is wrong size!");
        CHECK_AND_ASSERT_THROW_MES(t.size() == T, "Output mask vector is wrong size!");
        CHECK_AND_ASSERT_THROW_MES(val_a.size() == w, "Commitment value vector is wrong size!");
        CHECK_AND_ASSERT_THROW_MES(val_b.size() == T, "Output value vector is wrong size!");

        // Reconstruct known commitments
        for (size_t u = 0; u < w; u++)
        {
            CHECK_AND_ASSERT_THROW_MES(l[u] < N, "Signing index out of bounds!");
            CHECK_AND_ASSERT_THROW_MES(scalarmultBase(r[u]) == M[l[u]], "Bad signing key!");
            CHECK_AND_ASSERT_THROW_MES(com(val_a[l[u]],s[l[u]]) == P[l[u]], "Bad commitment key!");
        }
        for (size_t j = 0; j < T; j++)
        {
            CHECK_AND_ASSERT_THROW_MES(com(val_b[j],t[j]) == Q[j], "Bad output key!");
        }

        init_gens();
        gray_N = n;
        gray_K = m;
        gray_init();

        ArcturusProof proof;
        std::vector<MultiexpData> data;
        data.reserve(m*n*w + 1);
        data.resize(m*n*w + 1);

        // Begin transcript
        key tr;
        transcript_init(tr);

        // Compute key images
        // J[u] = (1/r[u])*U
        proof.J = keyV(w);
        for (size_t u = 0; u < w; u++)
        {
            proof.J[u] = scalarmultKey(U,invert(r[u]));
        }

        // Matrix masks
        key rA = skGen();
        key rB = skGen();
        key rC = skGen();
        key rD = skGen();

        // Commit to zero-sum values
        keyT a = keyTInit(n,m,w);
        CHECK_AND_ASSERT_THROW_MES(a.size() == w, "Bad matrix size!");
        CHECK_AND_ASSERT_THROW_MES(a[0].size() == m, "Bad matrix size!");
        CHECK_AND_ASSERT_THROW_MES(a[0][0].size() == n, "Bad matrix size!");
        for (size_t j = 0; j < m; j++)
        {
            for (size_t u = 0; u < w; u++)
            {
                a[u][j][0] = ZERO;
                for (size_t i = 1; i < n; i++)
                {
                    a[u][j][i] = skGen();
                    sc_sub(a[u][j][0].bytes,a[u][j][0].bytes,a[u][j][i].bytes);
                }
            }
        }
        com_tensor(data,a,rA);
        CHECK_AND_ASSERT_THROW_MES(data.size() == m*n*w + 1, "Matrix commitment returned unexpected size!");
        proof.A = straus(data);
        CHECK_AND_ASSERT_THROW_MES(!(proof.A == IDENTITY), "Linear combination unexpectedly returned zero!");

        // Commit to decomposition bits
        std::vector<std::vector<size_t>> decomp_l;
        decomp_l.reserve(w);
        decomp_l.resize(w);
        for (size_t u = 0; u < w; u++)
        {
            decomp_l[u].reserve(m);
            decomp_l[u].resize(m);
            gray_init();
            for (size_t j = 0; j < m; j++)
            {
                decomp_l[u][j] = 0;
            }
            while (gray_counter <= l[u])
            {
                gray_next();
                decomp_l[u][gray_index] = gray_new;
            }
        }

        keyT sigma = keyTInit(n,m,w);
        CHECK_AND_ASSERT_THROW_MES(sigma.size() == w, "Bad matrix size!");
        CHECK_AND_ASSERT_THROW_MES(sigma[0].size() == m, "Bad matrix size!");
        CHECK_AND_ASSERT_THROW_MES(sigma[0][0].size() == n, "Bad matrix size!");
        for (size_t j = 0; j < m; j++)
        {
            for (size_t i = 0; i < n; i++)
            {
                for (size_t u = 0; u < w; u++)
                {
                    sigma[u][j][i] = delta(decomp_l[u][j],i);
                }
            }
        }
        com_tensor(data,sigma,rB);
        CHECK_AND_ASSERT_THROW_MES(data.size() == m*n*w + 1, "Matrix commitment returned unexpected size!");
        proof.B = straus(data);
        CHECK_AND_ASSERT_THROW_MES(!(proof.B == IDENTITY), "Linear combination unexpectedly returned zero!");

        // Commit to a/sigma relationships
        keyT a_sigma = keyTInit(n,m,w);
        CHECK_AND_ASSERT_THROW_MES(a_sigma.size() == w, "Bad matrix size!");
        CHECK_AND_ASSERT_THROW_MES(a_sigma[0].size() == m, "Bad matrix size!");
        CHECK_AND_ASSERT_THROW_MES(a_sigma[0][0].size() == n, "Bad matrix size!");
        for (size_t j = 0; j < m; j++)
        {
            for (size_t i = 0; i < n; i++)
            {
                for (size_t u = 0; u < w; u++)
                {
                    // a_sigma[u][j][i] = a[u][j][i]*(ONE - TWO*sigma[u][j][i])
                    sc_mulsub(a_sigma[u][j][i].bytes, TWO.bytes, sigma[u][j][i].bytes, ONE.bytes);
                    sc_mul(a_sigma[u][j][i].bytes, a_sigma[u][j][i].bytes, a[u][j][i].bytes);
                }
            }
        }
        com_tensor(data,a_sigma,rC);
        CHECK_AND_ASSERT_THROW_MES(data.size() == w*m*n + 1, "Matrix commitment returned unexpected size!");
        proof.C = straus(data);
        CHECK_AND_ASSERT_THROW_MES(!(proof.C == IDENTITY), "Linear combination unexpectedly returned zero!");

        // Commit to squared a-values
        keyT a_sq = keyTInit(n,m,w);
        CHECK_AND_ASSERT_THROW_MES(a_sq.size() == w, "Bad matrix size!");
        CHECK_AND_ASSERT_THROW_MES(a_sq[0].size() == m, "Bad matrix size!");
        CHECK_AND_ASSERT_THROW_MES(a_sq[0][0].size() == n, "Bad matrix size!");
        for (size_t j = 0; j < m; j++)
        {
            for (size_t i = 0; i < n; i++)
            {
                for (size_t u = 0; u < w; u++)
                {
                    sc_mul(a_sq[u][j][i].bytes,a[u][j][i].bytes,a[u][j][i].bytes);
                    sc_mul(a_sq[u][j][i].bytes,MINUS_ONE.bytes,a_sq[u][j][i].bytes);
                }
            }
        }
        com_tensor(data,a_sq,rD);
        CHECK_AND_ASSERT_THROW_MES(data.size() == m*n*w + 1, "Matrix commitment returned unexpected size!");
        proof.D = straus(data);
        CHECK_AND_ASSERT_THROW_MES(!(proof.D == IDENTITY), "Linear combination unexpectedly returned zero!");

        // Compute p coefficients
        gray_N = n;
        gray_K = m;
        gray_init();
        keyT p = keyTInit(m+1,N,w);
        CHECK_AND_ASSERT_THROW_MES(p.size() == w, "Bad matrix size!");
        CHECK_AND_ASSERT_THROW_MES(p[0].size() == N, "Bad matrix size!");
        CHECK_AND_ASSERT_THROW_MES(p[0][0].size() == m+1, "Bad matrix size!");
        std::vector<size_t> decomp_k;
        decomp_k.reserve(m);
        decomp_k.resize(m);
        for (size_t j = 0; j < m; j++)
        {
            decomp_k[j] = 0;
        }
        for (size_t k = 0; k < N; k++)
        {
            gray_next();
            decomp_k[gray_index] = gray_new;

            for (size_t u = 0; u < w; u++)
            {
                for (size_t j = 0; j < m+1; j++)
                {
                    p[u][k][j] = ZERO;
                }
                p[u][k][0] = a[u][0][decomp_k[0]];
                p[u][k][1] = delta(decomp_l[u][0],decomp_k[0]);
            }

            for (size_t j = 1; j < m; j++)
            {
                for (size_t u = 0; u < w; u++)
                {
                    keyV temp;
                    temp.reserve(2);
                    temp.resize(2);
                    temp[0] = a[u][j][decomp_k[j]];
                    temp[1] = delta(decomp_l[u][j],decomp_k[j]);

                    p[u][k] = convolve(p[u][k],temp,m);
                }
            }

            // Combine coefficients in p[0]
            for (size_t j = 0; j < m; j++)
            {
                for (size_t u = 1; u < w; u++)
                {
                    sc_add(p[0][k][j].bytes,p[0][k][j].bytes,p[u][k][j].bytes);
                }
            }
        }

        // Generate initial proof values
        proof.X = keyV(m);
        proof.Y = keyV(m);
        proof.Z = keyV(m);

        keyM rho_R = keyMInit(m,w);
        keyM rho_S = keyMInit(m,w);
        for (size_t j = 0; j < m; j++)
        {
            for (size_t u = 0; u < w; u++)
            {
                rho_R[u][j] = skGen();
                rho_S[u][j] = skGen();
            }
        }

        // Challenge
        proof.A = scalarmultKey(proof.A,INV_EIGHT);
        proof.B = scalarmultKey(proof.B,INV_EIGHT);
        proof.C = scalarmultKey(proof.C,INV_EIGHT);
        proof.D = scalarmultKey(proof.D,INV_EIGHT);
        transcript_update_mu(tr,message,M,P,Q,proof.J,proof.A,proof.B,proof.C,proof.D);

        const key mu = copy(tr);
        keyV mu_powers = keyV(N);
        mu_powers[0] = ONE;
        for (size_t k = 1; k < N; k++)
        {
            sc_mul(mu_powers[k].bytes,mu_powers[k-1].bytes,mu.bytes);
        }

        key U_scalars;
        key X_scalars;
        key Z_scalars;
        for (size_t j = 0; j < m; j++)
        {
            std::vector<MultiexpData> data_X;
            std::vector<MultiexpData> data_Y;
            std::vector<MultiexpData> data_Z;
            data_X.reserve(N + 1);
            data_X.resize(0);
            data_Y.reserve(1 + w);
            data_Y.resize(0);
            data_Z.reserve(N + 1);
            data_Z.resize(0);

            U_scalars = ZERO;
            X_scalars = ZERO;
            Z_scalars = ZERO;

            for (size_t k = 0; k < N; k++)
            {
                // X[j] += mu**k*p[0][k][j]*M[k]
                // Y[j] += mu**k*p[0][k][j]*U
                // Z[j] += p[0][k][j]*P[k]
                sc_mul(temp.bytes,mu_powers[k].bytes,p[0][k][j].bytes);
                data_X.push_back({temp,M[k]});

                sc_add(U_scalars.bytes,U_scalars.bytes,temp.bytes);

                data_Z.push_back({p[0][k][j],P[k]});
            }
            data_Y.push_back({U_scalars,U_p3});
            for (size_t u = 0; u < w; u++)
            {
                // X[j] += rho_R[u][j]*G
                // Y[j] += rho_R[u][j]*J[u]
                // Z[j] += rho_S[u][j]*G
                sc_add(X_scalars.bytes,X_scalars.bytes,rho_R[u][j].bytes);

                data_Y.push_back({rho_R[u][j],proof.J[u]});

                sc_add(Z_scalars.bytes,Z_scalars.bytes,rho_S[u][j].bytes);
            }
            data_X.push_back({X_scalars,G_p3});
            data_Z.push_back({Z_scalars,G_p3});

            proof.X[j] = straus(data_X);
            proof.Y[j] = straus(data_Y);
            proof.Z[j] = straus(data_Z);
        }

        // Challenge
        for (size_t j = 0; j < m; j++)
        {
            proof.X[j] = scalarmultKey(proof.X[j],INV_EIGHT);
            proof.Y[j] = scalarmultKey(proof.Y[j],INV_EIGHT);
            proof.Z[j] = scalarmultKey(proof.Z[j],INV_EIGHT);
        }
        CHECK_AND_ASSERT_THROW_MES(proof.X.size() == m, "Proof coefficient vector is unexpected size!");
        CHECK_AND_ASSERT_THROW_MES(proof.Y.size() == m, "Proof coefficient vector is unexpected size!");
        CHECK_AND_ASSERT_THROW_MES(proof.Z.size() == m, "Proof coefficient vector is unexpected size!");
        transcript_update_x(tr,proof.X,proof.Y,proof.Z);
        const key x = copy(tr);

        // Challenge powers
        keyV x_pow;
        x_pow.reserve(m+1);
        x_pow.resize(m+1);
        x_pow[0] = ONE;
        for (size_t j = 1; j < m+1; j++)
        {
            sc_mul(x_pow[j].bytes,x_pow[j-1].bytes,x.bytes);
        }

        // Build the f-matrix
        proof.f = keyTInit(n-1,m,w);
        for (size_t j = 0; j < m; j++)
        {
            for (size_t i = 1; i < n; i++)
            {
                for (size_t u = 0; u < w; u++)
                {
                    sc_muladd(proof.f[u][j][i-1].bytes,sigma[u][j][i].bytes,x.bytes,a[u][j][i].bytes);
                    CHECK_AND_ASSERT_THROW_MES(!(proof.f[u][j][i-1] == ZERO), "Proof matrix element should not be zero!");
                }
            }
        }

        // Build the z-terms
        // zA = rB*x + rA
        // zC = rC*x + rD
        sc_muladd(proof.zA.bytes,rB.bytes,x.bytes,rA.bytes);
        CHECK_AND_ASSERT_THROW_MES(!(proof.zA == ZERO), "Proof scalar element should not be zero!");

        sc_muladd(proof.zC.bytes,rC.bytes,x.bytes,rD.bytes);
        CHECK_AND_ASSERT_THROW_MES(!(proof.zC == ZERO), "Proof scalar element should not be zero!");

        proof.zR = keyV(w);
        proof.zS = ZERO;
        for (size_t u = 0; u < w; u++)
        {
            sc_mul(proof.zR[u].bytes,mu_powers[l[u]].bytes,r[u].bytes);
            sc_mul(proof.zR[u].bytes,proof.zR[u].bytes,x_pow[m].bytes);

            sc_muladd(proof.zS.bytes,s[u].bytes,x_pow[m].bytes,proof.zS.bytes);
        }

        for (size_t j = 0; j < m; j++)
        {
            for (size_t u = 0; u < w; u++)
            {
                sc_mulsub(proof.zR[u].bytes,rho_R[u][j].bytes,x_pow[j].bytes,proof.zR[u].bytes);

                sc_mulsub(proof.zS.bytes,rho_S[u][j].bytes,x_pow[j].bytes,proof.zS.bytes);
            }
        }

        for (size_t j = 0; j < T; j++)
        {
            sc_mulsub(proof.zS.bytes,t[j].bytes,x_pow[m].bytes,proof.zS.bytes);
        }

        return proof;
    }

    // Verify an Arcturus proof
    bool arcturus_verify(const keyV &M, const keyV &P, const keyV &Q, ArcturusProof &proof, const size_t n, const size_t m, const key &message)
    {
        CHECK_AND_ASSERT_THROW_MES(n > 1, "Must have n > 1!");
        CHECK_AND_ASSERT_THROW_MES(m > 1, "Must have m > 1!");

        const size_t N = pow(n,m); // anonymity set size
        const size_t w = proof.J.size(); // number of signing indices
        const size_t T = Q.size(); // number of new outputs

        CHECK_AND_ASSERT_THROW_MES(m*n*w <= max_mnw, "Size parameters are too large!");
        CHECK_AND_ASSERT_THROW_MES(M.size() == N, "Signing vector is wrong size!");
        CHECK_AND_ASSERT_THROW_MES(P.size() == N, "Commitment vector is wrong size!");

        for (size_t u = 0; u < w; u++)
        {
            CHECK_AND_ASSERT_THROW_MES(!(proof.J[u] == IDENTITY), "Linking tag should not be zero!");
            CHECK_AND_ASSERT_THROW_MES(sc_check(proof.zR[u].bytes) == 0, "Bad scalar element in proof!");
            CHECK_AND_ASSERT_THROW_MES(!(proof.zR[u] == ZERO), "Proof scalar should not be zero!");
        }

        CHECK_AND_ASSERT_THROW_MES(proof.X.size() == m, "Bad proof vector size!");
        CHECK_AND_ASSERT_THROW_MES(proof.Y.size() == m, "Bad proof vector size!");
        CHECK_AND_ASSERT_THROW_MES(proof.Z.size() == m, "Bad proof vector size!");

        CHECK_AND_ASSERT_THROW_MES(proof.f.size() == w, "Bad proof matrix size!");
        for (size_t u = 0; u < w; u++)
        {
            CHECK_AND_ASSERT_THROW_MES(proof.f[u].size() == m, "Bad proof matrix size!");
            for (size_t j = 0; j < m; j++)
            {
                CHECK_AND_ASSERT_THROW_MES(proof.f[u][j].size() == n-1, "Bad proof matrix size!");
                for (size_t i = 0; i < n-1; i++)
                {
                    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.f[u][j][i].bytes) == 0, "Bad scalar element in proof!");
                }
            }
        }

        CHECK_AND_ASSERT_THROW_MES(sc_check(proof.zA.bytes) == 0, "Bad scalar element in proof!");
        CHECK_AND_ASSERT_THROW_MES(!(proof.zA == ZERO), "Proof scalar element should not be zero!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(proof.zC.bytes) == 0, "Bad scalar element in proof!");
        CHECK_AND_ASSERT_THROW_MES(!(proof.zC == ZERO), "Proof scalar element should not be zero!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(proof.zS.bytes) == 0, "Bad scalar element in proof!");
        CHECK_AND_ASSERT_THROW_MES(!(proof.zS == ZERO), "Proof scalar element should not be zero!");

        init_gens();
        key temp;

        // Holds final check data
        std::vector<MultiexpData> data;
        data.reserve(m*n*w + 2*N + T + 3*m + w + 6);
        data.resize(m*n*w + 1); // {Hi},H

        // Per-equation random weights
        key w1 = ZERO; // A/B/C/D-check
        key w2 = ZERO; // A/B/C/D-check
        key w3 = ZERO; // X-check
        key w4 = ZERO; // Y-check
        key w5 = ZERO; // Z-check
        while (w1 == ZERO || w2 == ZERO || w3 == ZERO || w4 == ZERO || w5 == ZERO)
        {
            w1 = skGen();
            w2 = skGen();
            w3 = skGen();
            w4 = skGen();
            w5 = skGen();
        }

        // Transcript
        key tr;
        transcript_init(tr);
        transcript_update_mu(tr,message,M,P,Q,proof.J,proof.A,proof.B,proof.C,proof.D);

        const key mu = copy(tr);
        keyV mu_powers = keyV(N);
        mu_powers[0] = ONE;
        for (size_t k = 1; k < N; k++)
        {
            sc_mul(mu_powers[k].bytes,mu_powers[k-1].bytes,mu.bytes);
        }

        transcript_update_x(tr,proof.X,proof.Y,proof.Z);
        const key x = copy(tr);

        keyV minus_x;
        minus_x.reserve(m+1);
        minus_x.resize(m+1);
        minus_x[0] = MINUS_ONE;
        for (size_t j = 1; j < m+1; j++)
        {
            sc_mul(minus_x[j].bytes,minus_x[j-1].bytes,x.bytes);
        }

        // Recover proof elements
        ge_p3 A_p3;
        ge_p3 B_p3;
        ge_p3 C_p3;
        ge_p3 D_p3;
        std::vector<ge_p3> X_p3;
        std::vector<ge_p3> Y_p3;
        std::vector<ge_p3> Z_p3;
        X_p3.reserve(m);
        X_p3.resize(m);
        Y_p3.reserve(m);
        Y_p3.resize(m);
        Z_p3.reserve(m);
        Z_p3.resize(m);
        scalarmult8(A_p3,proof.A);
        scalarmult8(B_p3,proof.B);
        scalarmult8(C_p3,proof.C);
        scalarmult8(D_p3,proof.D);
        for (size_t j = 0; j < m; j++)
        {
            scalarmult8(X_p3[j],proof.X[j]);
            scalarmult8(Y_p3[j],proof.Y[j]);
            scalarmult8(Z_p3[j],proof.Z[j]);
        }

        // Reconstruct the f-matrix
        keyT f = keyTInit(n,m,w);
        for (size_t j = 0; j < m; j++)
        {
            for (size_t u = 0; u < w; u++)
            {
                f[u][j][0] = x;
            }
            for (size_t i = 1; i < n; i++)
            {
                for (size_t u = 0; u < w; u++)
                {
                    CHECK_AND_ASSERT_THROW_MES(!(proof.f[u][j][i-1] == ZERO), "Proof matrix element should not be zero!");
                    f[u][j][i] = proof.f[u][j][i-1];
                    sc_sub(f[u][j][0].bytes,f[u][j][0].bytes,f[u][j][i].bytes);
                }
            }
        }

        // Invert the f-tensor
        keyT f_invert = invert(f);

        // Matrix generators
        for (size_t j = 0; j < m; j++)
        {
            for (size_t i = 0; i < n; i++)
            {
                for (size_t u = 0; u < w; u++)
                {
                    // Hi: w1*f + w2*f*(x-f) = w1*f + w2*f*x - w2*f*f
                    key Hi_scalar;
                    sc_mul(Hi_scalar.bytes,w1.bytes,f[u][j][i].bytes);

                    sc_mul(temp.bytes,w2.bytes,f[u][j][i].bytes);
                    sc_mul(temp.bytes,temp.bytes,x.bytes);
                    sc_add(Hi_scalar.bytes,Hi_scalar.bytes,temp.bytes);

                    sc_mul(temp.bytes,MINUS_ONE.bytes,w2.bytes);
                    sc_mul(temp.bytes,temp.bytes,f[u][j][i].bytes);
                    sc_mul(temp.bytes,temp.bytes,f[u][j][i].bytes);
                    sc_add(data[(j*n + i)*w + u].scalar.bytes,Hi_scalar.bytes,temp.bytes);

                    data[(j*n + i)*w + u].point = Hi_p3[(j*n + i)*w + u];
                }
            }
        }

        // H: w1*zA + w2*zC
        data[m*n*w].scalar = ZERO;
        data[m*n*w].point = H_p3;
        sc_muladd(data[m*n*w].scalar.bytes,w1.bytes,proof.zA.bytes,data[m*n*w].scalar.bytes);
        sc_muladd(data[m*n*w].scalar.bytes,w2.bytes,proof.zC.bytes,data[m*n*w].scalar.bytes);

        // A,B,C,D
        // A: -w1
        // B: -w1*x
        // C: -w2*x
        // D: -w2
        sc_mul(temp.bytes,MINUS_ONE.bytes,w1.bytes);
        data.push_back({temp,A_p3});

        sc_mul(temp.bytes,temp.bytes,x.bytes);
        data.push_back({temp,B_p3});

        sc_mul(temp.bytes,MINUS_ONE.bytes,w2.bytes);
        data.push_back({temp,D_p3});

        sc_mul(temp.bytes,temp.bytes,x.bytes);
        data.push_back({temp,C_p3});

        // M,P
        // M[k]: w3*t*mu**k
        // P[k]: w4*t
        // U:    w5*t*mu**k
        key U_scalars = ZERO;
        keyV t = keyV(w);
        key sum_t;
        gray_N = n;
        gray_K = m;
        gray_init();
        for (size_t u = 0; u < w; u++)
        {
            t[u] = ONE;
            for (size_t j = 0; j < m; j++)
            {
                sc_mul(t[u].bytes,t[u].bytes,f[u][j][0].bytes);
            }
        }
        for (size_t k = 0; k < N; k++)
        {
            gray_next();
            if (k > 0)
            {
                for (size_t u = 0; u < w; u++)
                {
                    sc_mul(t[u].bytes,t[u].bytes,f_invert[u][gray_index][gray_old].bytes);
                    sc_mul(t[u].bytes,t[u].bytes,f[u][gray_index][gray_new].bytes);
                }
            }
            sum_t = ZERO;
            for (size_t u = 0; u < w; u++)
            {
                sc_add(sum_t.bytes,sum_t.bytes,t[u].bytes);
            }

            sc_mul(temp.bytes,w3.bytes,sum_t.bytes);
            sc_mul(temp.bytes,temp.bytes,mu_powers[k].bytes);
            data.push_back({temp,M[k]});

            sc_mul(temp.bytes,w5.bytes,sum_t.bytes);
            data.push_back({temp,P[k]});

            sc_mul(temp.bytes,w4.bytes,sum_t.bytes);
            sc_mul(temp.bytes,temp.bytes,mu_powers[k].bytes);
            sc_add(U_scalars.bytes,U_scalars.bytes,temp.bytes);
        }
        data.push_back({U_scalars,U_p3});

        for (size_t j = 0; j < m; j++)
        {
            // X[j]: -w3*x**j
            sc_mul(temp.bytes,w3.bytes,minus_x[j].bytes);
            data.push_back({temp,X_p3[j]});

            // Y[j]: -w4*x**j
            sc_mul(temp.bytes,w4.bytes,minus_x[j].bytes);
            data.push_back({temp,Y_p3[j]});

            // Z[j]: -w5*x**j
            sc_mul(temp.bytes,w5.bytes,minus_x[j].bytes);
            data.push_back({temp,Z_p3[j]});
        }

        // Q[j]: -w5*x**m
        sc_mul(temp.bytes,w5.bytes,minus_x[m].bytes);
        for (size_t j = 0; j < T; j++)
        {
            data.push_back({temp,Q[j]});
        }

        // G: -[w3*(zR[0]+...) + w5*zS]
        temp = ZERO;
        for (size_t u = 0; u < w; u++)
        {
            sc_add(temp.bytes,temp.bytes,proof.zR[u].bytes);
        }
        sc_mul(temp.bytes,temp.bytes,w3.bytes);
        sc_muladd(temp.bytes,w5.bytes,proof.zS.bytes,temp.bytes);
        sc_mul(temp.bytes,temp.bytes,MINUS_ONE.bytes);
        data.push_back({temp,G_p3});

        // J[u]: -w4*zR[u]
        for (size_t u = 0; u < w; u++)
        {
            sc_mul(temp.bytes,MINUS_ONE.bytes,w4.bytes);
            sc_mul(temp.bytes,temp.bytes,proof.zR[u].bytes);
            data.push_back({temp,proof.J[u]});
        }

        // Final check
        // (Hi), H, (M,P), (Q), (J), (X,Y,Z), U, G, A, B, C, D
        CHECK_AND_ASSERT_THROW_MES(data.size() == m*n*w + 1 + 2*N + T + w + 3*m + 6, "Final proof data is incorrect size!");
        if (!(pippenger(data,cache,m*n*w,get_pippenger_c(data.size())) == IDENTITY))
        {
            MERROR("Arcturus verification failed!");
            return false;
        }

        return true;
    }
}
