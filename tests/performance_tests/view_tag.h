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

#pragma once

#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"

#include "single_tx_test_base.h"

using namespace crypto;

// use_tag: whether to enable view tag checking
// is_owned: if tags are enabled, whether the output is owned by us
template<bool use_tag, bool is_owned>
class test_view_tag : public single_tx_test_base
{
    public:
        static const size_t loop_count = 1000;

        bool init()
        {
            size_t t = 1;
            ec_scalar d;
            ec_scalar tag_full;

            if (!single_tx_test_base::init())
                return false;

            // Compute the view tag
            generate_key_derivation(m_tx_pub_key, m_bob.get_keys().m_view_secret_key, m_key_derivation);
            derivation_to_scalar(m_key_derivation, t, d);
            struct {
                char salt;
                ec_scalar payload;
            } buffer;
            buffer.salt = 0xEC; // arbitrary for this test
            buffer.payload = d;
            hash_to_scalar(&buffer, sizeof(char) + sizeof(ec_scalar), tag_full);
            memcpy(&tag, &tag_full, sizeof(char));

            // Compute the output key
            ge_p3 spend_p3;
            ge_p3 temp_p3;
            ge_cached temp_cached;
            ge_p1p1 temp_p1p1;
            ge_p2 temp_p2;

            public_key spend = m_bob.get_keys().m_account_address.m_spend_public_key;
            if (ge_frombytes_vartime(&spend_p3,&reinterpret_cast<unsigned char &>(spend)) != 0) return false; // B
            ge_scalarmult_base(&temp_p3,&reinterpret_cast<unsigned char &>(d)); // d*G
            ge_p3_to_cached(&temp_cached,&temp_p3);
            ge_add(&temp_p1p1,&spend_p3,&temp_cached); // d*G + B
            ge_p1p1_to_p2(&temp_p2,&temp_p1p1);
            ge_tobytes(&reinterpret_cast<unsigned char &>(output),&temp_p2);

            return true;
        }

        bool test()
        {
            size_t t = 1;
            ec_scalar d;
            ec_scalar tag_full;

            generate_key_derivation(m_tx_pub_key, m_bob.get_keys().m_view_secret_key, m_key_derivation);
            derivation_to_scalar(m_key_derivation, t, d);

            // Compute the view tag
            if (use_tag)
            {
                struct {
                    char salt;
                    ec_scalar payload;
                } buffer;
                buffer.salt = 0xEC; // arbitrary for this test
                buffer.payload = d;
                hash_to_scalar(&buffer, sizeof(char) + sizeof(ec_scalar), tag_full);

                // Ensure we computed the tag properly, even though this isn't strictly needed
                if (memcmp(&tag_full,&tag,sizeof(char))) return false;
            }

            // Test the output key
            if (is_owned)
            {
                ge_p3 output_p3;
                ge_p3 temp_p3;
                ge_cached temp_cached;
                ge_p1p1 temp_p1p1;
                ge_p2 temp_p2;
                public_key spend;

                if (ge_frombytes_vartime(&output_p3,&reinterpret_cast<unsigned char &>(output)) != 0) return false; // P
                ge_scalarmult_base(&temp_p3,&reinterpret_cast<unsigned char &>(d)); // d*G
                ge_p3_to_cached(&temp_cached,&temp_p3);
                ge_sub(&temp_p1p1,&output_p3,&temp_cached); // P - d*G
                ge_p1p1_to_p2(&temp_p2,&temp_p1p1);
                ge_tobytes(&reinterpret_cast<unsigned char &>(spend),&temp_p2);

                if (memcmp(&spend,&m_bob.get_keys().m_account_address.m_spend_public_key,sizeof(public_key))) return false;
            }

            return true;
        }

    private:
        key_derivation m_key_derivation;
        public_key output;
        char tag;
};
