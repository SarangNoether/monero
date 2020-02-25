// Copyright (c) 2014-2019, The Monero Project
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

#include "ringct/rctSigs.h"
#include "cryptonote_basic/cryptonote_basic.h"

#include "single_tx_test_base.h"

template<size_t ring_size, bool ver, size_t index>
class test_offset_mlsag : public single_tx_test_base
{
public:
  static const size_t n = ring_size;
  static const size_t loop_count = 1000;
  static const size_t l = index;

  bool init()
  {
    if (!single_tx_test_base::init())
      return false;

    rct::keyV x = rct::skvGen(2);
    rct::keyM M = rct::keyMInit(2,n);
    rct::identity(C_aux);

    // Set decoys
    rct::keyV P = rct::skvGen(n);
    rct::keyV C = rct::skvGen(n);
    for (size_t i = 0; i < n; i++)
    {
        M[i][0] = rct::scalarmultBase(P[i]);
        M[i][1] = rct::scalarmultBase(C[i]);
    }
    // Set known keys
    M[l][0] = rct::scalarmultBase(x[0]);
    M[l][1] = rct::scalarmultBase(x[1]);
    pubs.reserve(n);
    for (size_t i = 0; i < n; i++)
    {
        rct::ctkey tmp;
        tmp.dest = M[i][0];
        tmp.mask = M[i][1];
        pubs.push_back(tmp);
    }

    rct::key zero;
    sc_0(zero.bytes);

    sig = MLSAG_Gen(zero,M,x,NULL,NULL,l,1,hw::get_device("default"));

    return true;
  }

  bool test()
  {
    rct::key zero;
    sc_0(zero.bytes);
    if (ver)
      return verRctMGSimple(zero,sig,pubs,C_aux);
    else
      MLSAG_Gen(zero,M,x,NULL,NULL,l,1,hw::get_device("default"));
    return true;
  }

private:
  rct::keyM M;
  rct::keyV x;
  rct::key C_aux;
  rct::ctkeyV pubs;
  rct::mgSig sig;
};
