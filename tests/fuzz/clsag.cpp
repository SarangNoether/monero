// Copyright (c) 2017-2019, The Monero Project
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

#include <boost/archive/portable_binary_oarchive.hpp>

#include "include_base_utils.h"
#include "file_io_utils.h"
#include "cryptonote_basic/blobdatatype.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "ringct/rctSigs.h"
#include "serialization/binary_archive.h"
#include "serialization/binary_utils.h"
#include "serialization/vector.h"
#include "fuzzer.h"

using namespace crypto;
using namespace rct;

class CLSAGFuzzer: public Fuzzer
{
public:
  CLSAGFuzzer(): Fuzzer() {}
  virtual int init();
  virtual int run(const std::string &filename);
  int generate_seed_corpus(const std::string& path);
  int fuzz_message(const std::string&);
  int fuzz_cout(const std::string&);
  int fuzz_clsag(const std::string&);
  int fuzz_clsag_deserialize(const std::string&);

private:
    key message;
    ctkeyV pubs;
    key p, t, t2, u;
    ctkey backup;
    key Cout;
    ctkey insk;
    clsag clsag_s;
};

int CLSAGFuzzer::generate_seed_corpus(const std::string& path)
{
  try
  {
    std::cout << "Generating corpus seed: " << path << std::endl;
    std::string clsag_out;
    serialization::dump_binary(clsag_s, clsag_out);
    std::string corpus_path(path);

    // write valid CLSAG
    epee::file_io_utils::save_string_to_file(corpus_path, clsag_out);
  }
  catch (const std::exception &e)
  {
    std::cerr << "Error on CLSAGFuzzer::generate_seed_corpus: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}

int CLSAGFuzzer::init()
{
  try
  {
    message = identity();

    const size_t N = 11;
    const size_t idx = 5;

    for (size_t i = 0; i < N; ++i)
    {
      key sk;
      ctkey tmp;

      skpkGen(sk, tmp.dest);
      skpkGen(sk, tmp.mask);

      pubs.push_back(tmp);
    }

    // Set P[idx]
    skpkGen(p, pubs[idx].dest);

    // Set C[idx]
    t = skGen();
    u = skGen();
    addKeys2(pubs[idx].mask,t,u,H);

    // Set commitment offset
    t2 = skGen();
    addKeys2(Cout,t2,u,H);

    // Prepare generation inputs
    insk.dest = p;
    insk.mask = t;

    clsag_s = rct::proveRctCLSAGSimple(zero(),pubs,insk,t2,Cout,NULL,NULL,NULL,idx,hw::get_device("default"));
  }
  catch (const std::exception &e)
  {
    std::cerr << "Error on CLSAGFuzzer::init: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}

int CLSAGFuzzer::fuzz_message(const std::string& s)
{
  // fuzz message
  memcpy(&message, (uint8_t*)s.c_str(), sizeof(message));
  auto valid = rct::verRctCLSAGSimple(message,clsag_s,pubs,Cout);

  return 0;
}

int CLSAGFuzzer::fuzz_cout(const std::string& s)
{
  // fuzz Cout
  memcpy(&Cout, (uint8_t*)s.c_str(), sizeof(Cout));
  rct::verRctCLSAGSimple(message,clsag_s,pubs,Cout);

  return 0;
}

int CLSAGFuzzer::fuzz_clsag(const std::string& s)
{
  // fuzz clsag
  size_t off = 0;

  for (auto& s_ : clsag_s.s)
  {
    memcpy(&s_, (uint8_t*)s.c_str() + off, sizeof(s_));
    off += sizeof(s_);
  }

  memcpy(&clsag_s.c1, (uint8_t*)s.c_str() + off, sizeof(clsag_s.c1)); off += sizeof(clsag_s.c1);
  memcpy(&clsag_s.I, (uint8_t*)s.c_str() + off, sizeof(clsag_s.I)); off += sizeof(clsag_s.I);
  memcpy(&clsag_s.D, (uint8_t*)s.c_str() + off, sizeof(clsag_s.D));

  rct::verRctCLSAGSimple(message,clsag_s,pubs,Cout);

  return 0;
}

int CLSAGFuzzer::fuzz_clsag_deserialize(const std::string& s)
{
  // fuzz deserialization
  serialization::parse_binary(s, clsag_s);

  rct::verRctCLSAGSimple(message,clsag_s,pubs,Cout);

  return 0;
}

int CLSAGFuzzer::run(const std::string &filename)
{
  std::string s;

  if (!epee::file_io_utils::load_file_to_string(filename, s))
  {
    std::cout << "Error: failed to load file " << filename << std::endl;
    return 1;
  }

  fuzz_message(s);
  fuzz_cout(s);
  fuzz_clsag(s);
  fuzz_clsag_deserialize(s);

  return 0;
}

int main(int argc, const char **argv)
{
  TRY_ENTRY();
  CLSAGFuzzer fuzzer;

  if (argc >= 3 && std::string(argv[1]) == std::string("--gen-corpus"))
  {
    fuzzer.generate_seed_corpus(std::string(argv[2]) + "/clsag_seed");
    return 0;
  }

  return run_fuzzer(argc, argv, fuzzer);
  CATCH_ENTRY_L0("main", 1);
}
