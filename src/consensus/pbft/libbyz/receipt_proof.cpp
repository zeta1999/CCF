// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#include "receipt_proof.h"

#include "parameters.h"

ReceiptProof::ReceiptProof(Seqno seqno_, uint8_t num_proofs_) :
  seqno(seqno_),
  num_sigs(num_proofs_)
{}

void ReceiptProof::add_proof(uint8_t id, PbftSignature& sig)
{
  auto it = sig_location.find(id);
  if (it != sig_location.end())
  {
    auto& proof = it->second;
    std::copy(sig.begin(), sig.end(), proof->sig.begin());
  }
  else
  {
    auto proof = std::make_unique<ReceiptProof::Proof>();
    proof->id = id;
    std::copy(sig.begin(), sig.end(), proof->sig.begin());
  }
}