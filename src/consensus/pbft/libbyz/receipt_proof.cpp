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
    sig_location.insert({id, std::move(proof)});
  }
}

size_t ReceiptProof::get_size_of_proofs() const
{
  return sig_location.size() * sizeof(ReceiptProof::Proof);
}

size_t ReceiptProof::count() const
{
  return sig_location.size();
}

void ReceiptProof::copy_out_proofs(uint8_t* dest) const
{
  for (auto& proof : sig_location)
  {
    auto& p = proof.second;
    std::copy(
      (uint8_t*)p.get(), (uint8_t*)p.get() + sizeof(ReceiptProof::Proof), dest);
    dest += sizeof(ReceiptProof::Proof);
  }
}