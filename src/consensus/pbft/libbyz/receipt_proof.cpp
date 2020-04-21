// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#include "receipt_proof.h"

#include "parameters.h"

ReceiptProof::ReceiptProof(int id, Seqno seqno, uint8_t num_proofs) :
  Message(
    Receipt_proof_tag,
    sizeof(Receipt_proof_rep) + num_proofs * sizeof(ReceiptProof::Proof))
{
  rep().id = id;
  rep().seqno = seqno;
  rep().num_sigs = num_proofs;
}

void ReceiptProof::add_proof(uint8_t id, PbftSignature& sig)
{
  assert(current_stored < rep().num_sigs);

  uint8_t target_offset = current_stored;

  auto it = sig_location.find(id);
  if (it != sig_location.end())
  {
    target_offset = it->second;
  }
  else
  {
    ++current_stored;
  }
  auto& proof = *(
    ReceiptProof::
      Proof*)((uint8_t*)msg_buf + (sizeof(Receipt_proof_rep) + sizeof(ReceiptProof::Proof) * target_offset));
  proof.id = id;
  std::copy(sig.begin(), sig.end(), proof.sig.begin());
}

Receipt_proof_rep& ReceiptProof::rep() const
{
  PBFT_ASSERT(ALIGNED(msg_buf), "Improperly aligned pointer");
  return *((Receipt_proof_rep*)msg_buf);
}

bool ReceiptProof::pre_verify()
{
  return true;
}