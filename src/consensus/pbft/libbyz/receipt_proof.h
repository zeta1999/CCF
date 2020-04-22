// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include "parameters.h"
#include "types.h"

class ReceiptProof
{
public:
  struct Proof
  {
    int id;
    PbftSignature sig;
  };

public:
  ReceiptProof(Seqno seqno, uint8_t num_proofs);

  void add_proof(uint8_t id, PbftSignature& sig);

private:
  uint8_t num_sigs; // size of the buffer that follows the receipts
  Seqno seqno; // seqno of this receipt proof message

  std::map<int, std::unique_ptr<ReceiptProof::Proof>>
    sig_location; // maps node_id to where its proof is
};