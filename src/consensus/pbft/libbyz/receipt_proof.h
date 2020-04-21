// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include "message.h"
#include "parameters.h"

//
// Receipt proof messages have the following format:
//
#pragma pack(push)
#pragma pack(1)
struct Receipt_proof_rep : public Message_rep
{
  int id; // id of the replica that generated the message.
  Seqno seqno; // seqno of this receipt proof message
  uint8_t num_sigs; // size of the buffer that follows the receipts
};
#pragma pack(pop)

class ReceiptProof : public Message
{
public:
  struct Proof
  {
    int id;
    PbftSignature sig;
  };

public:
  ReceiptProof(uint32_t msg_size = 0) : Message(msg_size) {}

  ReceiptProof(int id, Seqno seqno, uint8_t num_proofs);

  int id() const;

  Seqno seqno() const;

  uint8_t num_proofs() const;

  void add_proof(uint8_t id, PbftSignature& sig);

  bool pre_verify();
  // Effects: Performs preliminary verification checks

private:
  Receipt_proof_rep& rep() const;
  uint32_t current_stored = 0;

  std::map<int, int> sig_location; // maps node_id to where its proof is
};