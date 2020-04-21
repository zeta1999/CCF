// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include "message.h"
#include "parameters.h"

//
// Receipt messages have the following format:
//
#pragma pack(push)
#pragma pack(1)
struct Receipts_rep : public Message_rep
{
  int id; // id of the replica that generated the message.
  Seqno seqno; // seqno of this receipt message
  kv::Version version;
  uint32_t receipt_msg_size; // size of the buffer that follows the receipts
  char padding[1];
};
#pragma pack(pop)

class Receipts : public Message
{
public:
  Receipts(uint32_t msg_size = 0) : Message(msg_size) {}

  Receipts(
    int id,
    int to,
    Seqno seqno,
    kv::Version version,
    uint32_t receipt_msg_size,
    uint8_t* msg);

  int id() const;

  int to() const;

  kv::Version version() const;

  uint8_t* get_receipts() const;

  uint32_t receipt_msg_size() const;

  Seqno seqno() const;

  bool pre_verify();
  // Effects: Performs preliminary verification checks

  Receipts* next = nullptr;
  Receipts* prev = nullptr;

private:
  Receipts_rep& rep() const;

  uint8_t current_signature_count;
  int send_to;
};
