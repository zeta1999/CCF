// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#include "receipts.h"

#include "ds/logger.h"
#include "message_tags.h"
#include "node.h"
#include "pbft_assert.h"

Receipts::Receipts(
  int id,
  int to,
  Seqno seqno,
  kv::Version version,
  uint32_t receipt_msg_size,
  uint8_t* msg) :
  Message(Receipts_tag, sizeof(Receipts_rep) + receipt_msg_size),
  current_signature_count(0),
  send_to(to)
{
  rep().id = id;
  rep().seqno = seqno;
  rep().version = version;
  rep().receipt_msg_size = receipt_msg_size;
  memcpy((uint8_t*)msg_buf + sizeof(Receipts_rep), msg, receipt_msg_size);
}

int Receipts::id() const
{
  return rep().id;
}

int Receipts::to() const
{
  return send_to;
}

kv::Version Receipts::version() const
{
  return rep().version;
}

uint32_t Receipts::receipt_msg_size() const
{
  return rep().receipt_msg_size;
}

Seqno Receipts::seqno() const
{
  return rep().seqno;
}

Receipts_rep& Receipts::rep() const
{
  PBFT_ASSERT(ALIGNED(msg_buf), "Improperly aligned pointer");
  return *((Receipts_rep*)msg_buf);
}

bool Receipts::pre_verify()
{
  return true;
}