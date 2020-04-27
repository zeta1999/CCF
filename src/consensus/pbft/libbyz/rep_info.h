// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "digest.h"
#include "ds/spin_lock.h"
#include "partition.h"
#include "reply.h"
#include "time_types.h"
#include "types.h"

#include <memory>
#include <sys/time.h>
#include <vector>

class Req_queue;

class Rep_info
{
  //
  // Holds replies to requests until they prepare.
  //
public:
  Rep_info();
  // Requires: "mem" points to an array of "size" bytes and is virtual
  // memory page aligned.
  // Effects: Creates a new object that stores data in "mem"

  char* new_reply(
    int pid,
    Request_id rid,
    Seqno n,
    kv::Version version,
    uint64_t nonce,
    uint32_t message_size);
  // Effects: Allocates a new reply for request rid from
  // principal pid executed at sequence number n and returns a buffer
  // to store the reply to the command.

  void end_reply(int pid, Request_id rid, Seqno n, int size);
  // Effects: Completes the construction of a new reply value: this is
  // informed that the reply value is size bytes long and computes its
  // digest.

  Reply* reply(int pid, Request_id rid, Seqno n);
  // Effects: returns a pointer to the reply stored for <pid,rid,n> or
  // nullptr if no such reply

  void send_reply(int pid, Request_id rid, Seqno n, View v, int id);
  // Effects: Sends a reply message to "pid" for view "v" from replica
  // "id" with the reply for <pid,rid,n> value stored in the buffer returned by
  // new_reply, and removes the message.

  void clear();
  // Effects: removes all replies stored by this

  void dump_state(std::ostream& os);
  // Effects: logs state for debugging

private:
  struct Key
  {
    size_t cid;
    Request_id rid;
    Seqno n;
    bool operator==(const Key& o) const
    {
      return (cid == o.cid) & (rid == o.rid) & (n == o.n);
    }
  };

  struct KeyHash
  {
    size_t operator()(const Key& k) const
    {
      return k.cid ^ k.rid;
    }
  };
  std::unordered_map<Key, std::unique_ptr<Reply>, KeyHash> reps;
  SpinLock lock;
};
