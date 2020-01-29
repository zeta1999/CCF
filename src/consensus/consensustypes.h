// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include <stdint.h>

namespace ccf
{
  using ObjectId = uint64_t;
  using Term = ObjectId;
  using NodeId = ObjectId;
  using Index = int64_t;
  using Node2NodeMsg = ObjectId;
}

namespace consensus
{
  enum ConsensusMsgType : ccf::Node2NodeMsg
  {
    append_entries = 0,
    append_entries_response
  };

#pragma pack(push, 1)

  struct ConsensusHeader
  {
    ConsensusMsgType msg;
    ccf::NodeId from_node;
  };

  struct AppendEntriesIndex : ConsensusHeader
  {
    ccf::Index idx;
    ccf::Index prev_idx;
  };

#pragma pack(pop)
}