// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "consensus/pbft/pbft_pre_prepares.h"
#include "consensus/pbft/pbft_requests.h"
#include "consensus/pbft/pbft_tables.h"
#include "consensus/pbft/pbft_types.h"
#include "consensus/test/stub_consensus.h"
#include "host/ledger.h"
#include "message.h"
#include "network_mock.h"
#include "node.h"
#include "replica.h"
#include "request.h"
#include "tls/key_pair.h"

#include <cstdio>
#include <doctest/doctest.h>

enclave::ThreadMessaging enclave::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> enclave::ThreadMessaging::thread_count = 0;

// power of 2 since ringbuffer circuit size depends on total_requests
static constexpr size_t total_requests = 32;

class ExecutionMock
{
public:
  ExecutionMock(size_t init_counter_) : command_counter(init_counter_) {}
  size_t command_counter;
  struct fake_req
  {
    uint8_t rt;
    int64_t ctx;
  };

  ExecCommand exec_command =
    [this](
      std::array<std::unique_ptr<ExecCommandMsg>, Max_requests_in_batch>& msgs,
      ByzInfo& info,
      uint32_t num_requests,
      uint64_t nonce,
      bool executed_single_threaded) {
      for (uint32_t i = 0; i < num_requests; ++i)
      {
        std::unique_ptr<ExecCommandMsg>& msg = msgs[i];
        Byz_req* inb = &msg->inb;
        Byz_rep& outb = msg->outb;
        int client = msg->client;
        Request_id rid = msg->rid;
        uint8_t* req_start = msg->req_start;
        size_t req_size = msg->req_size;
        Seqno total_requests_executed = msg->total_requests_executed;
        ccf::Store::Tx* tx = msg->tx;

        // increase total number of commands executed to compare with fake_req
        command_counter++;

        outb.contents =
          pbft::GlobalState::get_replica().create_response_message(
            client, rid, 0, nonce);
        outb.size = 0;
        auto request = reinterpret_cast<fake_req*>(inb->contents);
        info.ctx = request->ctx;
        info.replicated_state_merkle_root.fill(0);
        info.replicated_state_merkle_root.data()[0] = request->rt;

        REQUIRE(request->rt == command_counter);
        msg->cb(*msg.get(), info);
      }
      return 0;
    };
};

namespace pbft
{
  struct RollbackInfo
  {
    pbft::PbftStore* store;
    size_t* called;
    ExecutionMock* execution_mock;
  } register_rollback_ctx;
}

NodeInfo get_node_info()
{
  auto kp = tls::make_key_pair();
  std::vector<PrincipalInfo> principal_info;

  auto node_cert = kp->self_sign("CN=CCF node");

  PrincipalInfo pi = {0, (short)(3000), "ip", node_cert, "name-1", true};
  principal_info.emplace_back(pi);

  GeneralInfo gi = {false,
                    2,
                    0,
                    0,
                    "generic",
                    1800000,
                    5000,
                    100,
                    9999250000,
                    50,
                    principal_info};

  NodeInfo node_info = {gi.principal_info[0], kp->private_key_pem().str(), gi};

  return node_info;
}

void create_replica(
  std::vector<char>& service_mem,
  pbft::PbftStore& store,
  pbft::RequestsMap& pbft_requests_map,
  pbft::PrePreparesMap& pbft_pre_prepares_map,
  ccf::Signatures& signatures)
{
  auto node_info = get_node_info();

  pbft::GlobalState::set_replica(std::make_unique<Replica>(
    node_info,
    service_mem.data(),
    service_mem.size(),
    Create_Mock_Network(),
    pbft_requests_map,
    pbft_pre_prepares_map,
    signatures,
    store));

  pbft::GlobalState::get_replica().init_state();

  for (auto& pi : node_info.general_info.principal_info)
  {
    if (pi.id != node_info.own_info.id)
    {
      pbft::GlobalState::get_replica().add_principal(pi);
    }
  }
}

Request* create_and_store_request(
  size_t index,
  pbft::PbftStore& store,
  pbft::RequestsMap& req_map,
  ccf::Store::Map<std::string, std::string>* derived_map = nullptr)
{
  Byz_req req;
  Byz_alloc_request(&req, sizeof(ExecutionMock::fake_req));

  auto fr = reinterpret_cast<ExecutionMock::fake_req*>(req.contents);
  fr->rt = index;
  // context would be the version of the executed command
  fr->ctx = store.current_version() + 1;

  Request* request = (Request*)req.opaque;
  request->request_id() = index;
  request->authenticate(req.size, false);

  ccf::Store::Tx tx;
  auto req_view = tx.get_view(req_map);

  int command_size;
  auto command_start = request->command(command_size);

  req_view->put(
    0,
    {0,
     {},
     {command_start, command_start + command_size},
     {(const uint8_t*)request->contents(),
      (const uint8_t*)request->contents() + request->size()}});

  if (derived_map)
  {
    auto der_view = tx.get_view(*derived_map);
    der_view->put("key1", "value1");
  }

  REQUIRE(tx.commit() == kv::CommitSuccess::OK);

  return request;
}

void populate_entries(
  std::vector<std::vector<uint8_t>>& entries,
  std::shared_ptr<kv::StubConsensus> consensus)
{
  while (true)
  {
    auto ret = consensus->pop_oldest_data();
    if (!ret.second)
    {
      break;
    }
    entries.emplace_back(ret.first);
  }
}

static constexpr int mem_size = 256;

using PbftStoreType = pbft::Adaptor<ccf::Store, kv::DeserialiseSuccess>;
struct PbftState
{
  std::shared_ptr<ccf::Store> store;
  std::unique_ptr<PbftStoreType> pbft_store;
  pbft::RequestsMap& pbft_requests_map;
  ccf::Signatures& signatures;
  pbft::PrePreparesMap& pbft_pre_prepares_map;
  std::vector<char> service_mem;
  ExecutionMock exec_mock;

  PbftState() :
    store(std::make_shared<ccf::Store>(
      pbft::replicate_type_pbft, pbft::replicated_tables_pbft)),
    pbft_store(std::make_unique<PbftStoreType>(store)),
    pbft_requests_map(store->create<pbft::RequestsMap>(
      pbft::Tables::PBFT_REQUESTS, kv::SecurityDomain::PUBLIC)),
    signatures(store->create<ccf::Signatures>(ccf::Tables::SIGNATURES)),
    pbft_pre_prepares_map(store->create<pbft::PrePreparesMap>(
      pbft::Tables::PBFT_PRE_PREPARES, kv::SecurityDomain::PUBLIC)),
    service_mem(mem_size, 0),
    exec_mock(0)
  {}
};

void init_test_state(PbftState& pbft_state)
{
  create_replica(
    pbft_state.service_mem,
    *pbft_state.pbft_store,
    pbft_state.pbft_requests_map,
    pbft_state.pbft_pre_prepares_map,
    pbft_state.signatures);
  pbft::GlobalState::get_replica().register_exec(
    pbft_state.exec_mock.exec_command);
}

TEST_CASE("Test Ledger Replay")
{
  // initiate replica with stub consensus to be used on replay
  auto write_consensus =
    std::make_shared<kv::StubConsensus>(ConsensusType::PBFT);
  INFO("Create dummy pre-prepares and write them to ledger");
  {
    PbftState pbft_state;
    init_test_state(pbft_state);

    pbft_state.store->set_consensus(write_consensus);
    auto& write_derived_map =
      pbft_state.store->create<std::string, std::string>(
        "derived_map", kv::SecurityDomain::PUBLIC);

    for (size_t i = 1; i < total_requests; i++)
    {
      auto request = create_and_store_request(
        i,
        *pbft_state.pbft_store,
        pbft_state.pbft_requests_map,
        &write_derived_map);
      // replica handle request (creates and writes pre prepare to ledger)
      pbft::GlobalState::get_replica().handle(request);
    }
    // remove the requests that were not processed, only written to the ledger
    pbft::GlobalState::get_replica().big_reqs()->clear();
  }

  auto corrupt_consensus =
    std::make_shared<kv::StubConsensus>(ConsensusType::PBFT);
  INFO("Create dummy corrupt pre-prepares and write them to ledger");
  {
    // initialise a corrupt store that will follow the write store but with
    // the requests and merkle root off and use it later to trigger rollbacks
    PbftState pbft_state;
    init_test_state(pbft_state);
    pbft_state.store->set_consensus(corrupt_consensus);

    pbft_state.exec_mock.command_counter++;

    LedgerWriter ledger_writer(
      *pbft_state.pbft_store,
      pbft_state.pbft_pre_prepares_map,
      pbft_state.signatures);

    Req_queue rqueue;
    for (size_t i = 1; i < total_requests; i++)
    {
      auto request = create_and_store_request(
        i, *pbft_state.pbft_store, pbft_state.pbft_requests_map);

      // request is compatible but pre-prepare root is different
      rqueue.append(request);
      size_t num_requests = 1;
      auto pp = std::make_unique<Pre_prepare>(1, i, rqueue, num_requests, 0);

      // imitate exec command
      ByzInfo info;
      info.ctx = i;
      info.replicated_state_merkle_root.fill(0);
      // mess up merkle roots
      info.replicated_state_merkle_root.data()[0] = i + 1;

      pp->set_merkle_roots_and_ctx(info.replicated_state_merkle_root, info.ctx);

      ledger_writer.write_pre_prepare(pp.get());
    }
    // remove the requests that were not processed, only written to the ledger
    pbft::GlobalState::get_replica().big_reqs()->clear();
  }

  INFO(
    "Read the ledger entries and replay them out of order, while being "
    "corrupt, and in order");
  {
    PbftState pbft_state;
    init_test_state(pbft_state);

    auto consensus = std::make_shared<kv::StubConsensus>(ConsensusType::PBFT);
    pbft_state.store->set_consensus(consensus);
    auto& derived_map = pbft_state.store->create<std::string, std::string>(
      "derived_map", kv::SecurityDomain::PUBLIC);

    // create rollback cb
    size_t call_rollback = 0;
    kv::Version rb_version;

    auto rollback_cb =
      [](kv::Version version, pbft::RollbackInfo* rollback_info) {
        (*rollback_info->called)++;
        rollback_info->store->rollback(version);
        rollback_info->execution_mock->command_counter--;
      };

    pbft::register_rollback_ctx.called = &call_rollback;
    pbft::register_rollback_ctx.store = pbft_state.pbft_store.get();
    pbft::register_rollback_ctx.execution_mock = &pbft_state.exec_mock;

    pbft::GlobalState::get_replica().register_rollback_cb(
      rollback_cb, &pbft::register_rollback_ctx);

    // ledgerenclave work
    std::vector<std::vector<uint8_t>> entries;
    std::vector<std::vector<uint8_t>> corrupt_entries;
    populate_entries(entries, write_consensus);
    populate_entries(corrupt_entries, corrupt_consensus);

    // apply out of order first
    REQUIRE(
      pbft_state.store->deserialise(entries.back()) ==
      kv::DeserialiseSuccess::FAILED);

    ccf::Store::Tx tx;
    auto req_view = tx.get_view(pbft_state.pbft_requests_map);
    auto req = req_view->get(0);
    REQUIRE(!req.has_value());

    auto pp_view = tx.get_view(pbft_state.pbft_pre_prepares_map);
    auto pp = pp_view->get(0);
    REQUIRE(!pp.has_value());

    REQUIRE(entries.size() > 0);

    Seqno seqno = 1;
    size_t iterations = 0;
    size_t count_rollbacks = 0;
    // keep latest executed request so that we can re-apply it after a rollback
    std::vector<uint8_t> lastest_executed_request;
    // apply all of the data in order
    for (size_t i = 0; i < entries.size(); i++)
    {
      const auto& entry = entries.at(i);
      const auto& corrupt_entry = corrupt_entries.at(i);

      if (iterations % 2)
      {
        // odd entries are pre prepares
        // try to deserialise corrupt pre-prepare which should trigger a
        // rollback
        ccf::Store::Tx tx;
        REQUIRE(
          pbft_state.store->deserialise_views(
            corrupt_entry, false, nullptr, &tx) ==
          kv::DeserialiseSuccess::PASS_PRE_PREPARE);
        REQUIRE_THROWS_AS(
          pbft::GlobalState::get_replica().playback_pre_prepare(tx),
          std::logic_error);
        count_rollbacks++;

        // rolled back latest request so need to re-execute
        ccf::Store::Tx re_exec_tx;
        REQUIRE(
          pbft_state.store->deserialise_views(
            lastest_executed_request, false, nullptr, &re_exec_tx) ==
          kv::DeserialiseSuccess::PASS);
        pbft::GlobalState::get_replica().playback_request(re_exec_tx);
        REQUIRE(re_exec_tx.commit() == kv::CommitSuccess::OK);
      }

      if (iterations % 2)
      {
        // odd entries are pre prepares
        ccf::Store::Tx tx;
        REQUIRE(
          pbft_state.store->deserialise_views(entry, false, nullptr, &tx) ==
          kv::DeserialiseSuccess::PASS_PRE_PREPARE);
        pbft::GlobalState::get_replica().playback_pre_prepare(tx);

        ccf::Store::Tx read_tx;
        auto pp_view = read_tx.get_view(pbft_state.pbft_pre_prepares_map);
        auto pp = pp_view->get(0);
        REQUIRE(pp.has_value());
        REQUIRE(pp.value().seqno == seqno);
        seqno++;
      }
      else
      {
        // even entries are requests
        ccf::Store::Tx tx;
        REQUIRE(
          pbft_state.store->deserialise_views(entry, false, nullptr, &tx) ==
          kv::DeserialiseSuccess::PASS);
        pbft::GlobalState::get_replica().playback_request(tx);
        // pre-prepares are committed in playback_pre_prepare
        REQUIRE(tx.commit() == kv::CommitSuccess::OK);

        ccf::Store::Tx read_tx;
        lastest_executed_request = entry;
        // even entries are requests
        auto req_view = read_tx.get_view(pbft_state.pbft_requests_map);
        auto req = req_view->get(0);
        REQUIRE(req.has_value());
        REQUIRE(req.value().raw.size() > 0);
      }

      // no derived data should have gotten deserialised
      ccf::Store::Tx read_tx;
      auto der_view = read_tx.get_view(derived_map);
      auto derived_val = der_view->get("key1");
      REQUIRE(!derived_val.has_value());

      iterations++;
    }

    auto last_executed = pbft::GlobalState::get_replica().get_last_executed();
    REQUIRE(last_executed == total_requests - 1);
    REQUIRE(call_rollback == count_rollbacks);
  }
}

void no_op_pre_prepare(
  std::vector<uint8_t>& pp_contents, size_t& pp_digest_hash)
{
  PbftState pbft_state;
  init_test_state(pbft_state);

  // Null request
  Req_queue empty;
  size_t requests_in_batch;
  View v = 0;
  Seqno sn = 1;
  auto pp = std::make_unique<Pre_prepare>(v, sn, empty, requests_in_batch, 0);
  pp->set_digest();
  pp_digest_hash = pp->digest().hash();
  std::copy(
    pp->contents(),
    pp->contents() + pp->size(),
    std::back_inserter(pp_contents));

  // replica handle no op pre-prepare with empty request, so no execution should
  // occur
  pbft::GlobalState::get_replica().process_message(pp.release());
  DOCTEST_REQUIRE(pbft_state.exec_mock.command_counter == 0);
}

TEST_CASE("Test No Ops")
{
  size_t first_digest;
  std::vector<uint8_t> first_pp_contents;
  size_t second_digest;
  std::vector<uint8_t> second_pp_contents;

  INFO("Create no-op pre prepare on first replica");
  no_op_pre_prepare(first_pp_contents, first_digest);
  INFO("Create no-op pre prepare on second replica");
  no_op_pre_prepare(second_pp_contents, second_digest);
  INFO("Compare the two no op pre-prepares");
  REQUIRE(first_digest == second_digest);
  REQUIRE(first_pp_contents.size() == second_pp_contents.size());
  REQUIRE(std::equal(
    first_pp_contents.begin(),
    first_pp_contents.end(),
    second_pp_contents.begin()));
}