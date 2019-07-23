#include <enclave/appinterface.h>
#include <node/rpc/userfrontend.h>

namespace ccf
{
  struct ReleasePolicy
  {
    size_t min_builds;
  };
  DECLARE_REQUIRED_JSON_FIELDS(ReleasePolicy, min_builds);

  // RPC: CreateReleaseBranch
  struct CreateReleaseBranch
  {
    static constexpr auto METHOD = "CREATE_RELEASE_BRANCH";

    struct In
    {
      std::string repository;
      std::string branch;
      ReleasePolicy policy;
    };

    struct Out
    {
      std::vector<uint8_t> pubk;
    };
  };
  DECLARE_REQUIRED_JSON_FIELDS(
    CreateReleaseBranch::In, repository, branch, policy);
  DECLARE_REQUIRED_JSON_FIELDS(CreateReleaseBranch::Out, pubk);

  // RPC: SignReleaseBranch
  struct SignReleaseBranch
  {
    static constexpr auto METHOD = "SIGN_RELEASE_BRANCH";

    struct In
    {
      std::string repository;
      std::string branch;
      nlohmann::json pr;
      std::vector<uint8_t> binary;
      std::vector<uint8_t> oe_sig_info;
    };

    struct Out
    {
      std::vector<uint8_t> oe_sig_val;
    };
  };
  DECLARE_REQUIRED_JSON_FIELDS(
    SignReleaseBranch::In, repository, branch, pr, binary, oe_sig_info);
  DECLARE_REQUIRED_JSON_FIELDS(SignReleaseBranch::Out, oe_sig_val);

  struct BranchData
  {
    nlohmann::json info;
    std::vector<uint8_t> pubk;
    std::vector<uint8_t> privk;
    ReleasePolicy policy;
  };

  struct ReleaseData
  {
    std::string repository;
    std::string branch;
    nlohmann::json pr;
    std::vector<uint8_t> binary;
    std::vector<uint8_t> oe_sig_info;
    std::vector<uint8_t> oe_sig_val;
  };

  class TessApp : public ccf::UserRpcFrontend
  {
  public:
    enum class Role
    {
      Contributor,
      Reviewer,
      Builder,
      Publisher,
      Admin,
    };

    ccf::NetworkTables& network;

    using Roles = std::set<Role>;
    using RolesMap = ccfapp::Store::Map<ccf::CallerId, Roles>;
    RolesMap& user_roles;

    using BranchesMap = ccfapp::Store::Map<std::string, BranchData>;
    BranchesMap& branches;

    using ReleaseID = size_t;
    // Map with single value at key 0
    using NextReleaseMap = ccfapp::Store::Map<size_t, ReleaseID>;
    NextReleaseMap& next_release;
    using ReleasesMap = ccfapp::Store::Map<ReleaseID, ReleaseData>;
    ReleasesMap& releases;

    Roles get_roles(ccf::Store::Tx& tx, ccf::CallerId user)
    {
      auto rv = tx.get_view(user_roles);
      auto r = rv->get(user);

      Roles roles = r.value_or(Roles{});

      // TODO: Temporary hack to work around governance bootstrapping.
      // Every user is also an admin.
      roles.insert(Role::Admin);

      return roles;
    }

    ReleaseID get_next_release(ccf::Store::Tx& tx)
    {
      auto v = tx.get_view(next_release);
      const auto it = v->get(0);
      const auto id = it.value_or(0);
      v->put(0, id + 1);

      return id;
    }

    bool is_policy_met(
      const ReleasePolicy& policy,
      const nlohmann::json& pr,
      std::vector<std::string>& failure_reasons)
    {
      // TODO
      return true;
    }

    TessApp(ccf::NetworkTables& nwt, ccf::AbstractNotifier& notifier) :
      UserRpcFrontend(*nwt.tables),
      network(nwt),
      user_roles(tables.create<RolesMap>("user-roles")),
      branches(tables.create<BranchesMap>("branches")),
      next_release(tables.create<NextReleaseMap>("next-release")),
      releases(tables.create<ReleasesMap>("releases"))
    {
      auto roles_get = [this](RequestArgs& args) {
        return jsonrpc::success(get_roles(args.tx, args.caller_id));
      };
      install("ROLES_GET", roles_get, Read);

      auto roles_add = [this](RequestArgs& args) {
        const auto caller_roles = get_roles(args.tx, args.caller_id);
        if (caller_roles.find(Role::Admin) == caller_roles.end())
          return jsonrpc::error(
            jsonrpc::CCFErrorCodes::INSUFFICIENT_RIGHTS,
            "Only admins may add roles");

        auto user_it = args.params.find("user");
        if (user_it == args.params.end())
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS, "Missing param: user");

        auto new_role_it = args.params.find("role");
        if (new_role_it == args.params.end())
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS, "Missing param: role");

        auto rv = args.tx.get_view(user_roles);
        const auto user = user_it->get<ccf::CallerId>();
        auto roles = get_roles(args.tx, user);
        const auto new_role = new_role_it->get<Role>();

        if (roles.find(new_role) != roles.end())
          return jsonrpc::error(
            jsonrpc::CCFErrorCodes::INSUFFICIENT_RIGHTS,
            fmt::format("User {} already has role {}", user, new_role));

        roles.insert(new_role);
        rv->put(user, roles);
        return jsonrpc::success(roles);
      };
      install("ROLES_ADD", roles_add, Write);

      auto create_release_branch = [this](RequestArgs& args) {
        auto in = args.params.get<CreateReleaseBranch::In>();
        CreateReleaseBranch::Out out;

        auto release_name = fmt::format("{}:{}", in.repository, in.branch);

        auto branches_view = args.tx.get_view(branches);
        if (branches_view->get(release_name).has_value())
        {
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            fmt::format(
              "Already have a branch named {} in repository {}",
              in.branch,
              in.repository));
        }

        // GH.create_protected_branch(branch, commit);

        auto kp = tls::make_key_pair();

        BranchData bd;
        bd.info = args.params["info"];
        bd.pubk = out.pubk;
        bd.privk = kp->private_key();
        bd.policy = in.policy;
        branches_view->put(release_name, bd);

        return jsonrpc::success(out);
      };
      install(CreateReleaseBranch::METHOD, create_release_branch, Write);

      auto sign_release_branch = [this](RequestArgs& args) {
        auto in = args.params.get<SignReleaseBranch::In>();
        SignReleaseBranch::Out out;

        auto release_name = fmt::format("{}:{}", in.repository, in.branch);

        auto branches_view = args.tx.get_view(branches);
        const auto branch_it = branches_view->get(release_name);
        if (!branch_it.has_value())
        {
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            fmt::format(
              "There is no branch {} for repository {}",
              in.repository,
              in.branch));
        }

        const auto& branch_data = *branch_it;

        std::vector<std::string> failure_reasons;
        if (!is_policy_met(in.pr, branch_data.policy, failure_reasons))
        {
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            fmt::format(
              "Policy is not met:\n{}", fmt::join(failure_reasons, "\n")));
        }

        const auto release_id = get_next_release(args.tx);

        out.oe_sig_val = std::vector<uint8_t>(); // Sign

        // GH.accept_pr(..., oe_sig_val);

        auto releases_view = args.tx.get_view(releases);
        ReleaseData rd;
        rd.repository = in.repository;
        rd.branch = in.branch;
        rd.pr = in.pr;
        rd.binary = in.binary;
        rd.oe_sig_info = in.oe_sig_info;
        rd.oe_sig_val = out.oe_sig_val;
        releases_view->put(release_id, rd);

        return jsonrpc::success(out);
      };
      install(SignReleaseBranch::METHOD, sign_release_branch, Write);
    }
  };

  NLOHMANN_JSON_SERIALIZE_ENUM(
    ccf::TessApp::Role,
    {
      {ccf::TessApp::Role::Contributor, "Contributor"},
      {ccf::TessApp::Role::Reviewer, "Reviewer"},
      {ccf::TessApp::Role::Builder, "Builder"},
      {ccf::TessApp::Role::Publisher, "Publisher"},
      {ccf::TessApp::Role::Admin, "Admin"},
    });
}

namespace fmt
{
  template <>
  struct formatter<ccf::TessApp::Role>
  {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(ccf::TessApp::Role r, FormatContext& ctx)
    {
      switch (r)
      {
        case (ccf::TessApp::Role::Contributor):
          return format_to(ctx.out(), "Contributor");
        case (ccf::TessApp::Role::Reviewer):
          return format_to(ctx.out(), "Reviewer");
        case (ccf::TessApp::Role::Builder):
          return format_to(ctx.out(), "Builder");
        case (ccf::TessApp::Role::Publisher):
          return format_to(ctx.out(), "Publisher");
        case (ccf::TessApp::Role::Admin):
          return format_to(ctx.out(), "Admin");
        default:
          return format_to(ctx.out(), "Unknown");
      }
    }
  };
}

namespace msgpack
{
  // msgpack conversion for uint256_t
  MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS)
  {
    namespace adaptor
    {
      // ReleasePolicy
      template <>
      struct convert<ccf::ReleasePolicy>
      {
        msgpack::object const& operator()(
          msgpack::object const& o, ccf::ReleasePolicy& rp) const
        {
          rp = {
            o.via.array.ptr[0].as<decltype(ccf::ReleasePolicy::min_builds)>()};

          return o;
        }
      };

      template <>
      struct pack<ccf::ReleasePolicy>
      {
        template <typename Stream>
        packer<Stream>& operator()(
          msgpack::packer<Stream>& o, ccf::ReleasePolicy const& rp) const
        {
          o.pack_array(1);

          o.pack(rp.min_builds);

          return o;
        }
      };

      // BranchData
      template <>
      struct convert<ccf::BranchData>
      {
        msgpack::object const& operator()(
          msgpack::object const& o, ccf::BranchData& bd) const
        {
          bd = {o.via.array.ptr[0].as<decltype(ccf::BranchData::info)>(),
                o.via.array.ptr[1].as<decltype(ccf::BranchData::pubk)>(),
                o.via.array.ptr[2].as<decltype(ccf::BranchData::privk)>(),
                o.via.array.ptr[3].as<decltype(ccf::BranchData::policy)>()};

          return o;
        }
      };

      template <>
      struct pack<ccf::BranchData>
      {
        template <typename Stream>
        packer<Stream>& operator()(
          msgpack::packer<Stream>& o, ccf::BranchData const& bd) const
        {
          o.pack_array(4);

          o.pack(bd.info);
          o.pack(bd.pubk);
          o.pack(bd.privk);
          o.pack(bd.policy);

          return o;
        }
      };

      // ReleaseData
      template <>
      struct convert<ccf::ReleaseData>
      {
        msgpack::object const& operator()(
          msgpack::object const& o, ccf::ReleaseData& rd) const
        {
          rd = {
            o.via.array.ptr[0].as<decltype(ccf::ReleaseData::repository)>(),
            o.via.array.ptr[1].as<decltype(ccf::ReleaseData::branch)>(),
            o.via.array.ptr[2].as<decltype(ccf::ReleaseData::pr)>(),
            o.via.array.ptr[3].as<decltype(ccf::ReleaseData::binary)>(),
            o.via.array.ptr[4].as<decltype(ccf::ReleaseData::oe_sig_info)>(),
            o.via.array.ptr[5].as<decltype(ccf::ReleaseData::oe_sig_val)>()};

          return o;
        }
      };

      template <>
      struct pack<ccf::ReleaseData>
      {
        template <typename Stream>
        packer<Stream>& operator()(
          msgpack::packer<Stream>& o, ccf::ReleaseData const& rd) const
        {
          o.pack_array(6);

          o.pack(rd.repository);
          o.pack(rd.branch);
          o.pack(rd.pr);
          o.pack(rd.binary);
          o.pack(rd.oe_sig_info);
          o.pack(rd.oe_sig_val);

          return o;
        }
      };
    } // namespace adaptor
  }
} // namespace msgpack

MSGPACK_ADD_ENUM(ccf::TessApp::Role);

namespace ccfapp
{
  std::shared_ptr<enclave::RpcHandler> get_rpc_handler(
    ccf::NetworkTables& nwt, ccf::AbstractNotifier& notifier)
  {
    return std::make_shared<ccf::TessApp>(nwt, notifier);
  }
} // namespace ccfapp
