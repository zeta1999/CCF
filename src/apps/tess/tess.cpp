#include <enclave/appinterface.h>
#include <node/rpc/userfrontend.h>

namespace tess
{
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

    static constexpr ccf::ValueId REPO_VAL_ID = ccf::ValueIds::END_ID + 1;
    using RepoID = ccf::Value;
    using ReposMap = ccfapp::Store::Map<std::string, RepoID>;
    ReposMap& repo_ids;

    // TODO: JSON is general for now,
    static constexpr ccf::ValueId BUILD_VAL_ID = REPO_VAL_ID + 1;
    using BuildID = ccf::Value;
    using Build = std::pair<RepoID, nlohmann::json>;
    using BuildsMap = ccfapp::Store::Map<BuildID, Build>;
    BuildsMap& builds;

    struct BranchData
    {};

    using BranchesMap = ccfapp::Store::Map<std::string, BranchData>;
    BranchesMap& branches;

    struct CreateReleaseBranch
    {
      static constexpr auto METHOD = "CREATE_RELEASE_BRANCH";

      struct In
      {
        std::string repository;
        std::string branch;
      };

      struct Out
      {};
    };

    inline void to_json(nlohmann::json& j, const CreateReleaseBranch::In& in) {}

    inline void from_json(const nlohmann::json& j, CreateReleaseBranch::In& in)
    {}

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

    RepoID get_repo(ccf::Store::Tx& tx, const std::string& name)
    {
      auto repos_view = tx.get_view(repo_ids);
      auto repo_it = repos_view->get(name);
      if (!repo_it.has_value())
      {
        throw std::runtime_error(fmt::format("No repo named {}", name));
      }

      return repo_it.value();
    }

    inline ccf::Value get_next_id(ccf::Store::Tx& tx, ccf::ValueId id)
    {
      auto values_view = tx.get_view(network.values);
      try
      {
        return ccf::get_next_id(values_view, id);
      }
      catch (const std::logic_error& e)
      {
        values_view->put(id, 1);
        return 0;
      }
    }

    TessApp(ccf::NetworkTables& nwt, ccf::AbstractNotifier& notifier) :
      UserRpcFrontend(*nwt.tables),
      network(nwt),
      user_roles(tables.create<RolesMap>("user-roles")),
      repo_ids(tables.create<ReposMap>("repo-ids")),
      builds(tables.create<BuildsMap>("builds")),
      branches(tables.create<BranchesMap>("branches"))
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

      auto repos_add = [this](RequestArgs& args) {
        auto repo_name_it = args.params.find("name");
        if (repo_name_it == args.params.end())
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS, "Missing param: name");

        RepoID next_repo_id = get_next_id(args.tx, REPO_VAL_ID);

        auto repos_view = args.tx.get_view(repo_ids);
        const auto name = repo_name_it->get<std::string>();
        const auto existing = repos_view->get(name);
        if (existing.has_value())
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            fmt::format("Repo with name {} already exists", name));

        repos_view->put(name, next_repo_id);

        auto j = nlohmann::json::object();
        j["name"] = name;
        j["internal_id"] = next_repo_id;

        return jsonrpc::success(j);
      };
      install("REPOS_ADD", repos_add, Write);

      auto repos_list = [this](RequestArgs& args) {
        auto names = nlohmann::json::array();
        auto repos_view = args.tx.get_view(repo_ids);
        repos_view->foreach([&names](const std::string& s, auto) {
          names.push_back(s);
          return true;
        });

        return jsonrpc::success(names);
      };
      install("REPOS_LIST", repos_list, Read);

      auto builds_add = [this](RequestArgs& args) {
        auto repo_name_it = args.params.find("repo");
        if (repo_name_it == args.params.end())
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS, "Missing param: repo");

        auto build_info_it = args.params.find("build_info");
        if (build_info_it == args.params.end())
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Missing param: build_info");

        const auto repo_name = repo_name_it->get<std::string>();
        const auto repo_id = get_repo(args.tx, repo_name);

        const auto build_info = *build_info_it;

        const auto build_id = get_next_id(args.tx, BUILD_VAL_ID);

        auto builds_view = args.tx.get_view(builds);
        if (builds_view->get(build_id).has_value())
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            fmt::format("Build ID {} is already in use", build_id));

        builds_view->put(build_id, std::make_pair(repo_id, build_info));

        return jsonrpc::success(fmt::format("Build #{} stored", build_id));
      };
      install("BUILDS_ADD", builds_add, Write);

      auto builds_get = [this](RequestArgs& args) {
        auto build_id_it = args.params.find("build_id");
        if (build_id_it == args.params.end())
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Missing param: build_index");

        const auto build_id = build_id_it->get<size_t>();

        auto builds_view = args.tx.get_view(builds);
        const auto build = builds_view->get(build_id);
        if (!build.has_value())
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            fmt::format("Build ID {} is not valid", build_id));

        auto j = nlohmann::json::object();
        j["repo"] = build->first;
        j["info"] = build->second;

        return jsonrpc::success(j);
      };
      install("BUILDS_GET", builds_get, Read);

      auto create_release_branch = [this](RequestArgs& args) {
        CreateReleaseBranch::In in =
          {}; // args.params.get<CreateReleaseBranch::In>();

        auto release_name = fmt::format("{}:{}", in.repository, in.branch);

        auto releases_view = args.tx.get_view(branches);
        if (releases_view->get(release_name).has_value())
        {
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            fmt::format(
              "Already have a release branch named {} in repository {}",
              in.branch,
              in.repository));
        }

        // GH.create_protected_branch(branch, commit);

        auto kp = tls::make_key_pair();
        const auto privk = kp->private_key();
        const auto pubk = kp->public_key();

        releases_view->put(release_name, {});

        return jsonrpc::success(pubk);
      };
      install(CreateReleaseBranch::METHOD, create_release_branch, Write);

      // auto builds_list = [this](RequestArgs& args) {};
      // install("BUILDS_LIST", builds_list, Read);
    }
  };

  NLOHMANN_JSON_SERIALIZE_ENUM(
    tess::TessApp::Role,
    {
      {tess::TessApp::Role::Contributor, "Contributor"},
      {tess::TessApp::Role::Reviewer, "Reviewer"},
      {tess::TessApp::Role::Builder, "Builder"},
      {tess::TessApp::Role::Publisher, "Publisher"},
      {tess::TessApp::Role::Admin, "Admin"},
    });
}

namespace fmt
{
  template <>
  struct formatter<tess::TessApp::Role>
  {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(tess::TessApp::Role r, FormatContext& ctx)
    {
      switch (r)
      {
        case (tess::TessApp::Role::Contributor):
          return format_to(ctx.out(), "Contributor");
        case (tess::TessApp::Role::Reviewer):
          return format_to(ctx.out(), "Reviewer");
        case (tess::TessApp::Role::Builder):
          return format_to(ctx.out(), "Builder");
        case (tess::TessApp::Role::Publisher):
          return format_to(ctx.out(), "Publisher");
        case (tess::TessApp::Role::Admin):
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
      template <>
      struct convert<tess::TessApp::BranchData>
      {
        msgpack::object const& operator()(
          msgpack::object const& o, tess::TessApp::BranchData& v) const
        {
          return o;
        }
      };

      template <>
      struct pack<tess::TessApp::BranchData>
      {
        template <typename Stream>
        packer<Stream>& operator()(
          msgpack::packer<Stream>& o, tess::TessApp::BranchData const& v) const
        {
          return o;
        }
      };
    } // namespace adaptor
  }
} // namespace msgpack

MSGPACK_ADD_ENUM(tess::TessApp::Role);

namespace ccfapp
{
  std::shared_ptr<enclave::RpcHandler> get_rpc_handler(
    ccf::NetworkTables& nwt, ccf::AbstractNotifier& notifier)
  {
    return std::make_shared<tess::TessApp>(nwt, notifier);
  }
} // namespace ccfapp
