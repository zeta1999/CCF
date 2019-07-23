#include <enclave/appinterface.h>
#include <node/rpc/userfrontend.h>

namespace tess
{
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

  void to_json(nlohmann::json& j, const CreateReleaseBranch::In& in)
  {
    j["repository"] = in.repository;
    j["branch"] = in.branch;
  }

  void from_json(const nlohmann::json& j, CreateReleaseBranch::In& in)
  {
    const auto repo_it = j.find("repository");
    if (repo_it == j.end())
    {
      throw std::logic_error(fmt::format("Missing param '{}'", "repository"));
    }
    in.repository = repo_it->get<std::string>();

    const auto branch_it = j.find("branch");
    if (branch_it == j.end())
    {
      throw std::logic_error(fmt::format("Missing param '{}'", "branch"));
    }
    in.branch = repo_it->get<std::string>();
  }

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

    struct BranchData
    {};

    using BranchesMap = ccfapp::Store::Map<std::string, BranchData>;
    BranchesMap& branches;

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

    TessApp(ccf::NetworkTables& nwt, ccf::AbstractNotifier& notifier) :
      UserRpcFrontend(*nwt.tables),
      network(nwt),
      user_roles(tables.create<RolesMap>("user-roles")),
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

      auto create_release_branch = [this](RequestArgs& args) {
        CreateReleaseBranch::In in = args.params.get<CreateReleaseBranch::In>();

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
