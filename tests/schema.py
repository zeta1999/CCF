# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
import json
import http
import infra.ccf
import infra.proc
import infra.e2e_args

from loguru import logger as LOG


def run(args):
    hosts = ["localhost"] * (4 if args.consensus == "pbft" else 2)
    os.makedirs(args.schema_dir, exist_ok=True)

    changed_files = []
    methods_with_schema = set()
    methods_without_schema = set()

    def fetch_schema(client):
        list_response = client.get("listMethods")
        check(
            list_response, error=lambda status, msg: status == http.HTTPStatus.OK.value
        )
        methods = list_response.result["methods"]

        for method in methods:
            schema_found = False
            schema_response = client.get("getSchema", params={"method": method})
            check(
                schema_response,
                error=lambda status, msg: status == http.HTTPStatus.OK.value,
            )

            if schema_response.result is not None:
                for schema_type in ["params", "result"]:
                    element_name = "{}_schema".format(schema_type)
                    element = schema_response.result[element_name]
                    if element is not None and len(element) != 0:
                        schema_found = True
                        formatted_schema = json.dumps(element, indent=2)
                        target_file = os.path.join(
                            args.schema_dir, "{}_{}.json".format(method, schema_type)
                        )
                        with open(target_file, "a+") as f:
                            f.seek(0)
                            previous = f.read()
                            if previous != formatted_schema:
                                LOG.debug("Writing schema to {}".format(target_file))
                                f.truncate(0)
                                f.seek(0)
                                f.write(formatted_schema)
                                changed_files.append(target_file)
                            else:
                                LOG.debug("Schema matches in {}".format(target_file))

            if schema_found:
                methods_with_schema.add(method)
            else:
                methods_without_schema.add(method)

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes
    ) as network:
        network.start_and_join(args)
        primary, _ = network.find_primary()

        check = infra.checker.Checker()

        with primary.user_client() as user_client:
            LOG.info("user frontend")
            fetch_schema(user_client)

        with primary.node_client() as node_client:
            LOG.info("node frontend")
            fetch_schema(node_client)

        with primary.member_client() as member_client:
            LOG.info("member frontend")
            fetch_schema(member_client)

    if len(methods_without_schema) > 0:
        LOG.info("The following methods have no schema:")
        for m in methods_without_schema:
            LOG.info(" " + m)

    if len(changed_files) > 0:
        LOG.error("Made changes to the following schema files:")
        for f in changed_files:
            LOG.error(" " + f)
        sys.exit(1)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., liblogging)",
            required=True,
        )
        parser.add_argument(
            "--schema-dir",
            help="Path to directory where retrieved schema should be saved",
            required=True,
        )

    args = infra.e2e_args.cli_args(add=add)
    run(args)
