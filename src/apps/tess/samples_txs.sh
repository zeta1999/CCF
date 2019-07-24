#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

# Set github auth token to access tess-mockup repo
./client --pretty-print userrpc --req '{"jsonrpc": "2.0", "id": 0, "method": "SET_GITHUB_USER", "params": {"user_token": "'${GITHUB_AUTH_TOKEN}'"}}'

# Get roles of current user
./client --pretty-print userrpc --req '{ "jsonrpc": "2.0", "id": 0, "method": "ROLES_GET"}'

# Create branch
./client --pretty-print userrpc --req '{ "jsonrpc": "2.0", "id": 0, "method": "CREATE_RELEASE_BRANCH", "params": { "owner": "ad-l", "repository": "tess-mockup", "branch": "v0.42", "policy": { "min_builds": 2 }, "info": { "arbitrary": ["user", "data"], "goes": "here" } }}'

# Get branch
./client --pretty-print userrpc --req '{ "jsonrpc": "2.0", "id": 0, "method": "GET_BRANCH", "params": { "owner": "ad-l", "repository": "tess-mockup", "branch": "v0.42" }}'

# Sign release 
./client --pretty-print userrpc --req '{ "jsonrpc": "2.0", "id": 0, "method": "SIGN_RELEASE_BRANCH", "params": { "owner": "ad-l", "repository": "tess-mockup", "branch": "v0.42", "pr_number": 7, "binary": [0, 1, 2, 3, 4], "oe_sig_info": [] }}'

# Get release
./client --pretty-print userrpc --req '{ "jsonrpc": "2.0", "id": 0, "method": "GET_RELEASE", "params": { "release_id": 0 }}'

# Get details of PR
#./client --pretty-print userrpc --req '{"jsonrpc": "2.0", "id": 0, "method": "GITHUB_GET", "params": {"path": "repos/ad-l/tess-mockup/pulls/3"}}'

# Record new repository
./client --pretty-print userrpc --req '{"jsonrpc": "2.0", "id": 0, "method": "RECORD_NEW_REPOSITORY", "params": {"path": "repos/transparent-enclave/uiTest"}}'