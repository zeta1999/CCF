#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

./client userrpc --req '{"jsonrpc": "2.0", "id": 0, "method": "ROLES_GET"}'

# Create repos
./client userrpc --req '{"jsonrpc": "2.0", "id": 0, "method": "REPOS_ADD", "params": {"name": "ONNX"}}'
./client userrpc --req '{"jsonrpc": "2.0", "id": 0, "method": "REPOS_ADD", "params": {"name": "mbedtls"}}'
./client userrpc --req '{"jsonrpc": "2.0", "id": 0, "method": "REPOS_ADD", "params": {"name": "nlohmann::json"}}'

./client userrpc --req '{"jsonrpc": "2.0", "id": 0, "method": "REPOS_LIST", "params": {"name": "ONNX"}}'

# Add builds
./client userrpc --req '{"jsonrpc": "2.0", "id": 0, "method": "BUILDS_ADD", "params": {"repo": "ONNX", "build_info": {"date": "Today", "builder": "Bob"}}}'
./client userrpc --req '{"jsonrpc": "2.0", "id": 0, "method": "BUILDS_ADD", "params": {"repo": "ONNX", "build_info": {"date": "Today", "builder": "Alice"}}}'
./client userrpc --req '{"jsonrpc": "2.0", "id": 0, "method": "BUILDS_ADD", "params": {"repo": "mbedtls", "build_info": {"date": "Yesterday", "builder": "Alice"}}}'

# Retrieve builds
./client userrpc --req '{"jsonrpc": "2.0", "id": 0, "method": "BUILDS_GET", "params": {"build_id": 0}}'
./client userrpc --req '{"jsonrpc": "2.0", "id": 0, "method": "BUILDS_GET", "params": {"build_id": 1}}'
./client userrpc --req '{"jsonrpc": "2.0", "id": 0, "method": "BUILDS_GET", "params": {"build_id": 2}}'
