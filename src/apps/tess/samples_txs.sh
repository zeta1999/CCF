#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

./client --pretty-print userrpc --req '
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "ROLES_GET"
}'

# Create branch
./client --pretty-print userrpc --req '
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "CREATE_RELEASE_BRANCH",
  "params": {
    "repository": "ONNX",
    "branch": "v0.42",
    "policy": {
      "min_builds": 2
    },
    "info": {
      "arbitrary": ["user", "data"],
      "goes": "here"
    }
  }
}'

# Get branch
./client --pretty-print userrpc --req '
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "GET_BRANCH",
  "params": {
    "repository": "ONNX",
    "branch": "v0.42"
  }
}'

# Sign release 
./client --pretty-print userrpc --req '
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "SIGN_RELEASE_BRANCH",
  "params": {
    "repository": "ONNX",
    "branch": "v0.42",
    "pr": {},
    "binary": [],
    "oe_sig_info": []
  }
}'

# Get release
./client --pretty-print userrpc --req '
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "GET_RELEASE",
  "params": {
    "release_id": 0
  }
}'