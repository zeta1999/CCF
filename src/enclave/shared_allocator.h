// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifndef IS_ADDRESS_SPACE_CONSTRAINED
#  define IS_ADDRESS_SPACE_CONSTRAINED
#endif

#define snmalloc snmalloc_enclave
#define NO_BOOTSTRAP_ALLOCATOR
#define SNMALLOC_MEMORY_PROVIDER PALOpenEnclaveUntrusted

#ifndef OPEN_ENCLAVE
#  define OPEN_ENCLAVE
#endif
#include "pal_open_enclave_untrusted.h"

#include <snmalloc.h>

#ifdef __cplusplus
extern "C"
{
#endif

  void set_ccf_shared_pagemap(void* pm);

  void enclave_shared_free(void*);

  void* enclave_shared_malloc(size_t);

#ifdef __cplusplus
}
#endif
