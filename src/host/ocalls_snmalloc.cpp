// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include <stddef.h>

extern "C" void* snmalloc_reserve_shared(size_t* size, size_t align);

extern "C" void* host_reserve(size_t size, size_t align)
{
#ifdef CCF_HOST_USE_SNMALLOC
  return snmalloc_reserve_shared(&size, align);
#else
  // host_reserve is an ocall that can only be made when using snmalloc
  return nullptr;
#endif
}
