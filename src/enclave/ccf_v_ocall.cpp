#ifdef VIRTUAL_ENCLAVE

#  include "../ds/logger.h"

#  include <dlfcn.h>
#  include <openenclave/bits/report.h>
#  include <openenclave/bits/result.h>
#  include <stdlib.h>
#  include <string.h>
#  include <wchar.h>

extern "C" void* snmalloc_reserve_shared(size_t* size, size_t align)
  __attribute__((weak));

extern "C" oe_result_t host_reserve(void** _retval, size_t size, size_t align)
{
  *_retval = snmalloc_reserve_shared(&size, align);

  return OE_OK;
}

#else
#error Attempting to compile virtual ocall wrapper for non-virtual enclave
#endif
