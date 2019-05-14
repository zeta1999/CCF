#ifdef VIRTUAL_ENCLAVE

#include <dlfcn.h>
#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>

using snmalloc_reserve_shared_func_t = void* (*)(size_t*, size_t);

extern "C" oe_result_t host_reserve(void** _retval, size_t size, size_t align)
{
  static snmalloc_reserve_shared_func_t snmalloc_reserve_shared_func =
    (snmalloc_reserve_shared_func_t)dlsym(
      RTLD_DEFAULT, "snmalloc_reserve_shared");
  *_retval = snmalloc_reserve_shared_func(&size, align);

  return OE_OK;
}

#else
#  error Attempting to compile virtual ocall wrapper for non-virtual enclave
#endif
